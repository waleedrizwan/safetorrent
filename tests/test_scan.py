"""Archive extraction tests for the VM agent. 7z is replaced by a fake that
"unpacks" archives from a table, so these run anywhere."""
import shutil
import subprocess
import tempfile
import unittest
from collections import namedtuple
from pathlib import Path
from unittest import mock

from test_rules import st

GB = 1024**3
Usage = namedtuple("Usage", "total used free")
PE = b"MZ\x90\x00" + b"\x00" * 60


class Fake7z:
    """Each archive (by file name) maps to its contents, or to a canned listing/exit code."""

    def __init__(self, archives: dict):
        self.archives = archives
        self.extracted: list[str] = []

    def __call__(self, cmd, **kw):
        if cmd[0] == "install":
            Path(cmd[-1]).mkdir(parents=True, exist_ok=True)
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if cmd[:4] == ["runuser", "-u", "torrent", "--"]:
            cmd = cmd[4:]
        if cmd[0] == "timeout":
            cmd = cmd[2:]
        src = Path(cmd[-1])
        spec = self.archives[src.name]
        files = spec.get("files", {})
        if cmd[1] == "l":
            listing = spec.get("listing") or "".join(f"Path = {p}\nSize = {len(b)}\n\n" for p, b in files.items())
            return subprocess.CompletedProcess(cmd, 0, listing, "")
        self.extracted.append(src.name)
        dest = Path(next(a for a in cmd if a.startswith("-o"))[2:])
        for rel, data in files.items():
            (dest / rel).parent.mkdir(parents=True, exist_ok=True)
            (dest / rel).write_bytes(data)
        return subprocess.CompletedProcess(cmd, spec.get("rc", 0), spec.get("out", ""), "")


class ExtractArchives(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.root = self.tmp / "files"
        self.root.mkdir()
        mock.patch.object(st.shutil, "which", return_value="/usr/bin/7z").start()
        mock.patch.object(st.shutil, "disk_usage", return_value=Usage(0, 0, 500 * GB)).start()
        self.addCleanup(mock.patch.stopall)

    def extract(self, archives, files, category="media", max_gb=20):
        fake = Fake7z(archives)
        for rel, _ in files:
            (self.root / rel).parent.mkdir(parents=True, exist_ok=True)
            (self.root / rel).write_bytes(b"archive")
        with mock.patch.object(st, "run", side_effect=fake):
            out = st.extract_archives(self.tmp, files, self.root, {"MAX_EXTRACT_GB": max_gb}, category)
        return out, fake

    def at(self, findings, path):
        return [f for f in findings if f["path"] == path]

    def test_password_protected_is_danger_and_not_extracted(self):
        out, fake = self.extract({"a.zip": {"listing": "Path = x.exe\nEncrypted = +\n"}}, [("a.zip", 100)])
        self.assertEqual(self.at(out, "a.zip")[0]["level"], st.DANGER)
        self.assertIn("password", out[0]["msg"])
        self.assertEqual(fake.extracted, [])

    def test_zip_bomb_ratio(self):
        out, fake = self.extract({"a.zip": {"listing": f"Size = {2 * GB}\n"}}, [("a.zip", 1024)])
        self.assertEqual(self.at(out, "a.zip")[0]["level"], st.DANGER)
        self.assertIn("zip bomb", out[0]["msg"])
        self.assertEqual(fake.extracted, [])

    def test_over_extract_limit(self):
        out, fake = self.extract({"a.7z": {"listing": f"Size = {3 * GB}\n"}}, [("a.7z", 2 * GB)], max_gb=2)
        self.assertEqual(self.at(out, "a.7z")[0]["level"], st.DANGER)
        self.assertEqual(fake.extracted, [])

    def test_over_free_disk(self):
        st.shutil.disk_usage.return_value = Usage(0, 0, 1 * GB)
        out, fake = self.extract({"a.7z": {"listing": f"Size = {1 * GB}\n"}}, [("a.7z", GB)])
        self.assertEqual(self.at(out, "a.7z")[0]["level"], st.DANGER)
        self.assertEqual(fake.extracted, [])

    def test_only_first_volume_of_multipart(self):
        names = ["m.part1.rar", "m.part2.rar", "m.part10.rar", "old.rar", "old.r00", "old.r01",
                 "s.7z.001", "s.7z.002", "z.zip", "z.z01"]
        archives = {n: {"files": {"ok.txt": b"hi"}} for n in names}
        _out, fake = self.extract(archives, [(n, 10) for n in names])
        self.assertEqual(sorted(fake.extracted), ["m.part1.rar", "old.rar", "s.7z.001", "z.zip"])

    def test_inner_files_get_name_and_content_checks(self):
        archives = {"a.zip": {"files": {"setup.exe": PE, "film.mp4": PE, "notes.txt": b"hello"}}}
        out, _ = self.extract(archives, [("Movie/a.zip", 100)])
        self.assertGreaterEqual(max(f["level"] for f in self.at(out, "Movie/a.zip.d/setup.exe")), st.DANGER)
        disguised = self.at(out, "Movie/a.zip.d/film.mp4")
        self.assertTrue(any("disguised" in f["msg"] and f["level"] == st.DANGER for f in disguised), disguised)
        self.assertEqual(self.at(out, "Movie/a.zip.d/notes.txt"), [])
        self.assertTrue((self.tmp / "extracted" / "Movie" / "a.zip.d" / "setup.exe").exists())

    def test_nested_findings_carry_full_path(self):
        archives = {"outer.zip": {"files": {"inner.zip": b"z"}}, "inner.zip": {"files": {"evil.lnk": b"x"}}}
        out, fake = self.extract(archives, [("outer.zip", 100)])
        self.assertEqual(fake.extracted, ["outer.zip", "inner.zip"])
        self.assertEqual(self.at(out, "outer.zip.d/inner.zip.d/evil.lnk")[0]["level"], st.DANGER)

    def test_stops_after_three_levels(self):
        archives = {"a.zip": {"files": {"b.zip": b"z"}}, "b.zip": {"files": {"c.zip": b"z"}},
                    "c.zip": {"files": {"d.zip": b"z"}}, "d.zip": {"files": {"x.lnk": b"x"}}}
        _out, fake = self.extract(archives, [("a.zip", 100)])
        self.assertEqual(fake.extracted, ["a.zip", "b.zip", "c.zip"])

    def test_failed_extraction(self):
        out, _ = self.extract({"a.rar": {"files": {"part.mkv": b"x"}, "rc": 2, "out": "Data error"}},
                              [("a.rar", 100)])
        self.assertEqual(self.at(out, "a.rar")[0]["level"], st.WARN)
        out, _ = self.extract({"b.rar": {"rc": 2, "out": "ERROR: Wrong password : x.exe"}}, [("b.rar", 100)])
        self.assertEqual(self.at(out, "b.rar")[0]["level"], st.DANGER)

    def test_non_archives_ignored(self):
        out, fake = self.extract({}, [("movie.mkv", 100), ("readme.txt", 1)])
        self.assertEqual((out, fake.extracted), ([], []))


if __name__ == "__main__":
    unittest.main()
