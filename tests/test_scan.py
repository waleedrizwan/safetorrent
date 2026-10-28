"""Scan tests for the VM agent: archive extraction and ClamAV. 7z is replaced by
a fake that "unpacks" archives from a table and clamscan by canned results, so
these run anywhere."""
import fcntl
import shutil
import subprocess
import tempfile
import threading
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

    def test_disk_images_are_unpacked(self):
        # ClamAV skips anything over 500 MB, so an ISO's contents are only scanned if unpacked.
        archives = {n: {"files": {"ok.txt": b"hi"}} for n in ("os.iso", "disk.img", "App.dmg", "game.bin")}
        _out, fake = self.extract(archives, [(n, GB) for n in archives], category="software")
        self.assertEqual(sorted(fake.extracted), ["App.dmg", "disk.img", "os.iso"])

    def test_programs_inside_an_os_image_are_expected(self):
        archives = {"os.iso": {"files": {"setup.exe": PE, "install.sh": b"#!/bin/sh\n", "boot/grub.cfg": b""}}}
        out, _ = self.extract(archives, [("os.iso", GB)], category="iso")
        self.assertEqual(max(f["level"] for f in out), st.INFO, out)

    def test_os_image_still_gets_the_always_danger_rules(self):
        out, _ = self.extract({"os.iso": {"files": {"photo.jpg.exe": PE}}}, [("os.iso", GB)], category="iso")
        self.assertEqual(self.at(out, "os.iso.d/photo.jpg.exe")[0]["level"], st.DANGER)


def clam(rc, stdout="", stderr=""):
    return subprocess.CompletedProcess([], rc, stdout, stderr)


class ClamAV(unittest.TestCase):
    """clamscan's exit code and output, mapped to findings. A scan that didn't run must never be CLEAN."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.d = self.tmp / "abcdef0123"
        (self.d / "files").mkdir(parents=True)
        db = self.tmp / "clamav"
        db.mkdir()
        (db / "daily.cld").write_text("x")
        mock.patch.object(st, "CLAMAV_DB", db).start()
        mock.patch.object(st, "SCAN_LOCK", self.tmp / "scan.lock").start()
        self.addCleanup(mock.patch.stopall)

    def scan(self, res, on_wait=None):
        with mock.patch.object(st, "run", return_value=res) as run:
            out = st.clamav_scan(self.d, on_wait)
        self.cmd = run.call_args.args[0]
        return out

    def line(self, rel, sig):
        return f"{self.d}/{rel}: {sig} FOUND\n"

    def verdict(self, findings):
        return st.SCAN_VERDICT[st.max_level(findings)]

    def test_clean(self):
        self.assertEqual(self.scan(clam(0)), [])
        self.assertIn("--alert-exceeds-max=yes", self.cmd)

    def test_detection(self):
        out = self.scan(clam(1, self.line("files/Show/a.exe", "Win.Trojan.Agent")))
        self.assertEqual(out, [st.finding(st.INFECTED, "Show/a.exe", "ClamAV detected Win.Trojan.Agent")])

    def test_crash_kill_or_missing_binary_is_never_clean(self):
        for rc, err in ((137, ""), (-9, ""), (127, "runuser: failed to execute clamscan"), (2, "ERROR: Can't open file")):
            with self.subTest(rc=rc):
                out = self.scan(clam(rc, "", err))
                self.assertEqual(self.verdict(out), "SUSPICIOUS", out)
                self.assertIn("didn't finish", out[-1]["msg"])

    def test_detection_count_with_no_readable_line_is_not_clean(self):
        self.assertEqual(self.verdict(self.scan(clam(1, "garbled\n"))), "SUSPICIOUS")

    def test_oversized_program_is_a_warning(self):
        out = self.scan(clam(2, self.line("files/Tool/setup.exe", "Heuristics.Limits.Exceeded.MaxFileSize")))
        self.assertEqual(self.verdict(out), "WARNING", out)
        self.assertEqual(out[0]["path"], "Tool/setup.exe")
        self.assertTrue(out[0]["unscanned"])

    def test_oversized_videos_dont_hold_a_movie_back(self):
        out = self.scan(clam(2, self.line("files/Film/film.mkv", "Heuristics.Limits.Exceeded.MaxFileSize")
                             + self.line("files/Film/extras.mp4", "Heuristics.Limits.Exceeded.MaxScanSize")))
        self.assertEqual(self.verdict(out), "CLEAN", out)
        self.assertIn("2 media file(s)", out[0]["msg"])

    def test_oversized_image_that_was_unpacked_is_fine(self):
        (self.d / "extracted" / "os.iso.d").mkdir(parents=True)
        out = self.scan(clam(2, self.line("files/os.iso", "Heuristics.Limits.Exceeded.MaxFileSize")))
        self.assertEqual(out, [])

    def test_size_limit_plus_a_real_error_is_incomplete(self):
        out = self.scan(clam(2, self.line("files/film.mkv", "Heuristics.Limits.Exceeded.MaxFileSize"),
                             "LibClamAV Warning: old database\nLibClamAV Error: cli_scanfile: out of memory"))
        self.assertEqual(self.verdict(out), "SUSPICIOUS", out)
        self.assertIn("out of memory", out[-1]["msg"])

    def test_detection_alongside_size_limit(self):
        out = self.scan(clam(2, self.line("files/a.exe", "Win.Trojan.X")
                             + self.line("files/film.mkv", "Heuristics.Limits.Exceeded.MaxFileSize")))
        self.assertEqual(self.verdict(out), "INFECTED")
        self.assertFalse(any("didn't finish" in f["msg"] for f in out))

    def test_scans_take_turns(self):
        waited = threading.Event()
        with open(st.SCAN_LOCK, "w") as held:
            fcntl.flock(held, fcntl.LOCK_EX)  # another download is being scanned
            t = threading.Thread(target=self.scan, args=(clam(0), waited.set))
            t.start()
            self.assertTrue(waited.wait(5))
            self.assertTrue(t.is_alive())
        t.join(5)
        self.assertFalse(t.is_alive())


class TrustChecksum(unittest.TestCase):
    def test_only_the_verified_file_and_its_contents(self):
        def unscanned(p):
            return st.finding(st.WARN, p, "too large", unscanned=True)
        findings = [st.finding(st.INFO, "os.iso", "matches ✓", verified=True),
                    unscanned("os.iso"), unscanned("os.iso.d/casper/filesystem.squashfs"),
                    unscanned("os.iso.dx/other.bin"), unscanned("extra.exe"),
                    st.finding(st.WARN, "os.iso.d/x.lnk", "not a size problem")]
        st.trust_checksum(findings)
        self.assertEqual([f["level"] for f in findings], [st.INFO, st.INFO, st.INFO, st.WARN, st.WARN, st.WARN])

    def test_no_match_trusts_nothing(self):
        findings = [st.finding(st.WARN, "os.iso", "too large", unscanned=True)]
        st.trust_checksum(findings)
        self.assertEqual(findings[0]["level"], st.WARN)


if __name__ == "__main__":
    unittest.main()
