"""Unit tests for the guest agent's parsing and rules (run on any machine)."""
import hashlib
import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("st", Path(__file__).parent.parent / "vm" / "st-guest.py")
st = importlib.util.module_from_spec(spec)
spec.loader.exec_module(st)

MB = 1024**2


def bencode(v) -> bytes:
    if isinstance(v, int):
        return b"i%de" % v
    if isinstance(v, str):
        v = v.encode()
    if isinstance(v, bytes):
        return b"%d:%s" % (len(v), v)
    if isinstance(v, list):
        return b"l" + b"".join(map(bencode, v)) + b"e"
    return b"d" + b"".join(bencode(k) + bencode(v[k]) for k in sorted(v)) + b"e"


class ParseTorrent(unittest.TestCase):
    def test_multi_file_and_infohash(self):
        info = {"name": "Show", "piece length": 16384, "pieces": b"x" * 20,
                "files": [{"length": 5, "path": ["a.mkv"]}, {"length": 3, "path": ["sub", "b.srt"]},
                          {"length": 9, "path": [".pad", "9"], "attr": "p"}]}
        t = st.parse_torrent(bencode({"announce": "http://t", "info": info}))
        self.assertEqual(t["files"], [("Show/a.mkv", 5), ("Show/sub/b.srt", 3)])
        self.assertEqual(t["infohash"], hashlib.sha1(bencode(info)).hexdigest())

    def test_single_file(self):
        t = st.parse_torrent(bencode({"info": {"name": "x.iso", "length": 42, "pieces": b"", "piece length": 1}}))
        self.assertEqual(t["files"], [("x.iso", 42)])

    def test_garbage_rejected(self):
        for bad in (b"", b"hello", b"d4:infoi1e", b"d4:info"):
            with self.assertRaises(ValueError):
                st.parse_torrent(bad)

    def test_malformed_values_rejected(self):
        for bad in (b"d4:infoie" b"e", b"d4:infoi-e" b"e", b"d4:info99:short" b"e", b"d4:infox" b"e"):
            with self.assertRaises(ValueError, msg=bad):
                st.parse_torrent(bad)

    def test_deep_nesting_rejected_not_crash(self):
        bomb = b"d4:info" + b"l" * 5000 + b"e" * 5000 + b"e"
        with self.assertRaises(ValueError):
            st.parse_torrent(bomb)

    def test_symlink_entries_skipped(self):
        info = {"name": "Show", "piece length": 1, "pieces": b"x" * 20,
                "files": [{"length": 5, "path": ["a.mkv"]},
                          {"length": 0, "path": ["evil"], "attr": "l", "symlink path": ["..", "..", "etc"]}]}
        self.assertEqual(st.parse_torrent(bencode({"info": info}))["files"], [("Show/a.mkv", 5)])

    def test_dot_dot_path_is_kept_visible(self):
        # aria2 sanitises paths itself; the pre-check must still see the raw name to judge it.
        info = {"name": "Show", "piece length": 1, "pieces": b"x" * 20,
                "files": [{"length": 5, "path": ["..", "x.mkv"]}]}
        self.assertEqual(st.parse_torrent(bencode({"info": info}))["files"], [("Show/../x.mkv", 5)])


class Category(unittest.TestCase):
    def test_detect(self):
        self.assertEqual(st.detect_category([("m.mkv", 900 * MB), ("setup.exe", MB)]), "media")
        self.assertEqual(st.detect_category([("game/data.bin", 10 * MB), ("game/setup.exe", 50 * MB)]), "software")
        self.assertEqual(st.detect_category([("b.pdf", 5 * MB), ("c.epub", MB)]), "docs")
        self.assertEqual(st.detect_category([("debian.iso", 600 * MB)]), "iso")


class NameRules(unittest.TestCase):
    def test_exe_in_movie_rejected(self):
        f = st.check_names([("Movie/movie.mkv", 2000 * MB), ("Movie/codec_install.exe", MB)], "media", "Movie 1080p")
        self.assertEqual(st.max_level(f), st.DANGER)

    def test_double_extension(self):
        f = st.check_names([("Movie.2024.1080p.mp4.exe", 3 * MB)], "software")
        self.assertEqual(st.max_level(f), st.DANGER)
        self.assertIn("double extension", f[0]["msg"])

    def test_version_numbers_are_not_double_extensions(self):
        f = st.check_names([("App/setup-2.1.4.exe", 80 * MB)], "software")
        self.assertEqual(st.max_level(f), st.INFO)

    def test_rtl_override(self):
        f = st.check_names([("song‮gpj.exe", MB)], "software")
        self.assertEqual(st.max_level(f), st.DANGER)

    def test_lnk_always_bad(self):
        self.assertEqual(st.max_level(st.check_names([("Game/Play.lnk", 1000)], "software")), st.DANGER)

    def test_clean_movie(self):
        f = st.check_names([("M/m.mkv", 2000 * MB), ("M/m.srt", 90_000), ("M/Visit site.url", 100)], "media", "M 1080p")
        self.assertEqual(st.max_level(f), st.INFO)

    def test_tiny_fake_video(self):
        f = st.check_names([("Big.Movie.2160p/movie.mp4", 2 * MB)], "media", "Big.Movie.2160p")
        self.assertEqual(st.max_level(f), st.WARN)

    def test_archive_in_media_and_password(self):
        f = st.check_names([("M/m.rar", 900 * MB), ("M/password.txt", 50)], "media", "M")
        self.assertEqual(st.max_level(f), st.WARN)

    def test_macro_doc(self):
        self.assertEqual(st.max_level(st.check_names([("b/report.docm", MB)], "docs")), st.WARN)

    def test_empty_torrent(self):
        self.assertEqual(st.max_level(st.check_names([("a.txt", 0)], "docs")), st.DANGER)
        self.assertEqual(st.max_level(st.check_names([], "docs", inner=True)), st.INFO)

    def test_app_bundle_contents_are_programs(self):
        self.assertEqual(st.kind_of(st.ext_of("X.app/Contents/Info.plist")), "exec")


class Sniff(unittest.TestCase):
    def test_disguised_pe(self):
        self.assertEqual(st.max_level(st.sniff("m.mkv", b"MZ\x90\x00" + b"\0" * 60)), st.DANGER)

    def test_real_mkv(self):
        self.assertEqual(st.sniff("m.mkv", b"\x1a\x45\xdf\xa3" + b"\0" * 60), [])

    def test_fake_mp4(self):
        self.assertEqual(st.max_level(st.sniff("m.mp4", b"this is not a video at all")), st.WARN)

    def test_exe_is_not_flagged_as_disguised(self):
        self.assertEqual(st.sniff("setup.exe", b"MZ\x90\x00"), [])

    def test_script_as_image(self):
        self.assertEqual(st.max_level(st.sniff("cover.jpg", b"#!/bin/sh\ncurl evil")), st.DANGER)

    def test_program_without_a_known_extension(self):
        pe = b"MZ\x90\x00" + b"\0" * 60
        for path in ("Movie/extras/data.bin2", "Movie/README", "Movie/x.terminal2"):
            with self.subTest(path):
                self.assertEqual(st.max_level(st.sniff(path, pe, "media")), st.DANGER)
                self.assertEqual(st.max_level(st.sniff(path, pe, "docs")), st.DANGER)
                # Extensionless programs are normal in software (e.g. Linux binaries).
                self.assertEqual(st.sniff(path, pe, "software"), [])

    def test_program_disguised_as_a_web_page_or_macro_doc(self):
        for path in ("index.html", "report.docm"):
            self.assertEqual(st.max_level(st.sniff(path, b"\x7fELF\x02\x01")), st.DANGER, path)


class MacAndWindowsTricks(unittest.TestCase):
    """File types that run code when opened on a Mac (or Windows) but weren't on the lists."""

    def level(self, path, category="media"):
        return st.max_level(st.check_names([("Movie.2160p.mkv", 4 * 1024**3), (path, 2000)], category, "Movie 2160p"))

    def test_mac_executables_in_a_movie(self):
        for ext in ("terminal", "dylib", "applescript", "prefPane", "scptd", "saver", "osax", "xpc", "bundle",
                    "plugin", "fileloc", "action"):
            with self.subTest(ext):
                self.assertEqual(self.level(f"Movie/extra.{ext}"), st.DANGER)

    def test_windows_extras(self):
        for ext in ("msc", "chm", "application", "settingcontent-ms", "appref-ms"):
            with self.subTest(ext):
                self.assertEqual(self.level(f"Movie/extra.{ext}"), st.DANGER)

    def test_terminal_files_are_dangerous_even_in_software(self):
        self.assertEqual(self.level("Tool/run.terminal", "software"), st.DANGER)

    def test_trailing_dots_and_spaces_dont_hide_the_extension(self):
        for name in ("Movie/codec.exe.", "Movie/codec.exe ", "Movie/codec.exe. ."):
            with self.subTest(repr(name)):
                self.assertEqual(st.ext_of(name), "exe")
                self.assertEqual(self.level(name), st.DANGER)
        self.assertEqual(self.level("Movie/clip.mp4.exe."), st.DANGER)

    def test_web_pages_in_a_movie_get_a_warning(self):
        for ext in ("html", "htm", "svg", "mht"):
            self.assertEqual(self.level(f"Movie/info.{ext}"), st.WARN, ext)
        self.assertEqual(self.level("Docs/manual.html", "docs"), st.INFO)

    def test_inetloc_is_junk(self):
        self.assertEqual(self.level("Movie/site.inetloc"), st.INFO)


class MalformedTorrents(unittest.TestCase):
    """Odd structures get a clean "not a valid .torrent" error, never a traceback."""

    def test_rejected_cleanly(self):
        cases = {
            "list as dict key": b"dli1ee1:xe",
            "info is a number": b"d4:infoi1ee",
            "file entry is a number": b"d4:infod5:filesli1ee6:pieces1:xee",
            "length is text": bencode({"info": {"name": "a", "pieces": b"x" * 20, "length": "big"}}),
            "files is a dict": bencode({"info": {"name": "a", "pieces": b"x" * 20, "files": {"a": 1}}}),
            "path is a number": bencode({"info": {"name": "a", "pieces": b"x" * 20,
                                                  "files": [{"length": 1, "path": 5}]}}),
            "negative size": bencode({"info": {"name": "a", "pieces": b"x" * 20, "length": -5}}),
        }
        for label, blob in cases.items():
            with self.subTest(label), self.assertRaisesRegex(ValueError, "not a valid .torrent"):
                st.parse_torrent(blob)


class ConfigValues(unittest.TestCase):
    """The rule the CLI (bash), the app and the VM all follow."""

    def test_rule(self):
        for raw, want in [("~/Downloads/SafeTorrents", "~/Downloads/SafeTorrents"),
                          ("  yes   # turn it on", "yes"),
                          ('"~/My #1 Shows"  # quoted', "~/My #1 Shows"),
                          ("'single quoted' # note", "single quoted"),
                          ("a#b", "a#b"),
                          ("", "")]:
            self.assertEqual(st.config_value(raw), want, raw)


if __name__ == "__main__":
    unittest.main()
