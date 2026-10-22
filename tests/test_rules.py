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


def levels(findings):
    return max((f["level"] for f in findings), default=st.INFO)


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


class Category(unittest.TestCase):
    def test_detect(self):
        self.assertEqual(st.detect_category([("m.mkv", 900 * MB), ("setup.exe", MB)]), "media")
        self.assertEqual(st.detect_category([("game/data.bin", 10 * MB), ("game/setup.exe", 50 * MB)]), "software")
        self.assertEqual(st.detect_category([("b.pdf", 5 * MB), ("c.epub", MB)]), "docs")
        self.assertEqual(st.detect_category([("debian.iso", 600 * MB)]), "iso")


class NameRules(unittest.TestCase):
    def test_exe_in_movie_rejected(self):
        f = st.check_names([("Movie/movie.mkv", 2000 * MB), ("Movie/codec_install.exe", MB)], "media", "Movie 1080p")
        self.assertEqual(levels(f), st.DANGER)

    def test_double_extension(self):
        f = st.check_names([("Movie.2024.1080p.mp4.exe", 3 * MB)], "software")
        self.assertEqual(levels(f), st.DANGER)
        self.assertIn("double extension", f[0]["msg"])

    def test_version_numbers_are_not_double_extensions(self):
        f = st.check_names([("App/setup-2.1.4.exe", 80 * MB)], "software")
        self.assertEqual(levels(f), st.INFO)

    def test_rtl_override(self):
        f = st.check_names([("song‮gpj.exe", MB)], "software")
        self.assertEqual(levels(f), st.DANGER)

    def test_lnk_always_bad(self):
        self.assertEqual(levels(st.check_names([("Game/Play.lnk", 1000)], "software")), st.DANGER)

    def test_clean_movie(self):
        f = st.check_names([("M/m.mkv", 2000 * MB), ("M/m.srt", 90_000), ("M/Visit site.url", 100)], "media", "M 1080p")
        self.assertEqual(levels(f), st.INFO)

    def test_tiny_fake_video(self):
        f = st.check_names([("Big.Movie.2160p/movie.mp4", 2 * MB)], "media", "Big.Movie.2160p")
        self.assertEqual(levels(f), st.WARN)

    def test_archive_in_media_and_password(self):
        f = st.check_names([("M/m.rar", 900 * MB), ("M/password.txt", 50)], "media", "M")
        self.assertEqual(levels(f), st.WARN)

    def test_macro_doc(self):
        self.assertEqual(levels(st.check_names([("b/report.docm", MB)], "docs")), st.WARN)

    def test_empty_torrent(self):
        self.assertEqual(levels(st.check_names([("a.txt", 0)], "docs")), st.DANGER)
        self.assertEqual(levels(st.check_names([], "docs", inner=True)), st.INFO)

    def test_app_bundle_contents_are_programs(self):
        self.assertEqual(st.kind_of(st.ext_of("X.app/Contents/Info.plist")), "exec")


class Sniff(unittest.TestCase):
    def test_disguised_pe(self):
        self.assertEqual(levels(st.sniff("m.mkv", b"MZ\x90\x00" + b"\0" * 60)), st.DANGER)

    def test_real_mkv(self):
        self.assertEqual(st.sniff("m.mkv", b"\x1a\x45\xdf\xa3" + b"\0" * 60), [])

    def test_fake_mp4(self):
        self.assertEqual(levels(st.sniff("m.mp4", b"this is not a video at all")), st.WARN)

    def test_exe_is_not_flagged_as_disguised(self):
        self.assertEqual(st.sniff("setup.exe", b"MZ\x90\x00"), [])

    def test_script_as_image(self):
        self.assertEqual(levels(st.sniff("cover.jpg", b"#!/bin/sh\ncurl evil")), st.DANGER)


if __name__ == "__main__":
    unittest.main()
