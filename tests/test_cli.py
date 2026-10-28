"""Tests for `safetorrent release`, the step that copies files onto the Mac.
Runs the real bash script against a fake `limactl` that plays the VM."""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RID = "abcdef0123"

# Answers `vm_status`, the guest's release-info / mark-released, and the rsync copy out of the VM.
FAKE_LIMACTL = r"""#!/bin/bash
echo "$*" >> "$FAKE_LOG"
case "$1" in
  list) echo Running ;;
  copy)
    src=${@: -2:1}; dst=${@: -1}
    cp -R "$FAKE_VM_FILES/." "$dst" ;;
  shell)
    while [[ "$1" != st-guest ]]; do shift; done; shift
    case "$1" in
      release-info) printf '%s\n' "$FAKE_RELEASE_INFO" ;;
      mark-released) ;;
      *) echo "unexpected guest call: $*" >&2; exit 9 ;;
    esac ;;
  *) echo "unexpected limactl call: $*" >&2; exit 9 ;;
esac
"""


class Release(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        bin_dir = self.tmp / "bin"
        bin_dir.mkdir()
        (bin_dir / "limactl").write_text(FAKE_LIMACTL)
        (bin_dir / "limactl").chmod(0o755)
        self.home = self.tmp / "home"
        self.home.mkdir()
        self.vm_files = self.tmp / "vm-files"
        (self.vm_files / "Show").mkdir(parents=True)
        (self.vm_files / "Show" / "ep1.mkv").write_bytes(b"\x1a\x45\xdf\xa3video")
        self.log = self.tmp / "limactl.log"
        self.downloads = self.home / "Downloads" / "SafeTorrents"
        self.env = {**os.environ, "HOME": str(self.home), "PATH": f"{bin_dir}:{os.environ['PATH']}",
                    "FAKE_LOG": str(self.log), "FAKE_VM_FILES": str(self.vm_files),
                    # Terminal's default. macOS's bash 3.2 reads "$var…" as one long name under UTF-8.
                    "LC_ALL": "en_US.UTF-8"}

    def release(self, status, verdict, name="Show", *args):
        self.env["FAKE_RELEASE_INFO"] = "\t".join([RID, status, verdict, name])
        return subprocess.run([str(ROOT / "safetorrent"), "release", RID, *args], env=self.env,
                              capture_output=True, text=True, timeout=30)

    def calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def assert_nothing_copied(self, res):
        self.assertNotEqual(res.returncode, 0)
        self.assertFalse(any(c.startswith("copy") for c in self.calls()))
        self.assertFalse(any("mark-released" in c for c in self.calls()))
        self.assertEqual(list(self.downloads.iterdir()) if self.downloads.exists() else [], [])

    def test_clean_is_copied_and_marked(self):
        res = self.release("scanned", "CLEAN")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual((self.downloads / "Show" / "Show" / "ep1.mkv").read_bytes()[:4], b"\x1a\x45\xdf\xa3")
        self.assertTrue(any(f"mark-released {RID} {self.downloads / 'Show'}" in c for c in self.calls()))
        self.assertFalse(any(p.name.startswith(".incoming") for p in self.downloads.iterdir()))

    def test_warning_is_allowed_when_asked(self):
        self.assertEqual(self.release("scanned", "WARNING").returncode, 0)

    def test_bad_verdicts_need_force(self):
        for verdict in ("SUSPICIOUS", "INFECTED", "-"):
            with self.subTest(verdict):
                self.log.unlink(missing_ok=True)
                res = self.release("scanned", verdict)
                self.assertIn("stays in quarantine", res.stderr)
                self.assert_nothing_copied(res)

    def test_force_overrides_verdict(self):
        self.assertEqual(self.release("scanned", "INFECTED", "Show", "--force").returncode, 0)
        self.assertTrue((self.downloads / "Show").is_dir())

    def test_unfinished_downloads_refused_even_with_force(self):
        for status in ("downloading", "scanning", "incomplete", "queued", "blocked"):
            with self.subTest(status):
                self.log.unlink(missing_ok=True)
                res = self.release(status, "CLEAN", "Show", "--force")
                self.assertIn("hasn't finished", res.stderr)
                self.assert_nothing_copied(res)

    def test_name_clash_gets_id_suffix(self):
        (self.downloads / "Show").mkdir(parents=True)
        (self.downloads / "Show" / "mine.txt").write_text("keep me")
        self.assertEqual(self.release("scanned", "CLEAN").returncode, 0)
        self.assertEqual((self.downloads / "Show" / "mine.txt").read_text(), "keep me")
        self.assertTrue((self.downloads / f"Show [{RID}]" / "Show" / "ep1.mkv").exists())

    def test_download_dir_from_config(self):
        conf = self.home / ".config" / "safetorrent"
        conf.mkdir(parents=True)
        (conf / "config").write_text('DOWNLOAD_DIR="~/Elsewhere"  # comment\n')
        self.assertEqual(self.release("scanned", "CLEAN").returncode, 0)
        self.assertTrue((self.home / "Elsewhere" / "Show" / "Show" / "ep1.mkv").exists())

    @unittest.skipUnless(sys.platform == "darwin", "Gatekeeper's quarantine flag is macOS-only")
    def test_every_file_gets_gatekeeper_quarantine_flag(self):
        (self.vm_files / "Show" / "App.app" / "Contents").mkdir(parents=True)
        (self.vm_files / "Show" / "App.app" / "Contents" / "run").write_bytes(b"#!/bin/sh\n")
        self.assertEqual(self.release("scanned", "CLEAN").returncode, 0)
        dest = self.downloads / "Show"
        paths = [dest, *dest.rglob("*")]
        self.assertGreater(len(paths), 4)
        for p in paths:
            flag = subprocess.run(["xattr", "-p", "com.apple.quarantine", str(p)], capture_output=True, text=True)
            self.assertEqual(flag.returncode, 0, f"no quarantine flag on {p}")
            self.assertIn(";safetorrent;", flag.stdout)


if __name__ == "__main__":
    unittest.main()
