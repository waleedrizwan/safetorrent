"""Tests for `safetorrent release`, the step that copies files onto the Mac.
Runs the real bash script against a fake `limactl` that plays the VM."""
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RID = "abcdef0123"

# Answers `vm_status` and the guest's release-info / manifest / send / mark-released.
FAKE_LIMACTL = r"""#!/bin/bash
echo "$*" >> "$FAKE_LOG"
case "$1" in
  list) echo Running ;;
  shell)
    while [[ "$1" != st-guest ]]; do shift; done; shift
    case "$1" in
      send)
        # The download as a tar stream. bsdtar keeps symlinks, FIFOs and modes as they are,
        # like a compromised VM could send them.
        [[ -t 0 ]] && { echo "send got a terminal on stdin: binary output would be mangled" >&2; exit 9; }
        sleep "${FAKE_SLEEP:-0}"
        if [[ -n "${FAKE_TAR:-}" ]]; then cat "$FAKE_TAR"; else COPYFILE_DISABLE=1 tar -C "$FAKE_VM_FILES" -cf - .; fi ;;
      release-info)
        # A second answer, if set, plays a rescan that finished while copying.
        if [[ -n "${FAKE_RELEASE_INFO2:-}" && -e "$FAKE_LOG.asked" ]]; then printf '%s\n' "$FAKE_RELEASE_INFO2"
        else printf '%s\n' "$FAKE_RELEASE_INFO"; fi
        touch "$FAKE_LOG.asked" ;;
      manifest)
        # What the scan saw: FAKE_MANIFEST if given, otherwise the VM's files as they are.
        if [[ -n "${FAKE_MANIFEST:-}" ]]; then cat "$FAKE_MANIFEST"; else /usr/bin/python3 -I -c '
import hashlib, json, os, sys
root = sys.argv[1]
print(json.dumps({os.path.relpath(os.path.join(d, n), root): [os.path.getsize(os.path.join(d, n)),
      hashlib.sha256(open(os.path.join(d, n), "rb").read()).hexdigest()]
      for d, _, ns in os.walk(root) for n in ns if os.path.isfile(os.path.join(d, n))
      and not os.path.islink(os.path.join(d, n))}))' "$FAKE_VM_FILES"; fi ;;
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

    def release(self, status, verdict, name="Show", *args, auto="auto"):
        self.env["FAKE_RELEASE_INFO"] = "\t".join([RID, status, verdict, auto, name])
        return subprocess.run([str(ROOT / "safetorrent"), "release", RID, *args], env=self.env,
                              capture_output=True, text=True, timeout=30)

    def calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def assert_nothing_copied(self, res):
        self.assertNotEqual(res.returncode, 0)
        self.assertFalse(any("st-guest send" in c for c in self.calls()))
        self.assertFalse(any("mark-released" in c for c in self.calls()))
        self.assertEqual(list(self.downloads.iterdir()) if self.downloads.exists() else [], [])

    def test_clean_is_copied_and_marked(self):
        res = self.release("scanned", "CLEAN")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual((self.downloads / "Show" / "ep1.mkv").read_bytes()[:4], b"\x1a\x45\xdf\xa3")
        self.assertTrue(any(f"mark-released {RID} {self.downloads / 'Show'}" in c for c in self.calls()))
        self.assertEqual([p.name for p in self.downloads.iterdir()], ["Show"])  # no staging folder or lock left

    def test_warning_is_allowed_when_asked(self):
        self.assertEqual(self.release("scanned", "WARNING").returncode, 0)

    def test_bad_verdicts_need_force(self):
        for verdict in ("SUSPICIOUS", "INFECTED", "-"):
            with self.subTest(verdict):
                self.log.unlink(missing_ok=True)
                res = self.release("scanned", verdict)
                self.assertIn("stays in quarantine", res.stderr)
                self.assert_nothing_copied(res)

    def test_unscanned_needs_force(self):
        res = self.release("scanned", "UNSCANNED")
        self.assertIn("couldn't be virus-scanned", res.stderr)
        self.assertIn("stays in quarantine", res.stderr)
        self.assert_nothing_copied(res)
        self.assertEqual(self.release("scanned", "UNSCANNED", "Show", "--force").returncode, 0)
        self.assertTrue((self.downloads / "Show" / "ep1.mkv").exists())

    def test_unvouched_needs_force(self):
        res = self.release("scanned", "UNVOUCHED")
        self.assertIn("no antivirus has a verdict on", res.stderr)
        self.assert_nothing_copied(res)
        self.assertEqual(self.release("scanned", "UNVOUCHED", "Show", "--force").returncode, 0)

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

    def assert_refused(self, res, why):
        self.assertIn(why, res.stderr)
        self.assert_nothing_copied(res)
        self.assertEqual(list(self.downloads.glob(".incoming-*")) if self.downloads.exists() else [], [])
        self.assertFalse((self.home / "Library").exists())

    def test_unsafe_names_from_the_vm_are_refused(self):
        # The VM is untrusted: a compromised one could aim the copy at ~/Library/LaunchAgents.
        for name in ("../../Library/LaunchAgents/x.plist", "..", ".", ".hidden", "a/b", "",
                     "Show\x1b]52;c;x\x07", "Show\x7f", "x" * 256, "é" * 128):
            with self.subTest(name=name):
                self.log.unlink(missing_ok=True)
                self.assert_refused(self.release("scanned", "CLEAN", name), "unsafe name")

    def test_bad_id_from_the_vm_is_refused(self):
        for rid in ("../../x", "ffffff0000", "ABCDEF0123", "abcdef0123/..", ""):
            with self.subTest(rid=rid):
                self.log.unlink(missing_ok=True)
                self.env["FAKE_RELEASE_INFO"] = "\t".join([rid, "scanned", "CLEAN", "auto", "Show"])
                res = subprocess.run([str(ROOT / "safetorrent"), "release", RID], env=self.env,
                                     capture_output=True, text=True, timeout=30)
                self.assert_refused(res, "invalid id")

    def test_unknown_verdict_or_auto_field_is_refused(self):
        for verdict, auto in (("CLEAN;rm", "auto"), ("clean", "auto"), ("CLEAN", "yes"), ("CLEAN", "")):
            with self.subTest(verdict=verdict, auto=auto):
                self.log.unlink(missing_ok=True)
                self.assert_refused(self.release("scanned", verdict, "Show", "--force", auto=auto), "bad data")

    def test_ordinary_names_still_work(self):
        for name in ("Amélie (2001) [1080p]", "Show S01", "x" * 255, "é" * 127, "Show: The Movie", "Show."):
            with self.subTest(name=name):
                res = self.release("scanned", "CLEAN", name)
                self.assertEqual(res.returncode, 0, res.stderr)
                self.assertTrue(any(f"mark-released {RID} {self.downloads / name}" in c for c in self.calls()))
                shutil.rmtree(self.downloads)
                self.log.unlink()

    def test_name_clash_gets_id_suffix(self):
        (self.downloads / "Show").mkdir(parents=True)
        (self.downloads / "Show" / "mine.txt").write_text("keep me")
        self.assertEqual(self.release("scanned", "CLEAN").returncode, 0)
        self.assertEqual((self.downloads / "Show" / "mine.txt").read_text(), "keep me")
        self.assertTrue((self.downloads / f"Show [{RID}]" / "ep1.mkv").exists())

    def test_download_dir_from_config(self):
        conf = self.home / ".config" / "safetorrent"
        conf.mkdir(parents=True)
        (conf / "config").write_text('DOWNLOAD_DIR="~/Elsewhere"  # comment\n')
        self.assertEqual(self.release("scanned", "CLEAN").returncode, 0)
        self.assertTrue((self.home / "Elsewhere" / "Show" / "ep1.mkv").exists())

    def test_already_released_needs_again(self):
        res = self.release("released", "CLEAN")
        self.assertIn("already on your Mac", res.stderr)
        self.assert_nothing_copied(res)
        self.assertEqual(self.release("released", "CLEAN", "Show", "--again").returncode, 0)
        self.assertTrue((self.downloads / "Show" / "ep1.mkv").exists())

    def test_repeated_copies_get_numbered_names(self):
        for _ in range(3):
            self.assertEqual(self.release("released", "CLEAN", "Show", "--again").returncode, 0)
        self.assertEqual(sorted(p.name for p in self.downloads.iterdir()), ["Show", f"Show [{RID} 2]", f"Show [{RID}]"])
        for d in self.downloads.iterdir():
            self.assertEqual([p.name for p in d.iterdir()], ["ep1.mkv"])  # nothing hidden inside

    def test_single_file_torrent_is_released_as_the_file(self):
        shutil.rmtree(self.vm_files / "Show")
        (self.vm_files / "movie.mkv").write_bytes(b"\x1a\x45\xdf\xa3")
        (self.downloads).mkdir(parents=True)
        (self.downloads / "movie.mkv").write_text("mine")
        self.assertEqual(self.release("scanned", "CLEAN", "movie.mkv").returncode, 0)
        self.assertEqual((self.downloads / "movie.mkv").read_text(), "mine")
        self.assertTrue((self.downloads / f"movie [{RID}].mkv").is_file())

    def test_only_one_copy_at_a_time(self):
        self.env["FAKE_SLEEP"] = "1"
        self.env["FAKE_RELEASE_INFO"] = "\t".join([RID, "scanned", "CLEAN", "auto", "Show"])
        procs = [subprocess.Popen([str(ROOT / "safetorrent"), "release", RID], env=self.env,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(2)]
        results = [(p.wait(30), p.stderr.read()) for p in procs]
        for p in procs:
            p.stdout.close()
            p.stderr.close()
        self.assertEqual(sorted(rc for rc, _ in results), [0, 1], results)
        self.assertTrue(any("already being copied" in err for _, err in results), results)
        self.assertEqual([p.name for p in self.downloads.iterdir()], ["Show"])

    def test_lock_left_by_a_killed_copy_is_taken_over(self):
        lock = self.downloads / f".release-{RID}.lock"
        lock.mkdir(parents=True)
        (lock / "pid").write_text("999999")  # no such process
        self.assertEqual(self.release("scanned", "CLEAN").returncode, 0)
        self.assertFalse(lock.exists())

    def test_config_comments_and_quotes(self):
        conf = self.home / ".config" / "safetorrent"
        conf.mkdir(parents=True)
        (conf / "config").write_text("DOWNLOAD_DIR='~/My #1 Shows'   # where they go\n")
        self.assertEqual(self.release("scanned", "CLEAN").returncode, 0)
        self.assertTrue((self.home / "My #1 Shows" / "Show" / "ep1.mkv").exists())

    def test_relative_download_dir_refused(self):
        conf = self.home / ".config" / "safetorrent"
        conf.mkdir(parents=True)
        (conf / "config").write_text("DOWNLOAD_DIR=Downloads/Here\n")
        res = subprocess.run([str(ROOT / "safetorrent"), "release", RID], env=dict(
            self.env, FAKE_RELEASE_INFO="\t".join([RID, "scanned", "CLEAN", "auto", "Show"])),
            cwd=self.tmp, capture_output=True, text=True, timeout=30)
        self.assertIn("full path", res.stderr)
        self.assertFalse((self.tmp / "Downloads").exists())

    def assert_special_refused(self):
        res = self.release("scanned", "CLEAN")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("symlinks or special files", res.stderr)
        self.assertFalse(any("mark-released" in c for c in self.calls()))
        self.assertEqual(list(self.downloads.iterdir()), [])  # no Show, no .incoming-*, no lock

    def test_symlink_in_the_copy_is_refused(self):
        (self.home / ".ssh").mkdir()
        os.symlink(self.home / ".ssh", self.vm_files / "Show" / "Subs")
        self.assert_special_refused()

    def test_fifo_in_the_copy_is_refused(self):
        os.mkfifo(self.vm_files / "Show" / "pipe")
        self.assert_special_refused()

    def test_setuid_and_group_write_are_stripped(self):
        os.chmod(self.vm_files / "Show" / "ep1.mkv", 0o6777)
        self.assertEqual(self.release("scanned", "CLEAN").returncode, 0)
        mode = os.stat(self.downloads / "Show" / "ep1.mkv").st_mode
        self.assertEqual(mode & (stat.S_ISUID | stat.S_ISGID | stat.S_IWGRP | stat.S_IWOTH), 0)

    def manifest_of(self, files: dict) -> Path:
        path = self.tmp / "manifest.json"
        path.write_text(json.dumps({rel: [len(data), hashlib.sha256(data).hexdigest()] for rel, data in files.items()}))
        return path

    def assert_mismatch_refused(self, res, why):
        self.assertNotEqual(res.returncode, 0)
        self.assertIn(why, res.stderr)
        self.assertFalse(any("mark-released" in c for c in self.calls()))
        self.assertEqual(list(self.downloads.iterdir()), [])  # nothing moved in, staging and manifest gone

    def test_file_changed_after_the_scan_is_refused(self):
        self.env["FAKE_MANIFEST"] = str(self.manifest_of({"Show/ep1.mkv": b"\x1a\x45\xdf\xa3original"}))
        self.assert_mismatch_refused(self.release("scanned", "CLEAN"), "changed after the scan")

    def test_extra_or_missing_file_is_refused(self):
        video = (self.vm_files / "Show" / "ep1.mkv").read_bytes()
        self.env["FAKE_MANIFEST"] = str(self.manifest_of({"Show/ep1.mkv": video}))
        # Empty, so the stream isn't bigger than what was scanned and the manifest check is what refuses it.
        (self.vm_files / "Show" / "extra.exe").write_bytes(b"")
        self.assert_mismatch_refused(self.release("scanned", "CLEAN"), "never scanned: Show/extra.exe")
        self.log.unlink()
        (self.vm_files / "Show" / "extra.exe").write_bytes(b"MZ")
        self.assert_mismatch_refused(self.release("scanned", "CLEAN"), "more than was scanned")
        (self.vm_files / "Show" / "extra.exe").unlink()
        self.log.unlink()
        self.env["FAKE_MANIFEST"] = str(self.manifest_of({"Show/ep1.mkv": video, "Show/ep2.mkv": video}))
        self.assert_mismatch_refused(self.release("scanned", "CLEAN"), "missing: Show/ep2.mkv")

    def test_hostile_stream_from_the_vm_writes_nothing_outside(self):
        """A compromised VM sends whatever it likes: a path out of the staging folder."""
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            ti = tarfile.TarInfo("../../Library/LaunchAgents/evil.plist")
            ti.size = 2
            tar.addfile(ti, io.BytesIO(b"<x"))
        (self.tmp / "evil.tar").write_bytes(buf.getvalue())
        self.env["FAKE_TAR"] = str(self.tmp / "evil.tar")
        self.assert_mismatch_refused(self.release("scanned", "CLEAN"), "path leading out of the folder")
        self.assertFalse((self.home / "Library").exists())
        self.assertFalse((self.home / "Downloads" / "Library").exists())

    def test_missing_manifest_is_refused(self):
        self.env["FAKE_MANIFEST"] = "/nonexistent"
        self.assert_mismatch_refused(self.release("scanned", "CLEAN"), "record of what was scanned")

    def test_verdict_changed_during_copy_is_refused(self):
        self.env["FAKE_RELEASE_INFO2"] = "\t".join([RID, "scanned", "INFECTED", "auto", "Show", "later"])
        res = self.release("scanned", "CLEAN")
        self.assertTrue(any("st-guest send" in c for c in self.calls()))  # copied, then thrown away
        self.assert_mismatch_refused(res, "scan result changed while copying")

    @unittest.skipUnless(sys.platform == "darwin", "Gatekeeper's quarantine flag is macOS-only")
    def test_every_file_gets_gatekeeper_quarantine_flag(self):
        (self.vm_files / "Show" / "App.app" / "Contents").mkdir(parents=True)
        (self.vm_files / "Show" / "App.app" / "Contents" / "run").write_bytes(b"#!/bin/sh\n")
        # An unsigned app in a show: the Mac's own check holds it, so force it through.
        self.assertEqual(self.release("scanned", "CLEAN", "Show", "--force").returncode, 0)
        dest = self.downloads / "Show"
        paths = [dest, *dest.rglob("*")]
        self.assertGreater(len(paths), 4)
        for p in paths:
            flag = subprocess.run(["xattr", "-p", "com.apple.quarantine", str(p)], capture_output=True, text=True)
            self.assertEqual(flag.returncode, 0, f"no quarantine flag on {p}")
            self.assertIn(";safetorrent;", flag.stdout)

    def test_mac_rechecks_what_the_vm_called_clean(self):
        """A taken-over VM can report CLEAN for anything; the Mac's own rules still catch it."""
        (self.vm_files / "Show" / "Codec_Installer.exe").write_bytes(b"MZ")  # smaller than the episode
        res = self.release("scanned", "CLEAN")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Codec_Installer.exe", res.stderr)
        self.assertIn("your Mac's own check held it back: Show/Codec_Installer.exe:", res.stderr)
        self.assertFalse(any("mark-released" in c for c in self.calls()))
        self.assertEqual(list(self.downloads.iterdir()), [])
        res = self.release("scanned", "CLEAN", "Show", "--force")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertTrue((self.downloads / "Show" / "Codec_Installer.exe").exists())

    def test_no_release_when_the_quarantine_flag_cant_be_set(self):
        """Some drives drop extended attributes: an app copied there would open with no Gatekeeper check."""
        fake = self.tmp / "bin" / "xattr"
        fake.write_text("#!/bin/sh\nexit 1\n")
        fake.chmod(0o755)
        res = self.release("scanned", "CLEAN")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("quarantine flag", res.stderr)
        self.assertFalse(any("mark-released" in c for c in self.calls()))
        self.assertEqual(list(self.downloads.iterdir()), [])  # nothing in place, staging cleaned up


if __name__ == "__main__":
    unittest.main()
