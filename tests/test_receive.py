"""Tests for host/receive.py, which unpacks the VM's tar stream on the Mac. The VM
is untrusted, so the stream is built here with every kind of hostile member."""
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RECEIVE = ROOT / "host" / "receive.py"
PROFILE = ROOT / "host" / "receive.sb"
SANDBOX_EXEC = "/usr/bin/sandbox-exec"


def tar_of(members) -> bytes:
    """members: (name, type, data) with type a tarfile type constant."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for name, kind, data in members:
            ti = tarfile.TarInfo(name)
            ti.type = kind
            ti.mtime = int(time.time())
            if kind == tarfile.DIRTYPE:
                ti.mode = 0o755
                tar.addfile(ti)
            elif kind == tarfile.REGTYPE:
                ti.size, ti.mode = len(data), 0o644
                tar.addfile(ti, io.BytesIO(data))
            else:
                ti.linkname = data.decode() if data else ""
                tar.addfile(ti)
    return buf.getvalue()


class Receive(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.stage = self.tmp / "out" / "stage"
        self.stage.mkdir(parents=True)
        self.manifest = self.tmp / "manifest.json"
        self.scanned(10**6)

    def scanned(self, total: int):
        self.manifest.write_text(json.dumps({"x": [total, "0" * 64]}))

    def receive(self, data: bytes, *prefix: str) -> subprocess.CompletedProcess:
        return subprocess.run([*prefix, sys.executable, "-I", str(RECEIVE), str(self.stage), str(self.manifest)],
                              input=data, capture_output=True, timeout=60)

    def tree(self, root: Path) -> dict:
        return {p.relative_to(root).as_posix(): (p.read_bytes() if p.is_file() else None)
                for p in sorted(root.rglob("*"))}

    def test_hostile_tar_members_are_refused(self):
        escape = self.tmp / "out" / "escaped"
        cases = {
            "parent": [("../escaped", tarfile.REGTYPE, b"x")],
            "nested parent": [("Show/../../escaped", tarfile.REGTYPE, b"x")],
            "absolute": [(str(escape), tarfile.REGTYPE, b"x")],
            "symlink": [("Show", tarfile.DIRTYPE, b""), ("Show/Subs", tarfile.SYMTYPE, str(self.tmp).encode())],
            "symlink then write through it": [("link", tarfile.SYMTYPE, str(self.tmp / "out").encode()),
                                              ("link/escaped", tarfile.REGTYPE, b"x")],
            "hardlink": [("a", tarfile.REGTYPE, b"x"), ("b", tarfile.LNKTYPE, b"a")],
            "fifo": [("pipe", tarfile.FIFOTYPE, b"")],
            "char device": [("dev", tarfile.CHRTYPE, b"")],
            "escape sequence in name": [("Show\x1b]52;c;x\x07.mkv", tarfile.REGTYPE, b"x")],
            "duplicate overwrites": [("a", tarfile.REGTYPE, b"first"), ("a", tarfile.REGTYPE, b"second")],
        }
        for label, members in cases.items():
            with self.subTest(label):
                shutil.rmtree(self.stage)
                self.stage.mkdir()
                res = self.receive(tar_of(members))
                self.assertNotEqual(res.returncode, 0, res.stderr)
                self.assertIn(b"refused", res.stderr)
                self.assertFalse(escape.exists())
                self.assertEqual(sorted(p.name for p in (self.tmp / "out").iterdir()), ["stage"])
                for p in self.stage.rglob("*"):
                    self.assertFalse(p.is_symlink(), p)

    def test_stream_larger_than_manifest_is_cut_off(self):
        self.scanned(10)
        res = self.receive(tar_of([("big.mkv", tarfile.REGTYPE, b"x" * 2**20)]))
        self.assertNotEqual(res.returncode, 0)
        self.assertIn(b"more than was scanned", res.stderr)
        self.assertEqual(list(self.stage.iterdir()), [])

    def test_truncated_stream_is_refused(self):
        data = tar_of([("a.mkv", tarfile.REGTYPE, b"x" * 100000)])
        self.assertNotEqual(self.receive(data[:20000]).returncode, 0)

    def test_stage_must_start_empty(self):
        (self.stage / "planted").write_text("x")
        self.assertNotEqual(self.receive(tar_of([("a", tarfile.REGTYPE, b"x")])).returncode, 0)

    def test_setuid_and_other_write_bits_are_dropped(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            ti = tarfile.TarInfo("tool")
            ti.size, ti.mode = 2, 0o6777
            tar.addfile(ti, io.BytesIO(b"MZ"))
        self.assertEqual(self.receive(buf.getvalue()).returncode, 0)
        self.assertEqual((self.stage / "tool").stat().st_mode & 0o7777, 0o755)

    def test_normal_tree_round_trips(self):
        src = self.tmp / "src"
        files = {"Show/ep1.mkv": b"\x1a\x45\xdf\xa3video", "Show/Extras/Amélie 日本語 🎬.srt": b"subs",
                 "Show/App.app/Contents/run": b"#!/bin/sh\n", "Show/empty.txt": b""}
        for rel, data in files.items():
            (src / rel).parent.mkdir(parents=True, exist_ok=True)
            (src / rel).write_bytes(data)
        (src / "Show" / "Empty folder").mkdir()
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
            tar.add(src, arcname=".")
        res = self.receive(buf.getvalue())
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(self.tree(self.stage), self.tree(src))

    @unittest.skipUnless(sys.platform == "darwin" and os.path.exists(SANDBOX_EXEC), "needs macOS's sandbox-exec")
    def test_receiver_is_sandboxed(self):
        """Even if a check in receive.py were bypassed, it couldn't write outside the stage."""
        target = Path.home() / f".safetorrent-sandbox-test-{os.getpid()}"
        self.addCleanup(lambda: target.unlink() if target.exists() else None)
        stage = os.path.realpath(self.stage)
        probe = (f"open({str(target)!r}, 'w').write('x')")
        res = subprocess.run([SANDBOX_EXEC, "-f", str(PROFILE), "-D", f"STAGE={stage}",
                              "/usr/bin/python3", "-I", "-c", probe], capture_output=True, text=True, timeout=60)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Operation not permitted", res.stderr)
        self.assertFalse(target.exists())
        # The real receiver works under the same profile.
        res = self.receive(tar_of([("a.mkv", tarfile.REGTYPE, b"x")]),
                           SANDBOX_EXEC, "-f", str(PROFILE), "-D", f"STAGE={stage}")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual((self.stage / "a.mkv").read_bytes(), b"x")


if __name__ == "__main__":
    unittest.main()
