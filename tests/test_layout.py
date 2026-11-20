"""Who owns what inside the VM. Root keeps every download's folder and the state
folder; the torrent user (aria2, 7z, ClamAV) only gets files/ and extracted/.
Otherwise a compromised parser could forge meta.json (a fake CLEAN verdict gets
auto-released) or plant symlinks for root to write through. Runs anywhere:
ownership changes are recorded rather than made."""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from test_rules import bencode, st


def ok(cmd, **kw):
    return subprocess.CompletedProcess(cmd, 0, "", "")


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.addCleanup(mock.patch.stopall)
        self.quarantine = self.tmp / "srv" / "quarantine"
        self.state = self.tmp / "var" / "safetorrent"
        self.quarantine.mkdir(parents=True)
        self.state.mkdir(parents=True)
        mock.patch.object(st, "QUARANTINE", self.quarantine).start()
        mock.patch.object(st, "STATE_DIR", self.state).start()
        mock.patch.object(st, "TORRENT_HOME", self.state / "torrent").start()
        self.run = mock.patch.object(st, "run", side_effect=ok).start()
        self.chown = mock.patch.object(st.shutil, "chown").start()

    def commands(self):
        return [c.args[0] for c in self.run.call_args_list]


class Precheck(Base):
    def test_download_folder_stays_roots(self):
        info = {"name": "Film", "piece length": 16384, "pieces": b"x" * 20, "length": 900 * 1024**2}
        src = self.tmp / "src.torrent"
        src.write_bytes(bencode({"info": info}))
        meta, _info, _existed = st.precheck(src, dict(st.DEFAULTS), None, None, True)
        d = self.quarantine / meta["id"]
        self.chown.assert_not_called()
        self.assertEqual(d.stat().st_mode & 0o022, 0)  # nobody else can add, rename or replace entries
        self.assertIn(["install", "-d", "-o", "torrent", "-g", "torrent", str(d / "files")], self.commands())


class MagnetMetadata(Base):
    MAGNET = "magnet:?xt=urn:btih:" + "a" * 40

    def setUp(self):
        super().setUp()
        self.dirs = []
        mock.patch("builtins.print").start()

    def fetch(self, write=lambda dest: (dest / "x.torrent").write_bytes(b"d4:infodee")):
        def aria2(cmd, **kw):
            dest = Path(next(a for a in cmd if a.startswith("--dir="))[6:])
            self.dirs.append(dest)
            write(dest)
            return ok(cmd)
        self.run.side_effect = aria2
        src = self.tmp / "src.magnet"
        src.write_text(self.MAGNET)
        return st.obtain_torrent(src, dict(st.DEFAULTS))

    def test_fresh_private_folder_each_time(self):
        self.assertEqual(self.fetch(), b"d4:infodee")
        self.fetch()
        first, second = self.dirs
        self.assertNotEqual(first, second)
        for dest in self.dirs:
            self.assertEqual(dest.parent, self.state)
            self.assertFalse(dest.exists())  # cleaned up
        self.assertEqual([c.args[0] for c in self.chown.call_args_list], self.dirs)
        self.assertIn(f"--dht-file-path={self.state / 'torrent' / 'dht.dat'}", self.commands()[0])

    def test_symlinked_result_is_not_read(self):
        secret = self.tmp / "shadow"
        secret.write_text("root:secret")
        with self.assertRaises(OSError):
            self.fetch(lambda dest: (dest / "x.torrent").symlink_to(secret))

    def test_nothing_found_still_cleans_up(self):
        with self.assertRaises(st.StError):
            self.fetch(lambda dest: None)
        self.assertFalse(self.dirs[0].exists())


class FakeAria2:
    def __init__(self, rc):
        self.rc, self.pid = rc, 4242

    def wait(self, timeout=None):
        return self.rc

    def poll(self):
        return self.rc


class StillRunning(FakeAria2):
    """aria2 that never finishes by itself, so the watchdog has to stop it."""

    def __init__(self):
        super().__init__(None)
        self.stopped = False

    def wait(self, timeout=None):
        if not self.stopped:
            raise subprocess.TimeoutExpired("aria2c", timeout)
        return 143

    def poll(self):
        return 143 if self.stopped else None


class Download(Base):
    def download(self, rc, proc=None, cfg=None):
        d = self.quarantine / "abcdef0123"
        (d / "files").mkdir(parents=True, exist_ok=True)
        meta = {"id": "abcdef0123", "total": 10, "status": "prechecked"}
        with mock.patch.object(st.subprocess, "Popen", return_value=proc or FakeAria2(rc)) as popen:
            st.download(d, meta, cfg or dict(st.DEFAULTS), background=True)
        self.argv = popen.call_args.args[0]
        self.unit = next(a for a in self.argv if a.startswith("--unit="))[len("--unit="):]
        return [c for c in self.commands() if c[0] == "chown"]

    def test_finished_files_are_locked_before_the_scan(self):
        chowns = self.download(0)
        self.assertEqual([c[-2] for c in chowns], ["torrent:torrent", "root:root"])
        self.assertTrue(all("--no-dereference" in c for c in chowns))

    def test_unfinished_files_stay_writable_for_resume(self):
        self.assertEqual([c[-2] for c in self.download(1)], ["torrent:torrent"])

    def test_aria2_runs_in_a_killable_unit(self):
        """runuser leaves a setsid() child running; a unit's cgroup doesn't."""
        self.download(0)
        self.assertEqual(self.argv[0], "systemd-run")
        self.assertIn("KillMode=control-group", self.argv)
        self.assertIn("User=torrent", self.argv)
        self.assertTrue(self.unit.startswith("st-step-aria2-abcdef0123-"), self.unit)
        self.assertEqual(self.argv[self.argv.index("--") + 1], "aria2c")

    def test_unit_is_stopped_before_files_are_locked(self):
        for rc in (0, 1):
            with self.subTest(rc=rc):
                self.run.reset_mock()
                self.download(rc)
                cmds = self.commands()
                stop = cmds.index(["systemctl", "stop", self.unit])
                if rc == 0:
                    self.assertLess(stop, cmds.index(["chown", "-R", "--no-dereference", "root:root",
                                                      str(self.quarantine / "abcdef0123" / "files")]))

    def test_pause_signals_the_unit_not_a_pid(self):
        proc = StillRunning()

        def run(cmd, **kw):
            if cmd[:2] == ["systemctl", "kill"]:
                proc.stopped = True
            return ok(cmd)
        self.run.side_effect = run
        with mock.patch.object(st, "vpn_healthy", return_value=None), \
                mock.patch.object(st.os, "killpg") as killpg, mock.patch.object(st, "save_meta"):
            self.download(None, proc=proc, cfg=dict(st.DEFAULTS, USE_VPN="yes"))
        cmds = self.commands()
        self.assertIn(["systemctl", "kill", "--signal=SIGTERM", self.unit], cmds)
        self.assertLess(cmds.index(["systemctl", "kill", "--signal=SIGTERM", self.unit]),
                        cmds.index(["systemctl", "stop", self.unit]))
        killpg.assert_not_called()


def unit_props(argv: list) -> list:
    return [argv[i + 1] for i, a in enumerate(argv[:argv.index("--")]) if a == "-p"]


def writable(argv: list) -> set:
    paths = [p[len("ReadWritePaths="):].split() for p in unit_props(argv) if p.startswith("ReadWritePaths=")]
    return {Path(x) for group in paths for x in group}


class StepSandbox(Base):
    """What a compromised aria2, 7z or ClamAV could still do: as little as possible."""

    def steps(self):
        """The systemd-run argv of a download, both 7z calls and ClamAV, for one item."""
        from test_scan import Fake7z, Usage  # the scan tests' fakes
        d = self.quarantine / "abcdef0123"
        (d / "files").mkdir(parents=True)
        (d / "files" / "a.zip").write_bytes(b"archive")
        with mock.patch.object(st.subprocess, "Popen", return_value=FakeAria2(0)) as popen:
            st.download(d, {"id": "abcdef0123", "total": 10, "status": "prechecked"}, dict(st.DEFAULTS), background=True)
        aria2 = popen.call_args.args[0]
        fake = Fake7z({"a.zip": {"files": {"x.txt": b"x"}}})
        with mock.patch.object(st, "run", side_effect=fake), \
                mock.patch.object(st.shutil, "which", return_value="/usr/bin/7z"), \
                mock.patch.object(st.shutil, "disk_usage", return_value=Usage(0, 0, 10**12)):
            st.extract_archives(d, [("a.zip", 100)], d / "files", {"MAX_EXTRACT_GB": 20}, "media")
        listing, unpack = [c for c in fake.commands if "/usr/bin/7z" in c]
        db = self.tmp / "clamav"
        db.mkdir()
        (db / "daily.cld").write_text("x")
        with mock.patch.object(st, "run", return_value=subprocess.CompletedProcess([], 0, "", "")) as run, \
                mock.patch.object(st, "CLAMAV_DB", db), mock.patch.object(st, "SCAN_LOCK", self.tmp / "lock"):
            st.clamav_scan(d)
        clam = next(c.args[0] for c in run.call_args_list if "clamscan" in c.args[0])
        return d, {"aria2": aria2, "7z-list": listing, "7z-unpack": unpack, "clamscan": clam}

    def test_every_step_unit_has_the_baseline_sandbox(self):
        _d, steps = self.steps()
        for name, argv in steps.items():
            with self.subTest(name):
                self.assertEqual(argv[0], "systemd-run")
                self.assertTrue(set(st.STEP_SANDBOX) <= set(unit_props(argv)), unit_props(argv))

    def test_unpack_and_scan_have_no_network(self):
        _d, steps = self.steps()
        for name in ("7z-list", "7z-unpack", "clamscan"):
            with self.subTest(name):
                self.assertIn("IPAddressDeny=any", unit_props(steps[name]))

    def test_only_the_unpacker_can_write_and_only_to_extracted(self):
        d, steps = self.steps()
        self.assertEqual(writable(steps["7z-unpack"]), {d / "extracted"})
        self.assertEqual(writable(steps["7z-list"]), set())
        self.assertEqual(writable(steps["clamscan"]), set())

    def test_aria2_can_only_write_its_own_download(self):
        d, steps = self.steps()
        self.assertEqual(writable(steps["aria2"]), {d / "files", self.state / "torrent"})
        self.assertIn(st.NO_PRIVATE_NETS, unit_props(steps["aria2"]))

    def test_metadata_fetch_writes_only_its_temp_folder(self):
        def aria2(cmd, **kw):
            dest = Path(next(a for a in cmd if a.startswith("--dir="))[6:])
            self.assertEqual(writable(cmd), {dest, self.state / "torrent"})
            self.assertTrue(set(st.STEP_SANDBOX) <= set(unit_props(cmd)))
            (dest / "x.torrent").write_bytes(b"d4:infodee")
            return ok(cmd)
        self.run.side_effect = aria2
        src = self.tmp / "src.magnet"
        src.write_text("magnet:?xt=urn:btih:" + "a" * 40)
        with mock.patch("builtins.print"):
            self.assertEqual(st.obtain_torrent(src, dict(st.DEFAULTS)), b"d4:infodee")


class SecureLayout(Base):
    """Migrating a VM set up before the torrent user lost these folders."""

    def setUp(self):
        super().setUp()
        self.lchown = mock.patch.object(st.os, "lchown").start()
        mock.patch.object(st.pwd, "getpwnam", return_value=mock.Mock(pw_uid=999, pw_gid=999)).start()
        self.outside = self.tmp / "etc"
        self.outside.mkdir()
        self.victim = self.outside / "shadow"
        self.victim.write_text("keep")

    def item(self, item_id, status):
        d = self.quarantine / item_id
        (d / "files" / "Show").mkdir(parents=True)
        (d / "meta.json").write_text(json.dumps({"id": item_id, "status": status}))
        return d

    def test_takes_everything_back_for_root(self):
        done = self.item("abcdef0001", "scanned")
        busy = self.item("abcdef0002", "downloading")
        (busy / "aria2.log").symlink_to(self.victim)   # planted for root to write through
        (busy / "meta.json.tmp").symlink_to(self.victim)
        (self.quarantine / "abcdef0003").symlink_to(self.outside)
        (self.quarantine / ".last").write_text("abcdef0001")
        (self.state / "vpn-state.json").write_text('{"ip": "1.2.3.4", "at": 9e9}')  # forged
        (self.state / "dht.dat").write_bytes(b"x")
        (self.state / "metadata").mkdir()
        (self.state / "torrent").symlink_to(self.outside)

        st.secure_layout()

        self.assertEqual(self.victim.read_text(), "keep")
        self.assertFalse((busy / "aria2.log").is_symlink() or (busy / "meta.json.tmp").exists())
        self.assertFalse((self.quarantine / "abcdef0003").is_symlink())
        for name in ("vpn-state.json", "dht.dat", "metadata"):
            self.assertFalse((self.state / name).exists(), name)
        home = self.state / "torrent"
        self.assertTrue(home.is_dir() and not home.is_symlink())

        to_root = {Path(c.args[0]) for c in self.lchown.call_args_list if c.args[1:] == (0, 0)}
        for p in (self.quarantine, self.state, done, busy, done / "meta.json", self.quarantine / ".last"):
            self.assertIn(p, to_root)
        self.assertNotIn(busy / "files", to_root)  # aria2 may still be writing there
        self.lchown.assert_any_call(home, 999, 999)
        self.assertIn(["usermod", "-d", str(home), "torrent"], self.commands())
        # Finished downloads are locked like new ones; one still downloading is left alone.
        self.assertIn(["chown", "-R", "--no-dereference", "root:root", str(done / "files")], self.commands())
        self.assertNotIn(["chown", "-R", "--no-dereference", "root:root", str(busy / "files")], self.commands())


class ReadsRefuseTricks(unittest.TestCase):
    """Root reads heads and hashes of files the torrent user wrote."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_symlink(self):
        (self.tmp / "real").write_bytes(b"secret")
        (self.tmp / "link").symlink_to(self.tmp / "real")
        for read in (st.read_head, st.sha256_file):
            with self.subTest(read.__name__), self.assertRaises(OSError):
                read(self.tmp / "link")

    def test_fifo_does_not_hang(self):
        os.mkfifo(self.tmp / "pipe")
        with self.assertRaises(OSError):
            st.read_head(self.tmp / "pipe")

    def test_regular_file(self):
        (self.tmp / "f").write_bytes(b"MZ\x90")
        self.assertEqual(st.read_head(self.tmp / "f"), b"MZ\x90")


if __name__ == "__main__":
    unittest.main()
