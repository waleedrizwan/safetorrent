"""Who's working on a download, and what the VM tells the Mac about releasing it.
Downloads started from a terminal aren't systemd units, so the agent records
the process working on each item; the GUI's status refresh and `start` must
respect it. Runs anywhere: /proc and systemd are faked."""
import argparse
import contextlib
import hashlib
import io
import json
import os
import shutil
import signal
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from test_rules import st

ID = "abcdef0123"


def stat_line(start: str) -> str:
    # /proc/<pid>/stat: field 22 is the start time; a process name may contain ") ".
    return "4242 (python3) x) S " + " ".join(str(i) for i in range(4, 22)) + f" {start} 0 0\n"


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(st, "QUARANTINE", self.tmp).start()
        self.units = mock.patch.object(st, "active_units", return_value=set()).start()
        self.starts = {}  # pid -> start time of the "running" processes
        mock.patch.object(st, "proc_start_time", side_effect=self.starts.get).start()

    def make(self, item_id=ID, **meta):
        d = self.tmp / item_id
        d.mkdir(exist_ok=True)
        base = {"id": item_id, "name": "Show", "status": "downloading", "added": "2026-10-28",
                "precheck": {"verdict": "OK", "findings": []}}
        st.save_meta(d, {**base, **meta})
        return d

    def terminal_download(self, pid=4242, start="777", **meta):
        """An item a `safetorrent get` in some terminal is downloading right now."""
        self.starts[pid] = start
        return self.make(worker={"pid": pid, "start": start}, **meta)


class ProcStartTime(unittest.TestCase):
    def test_reads_field_22_even_with_odd_process_names(self):
        with mock.patch.object(st.Path, "read_text", return_value=stat_line("98765")):
            self.assertEqual(st.proc_start_time(4242), "98765")

    def test_gone(self):
        with mock.patch.object(st.Path, "read_text", side_effect=FileNotFoundError):
            self.assertIsNone(st.proc_start_time(4242))


class WorkerTracking(Base):
    def test_claim_records_this_process(self):
        meta = {}
        with mock.patch.object(st.os, "getpid", return_value=4242):
            self.starts[4242] = "777"
            st.claim(meta)
        self.assertEqual(meta["worker"], {"pid": 4242, "start": "777"})
        self.assertTrue(st.worker_alive(meta))

    def test_reused_pid_is_not_the_worker(self):
        self.starts[4242] = "999"  # same pid, different process
        self.assertFalse(st.worker_alive({"worker": {"pid": 4242, "start": "777"}}))

    def test_terminal_download_is_not_marked_interrupted(self):
        m = st.item_view(self.terminal_download(), running=set())
        self.assertEqual((m["status"], m["running"]), ("downloading", True))
        self.assertEqual(st.load_meta(self.tmp / ID)["status"], "downloading")

    def test_dead_terminal_download_is(self):
        d = self.make(worker={"pid": 4242, "start": "777"})  # that process is gone
        self.assertEqual(st.item_view(d, running=set())["status"], "incomplete")

    def test_start_refuses_while_a_terminal_download_runs(self):
        self.terminal_download()
        with mock.patch.object(st, "run") as run, self.assertRaisesRegex(st.StError, "already running"):
            st.cmd_start(argparse.Namespace(id=ID, force=False, scan_only=False, json=True), {})
        run.assert_not_called()  # no second aria2c

    def test_resume_and_rescan_refuse_too(self):
        self.terminal_download(status="scanning")
        with mock.patch.object(st, "enforce"), mock.patch.object(st, "sync_inbox"), \
                mock.patch.object(st, "load_config", return_value={}):
            for cmd in (st.cmd_resume, st.cmd_rescan):
                with self.subTest(cmd.__name__), self.assertRaisesRegex(st.StError, "already running"):
                    cmd(argparse.Namespace(id=ID), {})

    def test_stop_stops_a_terminal_download(self):
        self.terminal_download()

        def killed(pid, sig):
            del self.starts[pid]  # it exits, saving its state as aria2 stops
            meta = st.load_meta(self.tmp / ID)
            st.save_meta(self.tmp / ID, dict(meta, status="incomplete", error="Stopped."))
        with mock.patch.object(st, "run"), mock.patch.object(st.os, "kill", side_effect=killed) as kill, \
                mock.patch.object(st.time, "sleep"), contextlib.redirect_stdout(io.StringIO()):
            st.cmd_stop(argparse.Namespace(id=ID, json=True), {})
        kill.assert_called_once_with(4242, signal.SIGTERM)
        meta = st.load_meta(self.tmp / ID)
        self.assertEqual(meta["status"], "incomplete")
        self.assertIn("Paused", meta["error"])

    def test_sigterm_unwinds_like_ctrl_c(self):
        # So `stop` (and systemd) let download() stop aria2 and save its state.
        with self.assertRaises(KeyboardInterrupt):
            st._terminate(signal.SIGTERM, None)


class Listing(Base):
    def test_one_unreadable_record_doesnt_break_the_list(self):
        self.make(item_id="abcdef0001", status="scanned")
        broken = self.tmp / "abcdef0002"
        broken.mkdir()
        (broken / "meta.json").write_text('{"id": "abcdef0002", "sta')  # cut off mid-write
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            st.cmd_items(argparse.Namespace(json=True), {})
        items = {m["id"]: m for m in json.loads(out.getvalue())["items"]}
        self.assertEqual(items["abcdef0001"]["status"], "scanned")
        self.assertEqual(items["abcdef0002"]["status"], "broken")
        self.assertIn("Delete it", items["abcdef0002"]["error"])

    def test_concurrent_saves_never_leave_a_torn_record(self):
        d = self.make()
        errors = []

        def writer(n):
            try:
                for i in range(40):
                    st.save_meta(d, {"id": ID, "status": "downloading", "phase": f"{n}-{i}" * 50})
            except Exception as e:  # pragma: no cover - reported below
                errors.append(e)
        threads = [threading.Thread(target=writer, args=(n,)) for n in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(st.load_meta(d)["id"], ID)
        self.assertEqual(sorted(p.name for p in d.iterdir()), ["meta.json"])  # no temp files left


class ReleaseState(Base):
    def release_info(self, **meta):
        self.make(**{"status": "scanned", "scan": {"verdict": "CLEAN", "findings": []}, **meta})
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            st.cmd_release_info(argparse.Namespace(id=ID), {})
        return out.getvalue().rstrip("\n").split("\t")

    def test_release_info_says_whether_to_copy_automatically(self):
        self.assertEqual(self.release_info(auto_release=True), [ID, "scanned", "CLEAN", "auto", "Show", "-"])
        self.assertEqual(self.release_info(auto_release=False)[3], "manual")

    def test_unscanned_warning_is_reported_as_unscanned(self):
        """Nothing scanned the bytes, so it mustn't copy as easily as an ordinary WARNING."""
        unscanned = {"level": st.WARN, "path": "Tool/setup.exe", "msg": "too large", "unscanned": True}
        scan_ = {"verdict": "WARNING", "findings": [unscanned]}
        self.assertEqual(self.release_info(scan=scan_)[2], "UNSCANNED")
        trusted = dict(unscanned, level=st.INFO)  # trust_checksum: the publisher's own file
        self.assertEqual(self.release_info(scan={"verdict": "WARNING", "findings": [trusted]})[2], "WARNING")
        ordinary = {"level": st.WARN, "path": "a.docm", "msg": "macros"}
        self.assertEqual(self.release_info(scan={"verdict": "WARNING", "findings": [ordinary]})[2], "WARNING")
        self.assertEqual(st.item_view(self.tmp / ID, set())["release_verdict"], "WARNING")

    def test_unvouched_program_is_reported_as_unvouched(self):
        """VirusTotal has never seen it and nothing else vouches for it: brand-new malware looks like this."""
        unvouched = {"level": st.WARN, "path": "Tool/setup.exe", "msg": "never seen", "unvouched": True}
        self.assertEqual(self.release_info(scan={"verdict": "WARNING", "findings": [unvouched]})[2], "UNVOUCHED")
        vouched = dict(unvouched, level=st.INFO)  # trust_checksum: the publisher's own file
        self.assertEqual(self.release_info(scan={"verdict": "WARNING", "findings": [vouched]})[2], "WARNING")
        unscanned = {"level": st.WARN, "path": "big.iso", "msg": "too large", "unscanned": True}
        self.assertEqual(self.release_info(scan={"verdict": "WARNING", "findings": [unvouched, unscanned]})[2],
                         "UNSCANNED")
        flagged = {"level": st.DANGER, "path": "x.exe", "msg": "flagged"}
        self.assertEqual(self.release_info(scan={"verdict": "SUSPICIOUS", "findings": [unvouched, flagged]})[2],
                         "SUSPICIOUS")

    def test_get_records_no_release(self):
        """`safetorrent get --no-release` must stop the app's auto-release too."""
        health = {"checks": [{"id": "vpn", "state": "ok", "title": "VPN", "detail": ""}]}
        args = argparse.Namespace(source="src.magnet", category=None, sha256=None, yes=True, force=False,
                                  no_auto_release=True)
        with mock.patch.object(st, "enforce", return_value=health), \
                mock.patch.object(st, "inbox", return_value=self.tmp), \
                mock.patch.object(st, "precheck", return_value=({"id": ID, "status": "scanned"}, {}, True)) as pre, \
                mock.patch.object(st, "print_report"), contextlib.redirect_stdout(io.StringIO()):
            st.cmd_get(args, {})
        self.assertIs(pre.call_args.args[4], False)

    def scan(self, **meta):
        d = self.make(status="downloaded", category="media", **meta)
        quiet = mock.patch.multiple(st, run=mock.DEFAULT, ensure_firewall=mock.DEFAULT,
                                    walk_files=mock.Mock(return_value=[]),
                                    extract_archives=mock.Mock(return_value=[]),
                                    clamav_scan=mock.Mock(return_value=[]), virustotal=mock.Mock(return_value=[]))
        with quiet:
            st.scan(d, st.load_meta(d), {"USE_VPN": "no"}, quiet=True)
        return st.load_meta(d)["status"]

    def test_extracted_is_locked_before_clamav(self):
        """7z runs as the torrent user, so what it unpacked must be taken away from it before ClamAV reads it."""
        d = self.make(status="downloaded", category="media")
        calls = []
        with mock.patch.multiple(st, run=mock.Mock(side_effect=lambda cmd, **kw: calls.append(cmd)),
                                 ensure_firewall=mock.DEFAULT, walk_files=mock.Mock(return_value=[]),
                                 extract_archives=mock.Mock(side_effect=lambda *a, **kw: calls.append("7z") or []),
                                 clamav_scan=mock.Mock(side_effect=lambda *a, **kw: calls.append("clamav") or []),
                                 virustotal=mock.Mock(return_value=[])):
            st.scan(d, st.load_meta(d), {"USE_VPN": "no"}, quiet=True)
        extracted = str(d / "extracted")
        lock = [["chown", "-R", "--no-dereference", "root:root", extracted], ["chmod", "-R", "a+rX,go-w", extracted]]
        i = calls.index("7z")
        self.assertEqual(calls[i + 1:i + 4], lock + ["clamav"])

    def test_firewall_is_up_before_anything_unpacks(self):
        """rescan and --scan-only skip prepare(), and the rules are gone after a VM reboot."""
        d = self.make(status="downloaded", category="media")
        calls = []
        with mock.patch.multiple(st, run=mock.DEFAULT, walk_files=mock.Mock(return_value=[]),
                                 ensure_firewall=mock.Mock(side_effect=lambda vpn: calls.append(("firewall", vpn))),
                                 extract_archives=mock.Mock(side_effect=lambda *a, **kw: calls.append("7z") or []),
                                 clamav_scan=mock.Mock(side_effect=lambda *a, **kw: calls.append("clamav") or []),
                                 virustotal=mock.Mock(return_value=[])):
            st.scan(d, st.load_meta(d), {"USE_VPN": "yes"}, quiet=True)
        self.assertEqual(calls, [("firewall", True), "7z", "clamav"])

    def test_archive_7z_flagged_is_not_reported_again_by_clamav(self):
        d = self.make(status="downloaded", category="media")
        locked = st.finding(st.DANGER, "a.zip", "password-protected archive", encrypted=True)
        with mock.patch.multiple(st, run=mock.DEFAULT, ensure_firewall=mock.DEFAULT,
                                 walk_files=mock.Mock(return_value=[]),
                                 extract_archives=mock.Mock(return_value=[locked]),
                                 clamav_scan=mock.Mock(return_value=[]), virustotal=mock.Mock(return_value=[])):
            st.scan(d, st.load_meta(d), {"USE_VPN": "no"}, quiet=True)
            self.assertEqual(st.clamav_scan.call_args.kwargs["flagged"], frozenset({"a.zip"}))

    def test_rescanning_something_already_copied_keeps_it_released(self):
        # Otherwise a rescan makes it look new, and the app or CLI copies it again.
        self.assertEqual(self.scan(released_to="/Users/me/Downloads/SafeTorrents/Show"), "released")
        self.assertEqual(self.scan(), "scanned")


class StepUnits(unittest.TestCase):
    def test_step_units_are_not_items(self):
        out = "st-abcdef0123.service loaded active running x\nst-step-7z-abcdef0123-1a2b3c4d.service loaded active running y\n"
        with mock.patch.object(st, "run", return_value=subprocess.CompletedProcess([], 0, out, "")):
            self.assertEqual(st.active_units(), {"abcdef0123"})

    def test_interrupted_step_stops_its_unit(self):
        """Ctrl-C or `safetorrent stop` kills systemd-run, but the unit would keep going."""
        calls = []

        def run(cmd, **kw):
            calls.append(cmd)
            if cmd[0] == "systemd-run":
                raise KeyboardInterrupt
            return subprocess.CompletedProcess(cmd, 0, "", "")
        with mock.patch.object(st, "run", side_effect=run), self.assertRaises(KeyboardInterrupt):
            st.run_step(["7z", "x", "a.zip"], "st-step-7z-abcdef0123-00000000")
        self.assertEqual(calls[-1], ["systemctl", "stop", "st-step-7z-abcdef0123-00000000"])

    def test_stop_and_purge_stop_the_items_steps(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        calls = []
        with mock.patch.object(st, "QUARANTINE", d), \
                mock.patch.object(st, "run", side_effect=lambda cmd, **kw: calls.append(cmd)), \
                contextlib.redirect_stdout(io.StringIO()):
            (d / ID).mkdir()
            st.save_meta(d / ID, {"id": ID, "status": "scanned"})
            st.cmd_stop(argparse.Namespace(id=ID, json=True), {})
            st.cmd_purge(argparse.Namespace(id=ID, json=True), {})
        self.assertEqual(calls.count(["systemctl", "stop", f"st-step-*-{ID}-*"]), 2)


class SpecialFiles(Base):
    def test_symlink_in_files_is_danger(self):
        """walk_files skips symlinks, so nothing would scan one, yet it would be copied to the Mac."""
        d = self.make(status="downloaded", category="media")
        (d / "files" / "Show").mkdir(parents=True)
        (d / "files" / "Show" / "ep1.mkv").write_bytes(b"\x1a\x45\xdf\xa3video")
        (d / "files" / "Show" / "link").symlink_to("/etc/passwd")
        (d / "files" / "Show" / "dirlink").symlink_to("/etc")
        with mock.patch.multiple(st, run=mock.DEFAULT, ensure_firewall=mock.DEFAULT,
                                 extract_archives=mock.Mock(return_value=[]),
                                 clamav_scan=mock.Mock(return_value=[]), virustotal=mock.Mock(return_value=[])):
            st.scan(d, st.load_meta(d), {"USE_VPN": "no"}, quiet=True)
        scan_ = st.load_meta(d)["scan"]
        danger = {f["path"] for f in scan_["findings"] if f["level"] == st.DANGER}
        self.assertEqual(danger, {"Show/link", "Show/dirlink"})
        self.assertEqual(scan_["verdict"], "SUSPICIOUS")

    def test_fifo_is_special(self):
        root = self.tmp / "f"
        root.mkdir()
        os.mkfifo(root / "pipe")
        (root / "ok.txt").write_text("x")
        self.assertEqual(st.special_entries(root), ["pipe"])


class Manifest(Base):
    """What the scan saw, so the Mac can check it received exactly that."""

    def scanned(self):
        d = self.make(status="downloaded", category="media")
        (d / "files" / "Show").mkdir(parents=True)
        (d / "files" / "Show" / "ep1.mkv").write_bytes(b"\x1a\x45\xdf\xa3video")
        (d / "files" / "Show" / "notes.txt").write_bytes(b"hello")
        with mock.patch.multiple(st, run=mock.DEFAULT, ensure_firewall=mock.DEFAULT,
                                 extract_archives=mock.Mock(return_value=[]),
                                 clamav_scan=mock.Mock(return_value=[]), virustotal=mock.Mock(return_value=[])):
            st.scan(d, st.load_meta(d), {"USE_VPN": "no"}, quiet=True)
        return d

    def manifest(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            st.cmd_manifest(argparse.Namespace(id=ID), {})
        return json.loads(out.getvalue())

    def test_scan_writes_a_manifest(self):
        d = self.scanned()
        files = d / "files"
        want = {rel: [len((files / rel).read_bytes()), hashlib.sha256((files / rel).read_bytes()).hexdigest()]
                for rel in ("Show/ep1.mkv", "Show/notes.txt")}
        self.assertEqual(json.loads((d / "manifest.json").read_text()), want)
        self.assertEqual((d / "manifest.json").stat().st_mode & 0o777, 0o644)
        self.assertEqual(st.load_meta(d)["scan"]["manifest"],
                         hashlib.sha256((d / "manifest.json").read_bytes()).hexdigest())
        self.assertEqual(self.manifest(), want)

    def test_tampered_or_missing_manifest_is_refused(self):
        d = self.scanned()
        (d / "manifest.json").write_text('{"Show/ep1.mkv": [1, "' + "0" * 64 + '"]}')
        with self.assertRaisesRegex(st.StError, "changed since the scan"):
            self.manifest()
        (d / "manifest.json").unlink()
        with self.assertRaisesRegex(st.StError, "missing"):
            self.manifest()

    def test_scanned_by_an_older_version_needs_a_rescan(self):
        self.make(status="scanned", scan={"verdict": "CLEAN", "findings": []})
        with self.assertRaisesRegex(st.StError, "rescan"):
            self.manifest()

    def test_release_info_ends_with_the_scan_time(self):
        """So a rescan between the two release-info calls aborts the copy."""
        d = self.make(status="scanned", scan={"verdict": "CLEAN", "findings": [], "at": "2026-11-19T10:00:00+00:00"})
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            st.cmd_release_info(argparse.Namespace(id=ID), {})
        self.assertEqual(out.getvalue().rstrip("\n").split("\t")[-1], "2026-11-19T10:00:00+00:00")
        self.assertTrue(d.exists())


class Update(unittest.TestCase):
    def test_apt_runs_as_its_own_unit(self):
        """So a GUI timeout or a dropped connection can't kill it halfway through an upgrade."""
        calls = []

        def run(cmd, **kw):
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, "", "")
        with mock.patch.object(st, "run", side_effect=run), mock.patch.object(st, "cmd_health", return_value=0), \
                contextlib.redirect_stdout(io.StringIO()):
            st.cmd_update(argparse.Namespace(json=False), {})
        apt = [c for c in calls if "apt-get" in " ".join(c)]
        self.assertEqual(len(apt), 1)
        self.assertEqual(apt[0][0], "systemd-run")
        self.assertIn("--wait", apt[0])
        self.assertFalse(any(c[0] == "apt-get" for c in calls))


if __name__ == "__main__":
    unittest.main()
