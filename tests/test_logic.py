"""Pure-logic tests for the VM agent: progress parsing, firewall checks,
VirusTotal verdicts, stale-state recovery, folder names. Run anywhere."""
import json
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from test_rules import st

# Real aria2c output shapes (summary-interval mode).
ARIA2_DOWNLOADING = """
 *** Download Progress Summary as of Tue Sep 22 16:41:03 2026 ***
===============================================================================
[#e1a2b3 488MiB/3.7GiB(12%) CN:45 SD:12 DL:60MiB ETA:55s]
FILE: /srv/quarantine/847b30cc51/files/debian-13.7.0-arm64-DVD-1.iso
-------------------------------------------------------------------------------
"""
# Captured from aria2c 1.37 while seeding (it prints no sizes in this state).
ARIA2_SEEDING = """
[#c6a44a SEED(0.0) CN:3 SD:0]
"""
ARIA2_NO_PEERS_YET = """
[#e1a2b3 0B/0B CN:0 DL:0B]
"""

IPT_OK_NO_VPN = """-N ST_OUT
-A ST_OUT -o lo -j RETURN
-A ST_OUT -d 10.0.0.0/8 -j REJECT --reject-with icmp-port-unreachable
-A ST_OUT -d 172.16.0.0/12 -j REJECT --reject-with icmp-port-unreachable
-A ST_OUT -d 192.168.0.0/16 -j REJECT --reject-with icmp-port-unreachable
-A ST_OUT -d 169.254.0.0/16 -j REJECT --reject-with icmp-port-unreachable
-A ST_OUT -d 100.64.0.0/10 -j REJECT --reject-with icmp-port-unreachable"""
IPT_OK_VPN = IPT_OK_NO_VPN + """
-A ST_OUT -o wg0 -j RETURN
-A ST_OUT -m mark --mark 0xca6c -j RETURN
-A ST_OUT -j REJECT --reject-with icmp-port-unreachable"""
IP6_OK_NO_VPN = """-N ST_OUT
-A ST_OUT -o lo -j RETURN
-A ST_OUT -d fc00::/7 -j REJECT --reject-with icmp6-port-unreachable
-A ST_OUT -d fe80::/10 -j REJECT --reject-with icmp6-port-unreachable"""
IP6_OK_VPN = IP6_OK_NO_VPN + """
-A ST_OUT -o wg0 -j RETURN
-A ST_OUT -m mark --mark 0xca6c -j RETURN
-A ST_OUT -j REJECT --reject-with icmp6-port-unreachable"""


def fake_iptables(v4: str, v6: str, jump=True):
    def run(cmd, **kw):
        out = ""
        if "-S" in cmd:
            out = v4 if cmd[0] == "iptables" else v6
        rc = 0 if ("-C" not in cmd or jump) else 1
        return subprocess.CompletedProcess(cmd, rc, out, "")
    return run


class Progress(unittest.TestCase):
    def parse(self, text):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "aria2.log").write_text(text)
            return st.download_progress(Path(tmp))

    def test_downloading(self):
        p = self.parse(ARIA2_DOWNLOADING)
        self.assertEqual(p, {"done": "488MiB", "total": "3.7GiB", "percent": 12, "peers": "45",
                             "speed": "60MiB", "eta": "55s"})

    def test_seeding_line(self):
        p = self.parse(ARIA2_SEEDING)
        self.assertEqual(p, {"seeding": True, "ratio": "0.0", "percent": 100, "peers": "3"})

    def test_seeding_after_downloading(self):
        self.assertTrue(self.parse(ARIA2_DOWNLOADING + ARIA2_SEEDING)["seeding"])

    def test_uses_latest_line(self):
        p = self.parse(ARIA2_DOWNLOADING + ARIA2_DOWNLOADING.replace("12%", "40%"))
        self.assertEqual(p["percent"], 40)

    def test_before_metadata_is_none(self):
        self.assertIsNone(self.parse(ARIA2_NO_PEERS_YET))

    def test_no_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(st.download_progress(Path(tmp)))


class FirewallCheck(unittest.TestCase):
    def check(self, v4, v6, use_vpn, jump=True):
        with mock.patch.object(st, "run", fake_iptables(v4, v6, jump)):
            return st.firewall_ok(use_vpn)

    def test_correct_rules(self):
        self.assertTrue(self.check(IPT_OK_NO_VPN, IP6_OK_NO_VPN, use_vpn=False))
        self.assertTrue(self.check(IPT_OK_VPN, IP6_OK_VPN, use_vpn=True))

    def test_kill_switch_missing_when_vpn_on(self):
        self.assertFalse(self.check(IPT_OK_NO_VPN, IP6_OK_NO_VPN, use_vpn=True))

    def test_leftover_kill_switch_when_vpn_off(self):
        # Would block all downloads with the VPN switched off: must be rebuilt.
        self.assertFalse(self.check(IPT_OK_VPN, IP6_OK_VPN, use_vpn=False))

    def test_missing_lan_block(self):
        v4 = IPT_OK_VPN.replace("-A ST_OUT -d 192.168.0.0/16 -j REJECT --reject-with icmp-port-unreachable\n", "")
        self.assertFalse(self.check(v4, IP6_OK_VPN, use_vpn=True))

    def test_missing_ipv6_rules(self):
        self.assertFalse(self.check(IPT_OK_VPN, "", use_vpn=True))

    def test_chain_not_hooked_up(self):
        self.assertFalse(self.check(IPT_OK_VPN, IP6_OK_VPN, use_vpn=True, jump=False))

    def test_health_does_not_rebuild_good_firewall(self):
        """Rebuilding briefly empties the chain, so a correct firewall must be left alone."""
        with mock.patch.object(st, "firewall_ok", return_value=True), \
             mock.patch.object(st, "apply_firewall") as rebuild:
            st.ensure_firewall(True)
        rebuild.assert_not_called()
        with mock.patch.object(st, "firewall_ok", return_value=False), \
             mock.patch.object(st, "apply_firewall") as rebuild:
            st.ensure_firewall(True)
        rebuild.assert_called_once_with(True)


class VirusTotalVerdicts(unittest.TestCase):
    def scan(self, files: dict, answers: dict, category="software", key="k" * 64, limit="20"):
        """files: relpath -> bytes; answers: filename -> (status, stats)."""
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            for rel, data in files.items():
                p = d / "files" / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(data)
            by_hash = {st.sha256_file(d / "files" / r): answers[Path(r).name] for r in files if Path(r).name in answers}
            lookups = []

            def lookup(sha, _key):
                lookups.append(sha)
                return by_hash.get(sha, ("unknown", None))
            cfg = dict(st.DEFAULTS, VT_API_KEY=key, VT_MAX_LOOKUPS=limit)
            with mock.patch.object(st, "vt_lookup", lookup), mock.patch.object(st.time, "sleep"):
                return st.virustotal(d, cfg, category, on_progress=lambda _m: None), lookups

    def test_many_engines_is_infected(self):
        f, _ = self.scan({"app/setup.exe": b"MZ1"}, {"setup.exe": ("found", {"malicious": 40, "undetected": 30})})
        self.assertEqual(st.max_level(f), st.INFECTED)

    def test_one_engine_is_danger_not_infected(self):
        f, _ = self.scan({"app/setup.exe": b"MZ2"}, {"setup.exe": ("found", {"malicious": 1, "undetected": 69})})
        self.assertEqual(st.max_level(f), st.DANGER)

    def test_clean_program(self):
        f, _ = self.scan({"app/setup.exe": b"MZ3"}, {"setup.exe": ("found", {"malicious": 0, "undetected": 70})})
        self.assertEqual(st.max_level(f), st.INFO)

    def test_unknown_program_warns_but_unknown_archive_does_not(self):
        f, _ = self.scan({"app/setup.exe": b"MZ4"}, {})
        self.assertEqual(st.max_level(f), st.WARN)
        f, _ = self.scan({"app/data.zip": b"PK5"}, {})
        self.assertEqual(st.max_level(f), st.INFO)

    def test_media_is_not_looked_up(self):
        _, lookups = self.scan({"m/movie.mkv": b"\x1a\x45\xdf\xa3", "m/movie.srt": b"1"}, {})
        self.assertEqual(lookups, [])

    def test_disguised_program_is_looked_up(self):
        _, lookups = self.scan({"m/movie.mp4": b"MZ-disguised"}, {}, category="media")
        self.assertEqual(len(lookups), 1)

    def test_rejected_key(self):
        f, _ = self.scan({"a/x.exe": b"MZ6"}, {"x.exe": ("badkey", None)})
        self.assertIn("rejected the API key", f[-1]["msg"])

    def test_duplicate_files_looked_up_once(self):
        _, lookups = self.scan({"a/x.exe": b"same", "a/y.exe": b"same"}, {})
        self.assertEqual(len(lookups), 1)

    def test_lookup_cap(self):
        files = {f"a/{i}.exe": f"MZ{i}".encode() for i in range(5)}
        f, lookups = self.scan(files, {}, limit="2")
        self.assertEqual(len(lookups), 2)
        self.assertTrue(any("only the 2 riskiest of 5" in x["msg"] for x in f))

    def test_no_key_skips(self):
        f, lookups = self.scan({"a/x.exe": b"MZ"}, {}, key="")
        self.assertEqual(lookups, [])
        self.assertIn("skipped", f[0]["msg"])


class Verdicts(unittest.TestCase):
    def test_worst_finding_wins(self):
        f = [st.finding(st.INFO, "", "a"), st.finding(st.WARN, "", "b"), st.finding(st.INFECTED, "", "c")]
        self.assertEqual(st.SCAN_VERDICT[st.max_level(f)], "INFECTED")
        self.assertEqual(st.SCAN_VERDICT[st.max_level([])], "CLEAN")
        self.assertEqual(st.PRE_VERDICT[st.max_level([st.finding(st.DANGER, "", "x")])], "REJECTED")


class StaleState(unittest.TestCase):
    def make(self, tmp, **meta):
        d = Path(tmp) / "abcdef0123"
        d.mkdir()
        base = {"id": "abcdef0123", "status": "downloading", "precheck": {"verdict": "OK", "findings": []}}
        (d / "meta.json").write_text(json.dumps({**base, **meta}))
        return d

    def test_dead_download_becomes_resumable(self):
        with tempfile.TemporaryDirectory() as tmp:
            m = st.item_view(self.make(tmp, status="downloading"), running=set())
            self.assertEqual(m["status"], "incomplete")
            self.assertIn("Interrupted", m["error"])

    def test_dead_scan_goes_back_to_downloaded(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(st.item_view(self.make(tmp, status="scanning"), running=set())["status"], "downloaded")

    def test_running_download_untouched(self):
        with tempfile.TemporaryDirectory() as tmp:
            m = st.item_view(self.make(tmp, status="downloading"), running={"abcdef0123"})
            self.assertEqual((m["status"], m["running"]), ("downloading", True))

    def test_just_queued_is_given_time_to_start(self):
        with tempfile.TemporaryDirectory() as tmp:
            m = st.item_view(self.make(tmp, status="queued", queued_at=time.time()), running=set())
            self.assertEqual(m["status"], "queued")
            m = st.item_view(self.make_old(tmp), running=set())
            self.assertEqual(m["status"], "incomplete")

    def make_old(self, tmp):
        d = Path(tmp) / "abcdef0124"
        d.mkdir()
        (d / "meta.json").write_text(json.dumps({"id": "abcdef0124", "status": "queued", "queued_at": 0,
                                                 "precheck": {"verdict": "OK", "findings": []}}))
        return d


class FolderNames(unittest.TestCase):
    def test_cannot_escape_download_folder(self):
        for evil in ("../../Library/LaunchAgents", "/etc/passwd", "..", "a/../../b", "..\\..\\x"):
            name = st.safe_folder_name(evil, "fallback")
            self.assertNotIn("/", name)
            self.assertNotIn("\\", name)
            self.assertNotIn(name, ("", ".", ".."))

    def test_strips_control_and_bidi(self):
        name = st.safe_folder_name("Movie‮gpj.exe\x07\n", "id")
        self.assertEqual(name, "Moviegpj.exe__")

    def test_length_and_fallback(self):
        self.assertEqual(len(st.safe_folder_name("x" * 500, "id")), 120)
        self.assertEqual(st.safe_folder_name("...", "abc123"), "abc123")


class HealthChecks(unittest.TestCase):
    def db(self, age_days):
        tmp = tempfile.mkdtemp()
        if age_days is not None:
            p = Path(tmp) / "daily.cld"
            p.write_text("x")
            t = time.time() - age_days * 86400
            os.utime(p, (t, t))
        return mock.patch.object(st, "CLAMAV_DB", Path(tmp))

    def test_virus_db_ages(self):
        for age, state in ((None, "block"), (0.2, "ok"), (4, "warn"), (8, "block")):
            with self.db(age):
                self.assertEqual(st.virusdb_check()[0], state, age)

    def test_disk_thresholds(self):
        gb = 1024**3
        self.assertEqual(st.disk_check(2 * gb)[0], "block")
        self.assertEqual(st.disk_check(10 * gb)[0], "warn")
        self.assertEqual(st.disk_check(50 * gb)[0], "ok")


if __name__ == "__main__":
    unittest.main()
