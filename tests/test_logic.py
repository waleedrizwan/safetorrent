"""Pure-logic tests for the VM agent: progress parsing, firewall checks,
VirusTotal verdicts, stale-state recovery, folder names. Run anywhere."""
import contextlib
import io
import json
import os
import shutil
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
                return (*by_hash.get(sha, ("unknown", None)), {})[:3]
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

    def test_only_never_seen_is_marked_unvouched(self):
        # trust_checksum may waive "nobody has seen it", never "an engine flagged it".
        f, _ = self.scan({"app/new.exe": b"MZ6", "app/bad.exe": b"MZ7"},
                         {"bad.exe": ("found", {"malicious": 1, "undetected": 69})})
        self.assertEqual({x["path"]: bool(x.get("unvouched")) for x in f if x["level"] >= st.WARN},
                         {"app/new.exe": True, "app/bad.exe": False})

    def test_only_the_biggest_media_file_is_looked_up(self):
        files = {"m/movie.mkv": b"\x1a\x45\xdf\xa3" * 4, "m/sample.mkv": b"\x1a\x45\xdf\xa3", "m/movie.srt": b"1"}
        _, lookups = self.scan(files, {})
        self.assertEqual(lookups, [st.hashlib.sha256(files["m/movie.mkv"]).hexdigest()])

    def test_known_bad_media_file_is_flagged(self):
        f, _ = self.scan({"m/movie.mkv": b"\x1a\x45\xdf\xa3bad"},
                         {"movie.mkv": ("found", {"malicious": 12, "undetected": 50})}, category="media")
        self.assertEqual(st.max_level(f), st.INFECTED)
        # Never seen is normal for a video: no warning.
        f, _ = self.scan({"m/movie.mkv": b"\x1a\x45\xdf\xa3new"}, {}, category="media")
        self.assertEqual(st.max_level(f), st.INFO)

    def test_disguised_program_is_looked_up(self):
        _, lookups = self.scan({"m/movie.mp4": b"MZ-disguised"}, {}, category="media")
        self.assertEqual(len(lookups), 1)

    def test_brand_new_or_long_unchecked_program_is_unvouched(self):
        now = st.time.time()
        clean = {"malicious": 0, "undetected": 70}
        for dates, unvouched in (({"first_seen": now - 2 * 86400, "last_analysis": now}, True),
                                 ({"first_seen": now - 900 * 86400, "last_analysis": now - 800 * 86400}, True),
                                 ({"first_seen": now - 900 * 86400, "last_analysis": now - 3 * 86400}, False),
                                 ({}, False)):
            with self.subTest(dates):
                f, _ = self.scan({"app/setup.exe": b"MZ8"}, {"setup.exe": ("found", clean, dates)})
                self.assertEqual(any(x.get("unvouched") and x["level"] == st.WARN for x in f), unvouched, f)
        # Only programs: an old archive with no detections is fine.
        f, _ = self.scan({"app/data.zip": b"PK9"}, {"data.zip": ("found", clean, {"first_seen": now})})
        self.assertEqual(st.max_level(f), st.INFO)

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

    def test_no_key_skips_and_leaves_programs_unvouched(self):
        f, lookups = self.scan({"a/x.exe": b"MZ", "a/notes.pdf": b"%PDF"}, {}, key="")
        self.assertEqual(lookups, [])
        self.assertIn("skipped", f[0]["msg"])
        self.assertEqual([(x["path"], x["level"]) for x in f if x.get("unvouched")], [("a/x.exe", st.WARN)])

    def test_programs_past_the_lookup_cap_are_unvouched(self):
        files = {f"a/{i}.exe": f"MZ{i}".encode() for i in range(3)}
        clean = ("found", {"malicious": 0, "undetected": 70})
        f, _ = self.scan(files, {f"{i}.exe": clean for i in range(3)}, limit="1")
        self.assertEqual(len([x for x in f if x.get("unvouched")]), 2)


class HashLookup(unittest.TestCase):
    def vouch(self, files: dict, records, cfg=None):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            for rel, data in files.items():
                (d / "files" / rel).parent.mkdir(parents=True, exist_ok=True)
                (d / "files" / rel).write_bytes(data)
            findings = [st.finding(st.WARN, rel, "never seen", unvouched=True) for rel in files]
            sent = []

            def lookup(sha1s):
                sent.extend(sha1s)
                if records is None:
                    return None
                return {st.hashlib.sha1(files[r]).hexdigest().upper(): rec for r, rec in records.items()}
            with mock.patch.object(st, "hashlookup", side_effect=lookup):
                new = st.hashlookup_vouch(d, findings, cfg or {})
            return findings, new, sent

    def test_nsrl_file_is_vouched(self):
        rec = {"RDS:package_id": "1", "ProductCode": {"ProductName": "7-Zip 23"}}
        findings, new, _ = self.vouch({"a/7z.exe": b"MZ7z"}, {"a/7z.exe": rec})
        self.assertEqual((findings[0]["level"], new), (st.INFO, []))
        self.assertIn("7-Zip 23", findings[0]["msg"])

    def test_known_malware_is_flagged_even_if_also_in_nsrl(self):
        rec = {"RDS:package_id": "1", "KnownMalicious": "malshare.com"}
        findings, new, _ = self.vouch({"a/eicar.com": b"X5O"}, {"a/eicar.com": rec})
        self.assertEqual(findings[0]["level"], st.WARN)
        self.assertEqual([(x["level"], x["path"]) for x in new], [(st.DANGER, "a/eicar.com")])

    def test_user_uploaded_packages_dont_vouch(self):
        findings, _, _ = self.vouch({"a/tool": b"\x7fELF"}, {"a/tool": {"source": "snap:abc"}})
        self.assertEqual(findings[0]["level"], st.WARN)

    def test_unreachable_leaves_everything_unvouched(self):
        findings, new, _ = self.vouch({"a/x.exe": b"MZx"}, None)
        self.assertEqual(findings[0]["level"], st.WARN)
        self.assertIn("couldn't be reached", new[0]["msg"])

    def test_can_be_turned_off(self):
        _, _, sent = self.vouch({"a/x.exe": b"MZx"}, {}, cfg={"HASHLOOKUP": "no"})
        self.assertEqual(sent, [])

    def test_only_sends_hashes_of_unvouched_programs(self):
        _, _, sent = self.vouch({"a/x.exe": b"MZx"}, {})
        self.assertEqual(sent, [st.hashlib.sha1(b"MZx").hexdigest().upper()])


class Verdicts(unittest.TestCase):
    def test_worst_finding_wins(self):
        f = [st.finding(st.INFO, "", "a"), st.finding(st.WARN, "", "b"), st.finding(st.INFECTED, "", "c")]
        self.assertEqual(st.SCAN_VERDICT[st.max_level(f)], "INFECTED")
        self.assertEqual(st.SCAN_VERDICT[st.max_level([])], "CLEAN")
        self.assertEqual(st.PRE_VERDICT[st.max_level([st.finding(st.DANGER, "", "x")])], "REJECTED")


class StaleState(unittest.TestCase):
    def make(self, tmp, item_id="abcdef0123", **meta):
        d = Path(tmp) / item_id
        d.mkdir()
        base = {"id": item_id, "status": "downloading", "precheck": {"verdict": "OK", "findings": []}}
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
            m = st.item_view(self.make(tmp, item_id="abcdef0124", status="queued", queued_at=0), running=set())
            self.assertEqual(m["status"], "incomplete")


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
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
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


class TerminalOutput(unittest.TestCase):
    """Torrent names and paths are printed in the Mac's terminal before you decide to
    download. StringIO isn't a TTY, so paint() adds no escapes: any in the output came
    from the torrent."""
    BAD = ("\x1b", "\x07", "\x9b", "\x90")

    def printed(self, fn, *args) -> str:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            fn(*args)
        return out.getvalue()

    def assertClean(self, out):
        for c in self.BAD:
            self.assertNotIn(c, out)

    def test_findings_cant_inject_escape_sequences(self):
        out = self.printed(st.print_findings, [st.finding(st.DANGER, "\x1b]52;c;ZWNobyBo\x07a.mkv", "x\x1b[2J\x9b")])
        self.assertClean(out)
        self.assertIn("a.mkv", out)

    def test_names_cant_fake_extra_lines(self):
        out = self.printed(st.print_findings, [st.finding(st.WARN, "a\nPre-download check: OK", "m")])
        self.assertEqual(out.count("\n"), 1)

    def test_report_and_list_names_are_neutralised(self):
        meta = {"id": "abcdef0123", "name": "\x1b[1;32mCLEAN\x1b[0m", "total": 10, "file_count": 1,
                "category": "media", "status": "scanned", "added": "2026", "released_to": "/x\x1b]0;t\x07",
                "error": "e\x1b[2K", "precheck": {"verdict": "OK", "findings": []},
                "scan": {"verdict": "CLEAN", "findings": [st.finding(st.INFO, "\x1bP", "\x1b[8m")]}}
        self.assertClean(self.printed(st.print_report, meta))
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        (tmp / meta["id"]).mkdir()
        st.save_meta(tmp / meta["id"], meta)
        with mock.patch.object(st, "QUARANTINE", tmp), mock.patch.object(st, "active_units", return_value=set()):
            out = self.printed(st.cmd_list, None, {})
        self.assertIn("CLEAN", out)
        self.assertClean(out)

    def test_bidi_is_made_visible(self):
        self.assertIn("<U+202E>", st.shown("photo‮gpj.exe"))

    def test_ordinary_unicode_names_unchanged(self):
        name = "Amélie (2001) 日本語 🎬"
        self.assertEqual(st.shown(name), name)
        self.assertIn(name, self.printed(st.print_findings, [st.finding(st.INFO, name, "ok")]))


if __name__ == "__main__":
    unittest.main()
