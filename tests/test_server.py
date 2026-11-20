"""Tests for the GUI server: access control, input validation, secret handling,
and (with Google Chrome installed) that hostile torrent names can't run code
in the page. Uses a throwaway HOME; the VM and CLI are mocked out."""
import http.client
import importlib.util
import json
import os
import pwd
import shutil
import socket
import stat
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
GOOD_KEY = "0123456789abcdef" * 4


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def load_server(home: str, port: int):
    os.environ["HOME"] = home
    os.environ["SAFETORRENT_PORT"] = str(port)
    spec = importlib.util.spec_from_file_location("st_server", ROOT / "gui" / "server.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class ServerBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Restores HOME, SAFETORRENT_PORT and the PATH the server prepends to, even if HOME was unset.
        cls.env = mock.patch.dict(os.environ)
        cls.env.start()
        cls.home = tempfile.mkdtemp()
        cls.port = free_port()
        cls.srv = load_server(cls.home, cls.port)
        cls.token = cls.srv.TOKEN
        cls.httpd = cls.srv.ThreadingHTTPServer(("127.0.0.1", cls.port), cls.srv.Handler)
        cls.httpd.daemon_threads = True
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.env.stop()
        shutil.rmtree(cls.home, ignore_errors=True)

    def setUp(self):
        # Nothing here may touch the real VM or CLI.
        self.cli = mock.patch.object(self.srv, "cli", return_value="").start()
        self.guest = mock.patch.object(self.srv, "guest").start()
        self.push = mock.patch.object(self.srv, "push_inbox").start()
        mock.patch.object(self.srv, "refresh_health").start()
        self.refresh = mock.patch.object(self.srv, "refresh_items")
        self.refresh.start()
        self.srv.State.health = {"blocked": False, "checks": []}
        self.addCleanup(mock.patch.stopall)

    def request(self, method, path, body=None, token=True, host=None, ctype="application/json", raw=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {"Host": host or f"127.0.0.1:{self.port}"}
        if token:
            headers["X-Safetorrent-Token"] = self.token if token is True else token
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        if data is not None:
            headers["Content-Type"] = ctype
        conn.request(method, path, body=data, headers=headers)
        res = conn.getresponse()
        text = res.read().decode()
        conn.close()
        try:
            return res.status, json.loads(text), res
        except ValueError:
            return res.status, text, res


class AccessControl(ServerBase):
    def test_ping_is_public(self):
        self.assertEqual(self.request("GET", "/ping", token=False)[0], 200)

    def test_api_needs_token(self):
        self.assertEqual(self.request("GET", "/api/state", token=False)[0], 403)
        self.assertEqual(self.request("GET", "/api/state", token="wrong")[0], 403)
        self.assertEqual(self.request("GET", "/api/state")[0], 200)

    def test_other_host_names_refused(self):
        """Blocks DNS-rebinding: a hostile site pointing its own name at 127.0.0.1."""
        for host in ("evil.example:%d" % self.port, "127.0.0.1", "localhost.evil.com:%d" % self.port):
            self.assertEqual(self.request("GET", "/api/state", host=host)[0], 403, host)
            self.assertEqual(self.request("GET", "/", host=host, token=False)[0], 403, host)
        self.assertEqual(self.request("GET", "/api/state", host=f"localhost:{self.port}")[0], 200)

    def test_page_security_headers(self):
        status, _, res = self.request("GET", "/", token=False)
        self.assertEqual(status, 200)
        self.assertEqual(res.getheader("X-Frame-Options"), "DENY")
        self.assertIn("frame-ancestors 'none'", res.getheader("Content-Security-Policy"))

    def test_rejects_non_json_and_oversized_bodies(self):
        self.assertEqual(self.request("POST", "/api/settings", raw=b"a=b",
                                      ctype="application/x-www-form-urlencoded")[0], 415)
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.putrequest("POST", "/api/add", skip_host=True)
        conn.putheader("Host", f"127.0.0.1:{self.port}")
        conn.putheader("X-Safetorrent-Token", self.token)
        conn.putheader("Content-Type", "application/json")
        conn.putheader("Content-Length", str(50 * 1024 * 1024))
        conn.endheaders()
        self.assertEqual(conn.getresponse().status, 413)
        conn.close()

    def test_bad_item_ids(self):
        self.assertEqual(self.request("POST", "/api/items/../../etc/delete", {})[0], 404)
        self.assertEqual(self.request("POST", "/api/items/abc123/format-disk", {})[0], 400)

    def test_malformed_requests_are_400_not_500(self):
        cases = [
            ("POST", "/api/add", b"[1, 2]"),                       # JSON, but not an object
            ("POST", "/api/add", b'{"magnet": 5}'),                # wrong type
            ("POST", "/api/add", b'{"torrent_b64": ["x"]}'),
            ("POST", "/api/settings", b'{"download_dir": 7}'),
            ("POST", "/api/vpn/import", b'{"conf_text": {"a": 1}}'),
        ]
        for method, path, raw in cases:
            with self.subTest(raw=raw):
                self.assertEqual(self.request(method, path, raw=raw)[0], 400)

    def raw_post(self, length):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.putrequest("POST", "/api/add", skip_host=True)
        conn.putheader("Host", f"127.0.0.1:{self.port}")
        conn.putheader("X-Safetorrent-Token", self.token)
        conn.putheader("Content-Type", "application/json")
        conn.putheader("Content-Length", length)
        conn.endheaders()
        status = conn.getresponse().status
        conn.close()
        return status

    def test_bad_content_length(self):
        # A negative length used to mean "read until the client hangs up", tying up a thread.
        self.assertEqual(self.raw_post("-1"), 400)
        self.assertEqual(self.raw_post("lots"), 400)

    def test_non_ascii_token_is_refused_not_a_crash(self):
        self.assertEqual(self.request("GET", "/api/state", token="tökén")[0], 403)


class LaunchCodes(ServerBase):
    """The launcher gets a one-time code for the page's URL instead of putting the
    token on a command line, where any local user could read it with ps."""

    def session(self, code):
        return self.request("POST", "/api/session", {"code": code}, token=False)

    def test_code_needs_the_token(self):
        self.assertEqual(self.request("POST", "/api/launch-code", {}, token=False)[0], 403)

    def test_code_is_traded_for_the_token_once(self):
        code = self.request("POST", "/api/launch-code", {})[1]["code"]
        status, data, _ = self.session(code)
        self.assertEqual((status, data["token"]), (200, self.token))
        status, data, _ = self.session(code)
        self.assertEqual(status, 400)
        self.assertNotIn("token", data)

    def test_expired_and_made_up_codes(self):
        code = self.request("POST", "/api/launch-code", {})[1]["code"]
        with mock.patch.object(self.srv.time, "time", return_value=self.srv.time.time() + 3600):
            self.assertEqual(self.session(code)[0], 400)
        for bad in ("nope", "", 5, None):
            self.assertEqual(self.session(bad)[0], 400, bad)

    def test_session_still_checks_the_host(self):
        code = self.request("POST", "/api/launch-code", {})[1]["code"]
        self.assertEqual(self.request("POST", "/api/session", {"code": code}, token=False,
                                      host=f"evil.example:{self.port}")[0], 403)

    def test_launcher_never_passes_the_token_as_an_argument(self):
        script = (ROOT / "gui" / "launch.sh").read_text()
        self.assertNotIn("#t=", script)
        self.assertIn("-H @-", script)  # the token header goes to curl on stdin


class PageScript(ServerBase):
    def test_script_is_a_file_and_inline_scripts_are_blocked(self):
        status, body, res = self.request("GET", "/app.js", token=False)
        self.assertEqual(status, 200)
        self.assertIn("javascript", res.getheader("Content-Type"))
        self.assertIn("async function api(", body)
        csp = self.request("GET", "/", token=False)[2].getheader("Content-Security-Policy")
        script_src = csp.split("script-src", 1)[1].split(";")[0]
        self.assertEqual(script_src.strip(), "'self'")
        page = (ROOT / "gui" / "index.html").read_text()
        self.assertEqual(page.count("<script"), page.count('<script src="/app.js">'))


class Settings(ServerBase):
    def conf(self) -> Path:
        return Path(self.home) / ".config" / "safetorrent" / "config"

    def test_validation(self):
        bad = [
            ({"vt_key": "not-a-key"}, "64 letters"),
            ({"seed_minutes": -1}, "between 0"),
            ({"seed_minutes": "abc"}, "whole number"),
            ({"download_dir": "~/x\nUSE_VPN=no"}, "folder"),
            ({"download_dir": "~/x\rUSE_VPN=no"}, "folder"),          # splitlines() breaks on these too
            ({"download_dir": "~/x USE_VPN=no"}, "folder"),
            ({"download_dir": "~/x\x1cUSE_VPN=no"}, "folder"),
            ({"download_dir": "~/x\tY"}, "folder"),
            ({"download_dir": "Downloads/Here"}, "full path"),
            ({"use_vpn": True}, "Import a WireGuard"),
        ]
        for body, msg in bad:
            status, data, _ = self.request("POST", "/api/settings", body)
            self.assertEqual(status, 400, body)
            self.assertIn(msg, data["error"])
        self.cli.assert_not_called()

    def test_saves_keeps_comments_and_is_private(self):
        self.conf().parent.mkdir(parents=True, exist_ok=True)
        self.conf().write_text("# my note\nVT_API_KEY=\nSEED_MINUTES=0\n")
        status, data, _ = self.request("POST", "/api/settings", {"vt_key": GOOD_KEY, "seed_minutes": 5})
        self.assertEqual(status, 200)
        text = self.conf().read_text()
        self.assertIn("# my note", text)
        self.assertIn(f"VT_API_KEY={GOOD_KEY}", text)
        self.assertIn("SEED_MINUTES=5", text)
        self.assertEqual(stat.S_IMODE(self.conf().stat().st_mode), 0o600)
        self.cli.assert_called_with("sync", timeout=120)

    def test_api_key_never_sent_back(self):
        self.request("POST", "/api/settings", {"vt_key": GOOD_KEY})
        status, data, _ = self.request("GET", "/api/state")
        self.assertNotIn(GOOD_KEY, json.dumps(data))
        self.assertEqual(data["settings"]["vt_key_hint"], "…" + GOOD_KEY[-4:])


class DownloadFolder(ServerBase):
    def set_dir(self, value):
        conf = Path(self.home) / ".config" / "safetorrent"
        conf.mkdir(parents=True, exist_ok=True)
        (conf / "config").write_text(f"DOWNLOAD_DIR={value}\n")
        self.addCleanup((conf / "config").unlink)

    def folder_check(self):
        status, data, _ = self.request("GET", "/api/state")
        self.assertEqual(status, 200)
        return next(c for c in data["health"]["checks"] if c["id"] == "download_dir")

    def test_ready_folder_passes(self):
        self.set_dir(Path(self.home) / "Downloads" / "SafeTorrents")  # doesn't exist yet: fine
        self.assertEqual(self.folder_check()["state"], "ok")

    def test_unplugged_drive_warns_without_blocking(self):
        self.set_dir("/Volumes/No Such Drive st-test/SafeTorrents")
        check = self.folder_check()
        self.assertEqual(check["state"], "warn")
        self.assertIn("No Such Drive st-test isn't connected", check["detail"])
        self.assertFalse(self.request("GET", "/api/state")[1]["health"]["blocked"])

    def test_unwritable_folder_warns(self):
        locked = Path(self.home) / "locked"
        locked.mkdir()
        locked.chmod(0o500)
        self.addCleanup(locked.chmod, 0o700)
        self.set_dir(locked / "SafeTorrents")
        self.assertIn("can't be written to", self.folder_check()["detail"])

    def test_check_is_not_stored_in_the_vm_health(self):
        self.request("GET", "/api/state")
        self.assertEqual(self.srv.State.health["checks"], [])

    def test_open_folder_on_unplugged_drive_explains(self):
        self.set_dir("/Volumes/No Such Drive st-test/SafeTorrents")
        with mock.patch.object(self.srv.subprocess, "run") as run:
            status, data, _ = self.request("POST", "/api/open-downloads", {})
        self.assertEqual(status, 400)
        self.assertIn("isn't connected", json.dumps(data))
        run.assert_not_called()


class VpnImport(ServerBase):
    def test_rejects_non_wireguard(self):
        oversized = "[Interface]\nPrivateKey = a\n[Peer]\nEndpoint = 1.2.3.4:1\n# " + "x" * 30000
        for text in ("hello", "[Interface]\nPrivateKey = x\n", oversized):
            status, data, _ = self.request("POST", "/api/vpn/import", {"conf_text": text})
            self.assertEqual(status, 400)
        self.cli.assert_not_called()

    def test_temp_file_is_private_and_removed(self):
        seen = {}

        def fake_cli(*args, **kw):
            path = Path(args[1])
            seen["mode"] = stat.S_IMODE(path.stat().st_mode)
            seen["path"] = path
            seen["args"] = args
            return ""
        self.cli.side_effect = fake_cli
        conf = "[Interface]\nPrivateKey = abc\nAddress = 10.2.0.2/32\n[Peer]\nPublicKey = def\nEndpoint = 1.2.3.4:51820\n"
        status, _, _ = self.request("POST", "/api/vpn/import", {"conf_text": conf})
        self.assertEqual(status, 200)
        self.assertEqual(seen["args"][0], "vpn-import")
        self.assertEqual(seen["mode"], 0o600)
        self.assertFalse(seen["path"].exists())

    def test_failed_import_reports_reason(self):
        self.cli.side_effect = self.srv.ApiError("Proton didn't accept that config, so the previous one was kept.")
        conf = "[Interface]\nPrivateKey = a\n[Peer]\nEndpoint = 1.2.3.4:1\n"
        status, data, _ = self.request("POST", "/api/vpn/import", {"conf_text": conf})
        self.assertEqual(status, 400)
        self.assertIn("previous one was kept", data["error"])


class AddTorrent(ServerBase):
    META_OK = {"id": "abcdef0123", "existed": False, "precheck": {"verdict": "OK", "findings": []}}

    def test_blocked_health_refuses(self):
        self.srv.State.health = {"blocked": True, "checks": []}
        status, data, _ = self.request("POST", "/api/add", {"magnet": "magnet:?xt=urn:btih:" + "a" * 40})
        self.assertEqual(status, 400)
        self.assertIn("blocked", data["error"])
        self.push.assert_not_called()

    def test_rejects_non_magnet(self):
        for text in ("http://evil/x.torrent", "javascript:alert(1)", ""):
            status, _, _ = self.request("POST", "/api/add", {"magnet": text})
            self.assertEqual(status, 400, text)
        self.push.assert_not_called()

    def test_rejected_add_leaves_no_temp_folder(self):
        with mock.patch.object(self.srv.tempfile, "mkdtemp", wraps=tempfile.mkdtemp) as mkdtemp:
            for body in ({"magnet": "javascript:alert(1)"}, {}, {"torrent_b64": "not base64!"}):
                self.assertEqual(self.request("POST", "/api/add", body)[0], 400, body)
        mkdtemp.assert_not_called()

    def test_auto_start_only_when_check_passes(self):
        magnet = "magnet:?xt=urn:btih:" + "a" * 40
        self.guest.return_value = dict(self.META_OK)
        self.request("POST", "/api/add", {"magnet": magnet})
        self.assertIn(mock.call("start", "abcdef0123"), self.guest.call_args_list)

        self.guest.reset_mock()
        self.guest.return_value = dict(self.META_OK, precheck={"verdict": "WARNING", "findings": []})
        self.request("POST", "/api/add", {"magnet": magnet})
        self.assertNotIn(mock.call("start", "abcdef0123"), self.guest.call_args_list)

        self.guest.reset_mock()
        self.guest.return_value = dict(self.META_OK)
        self.request("POST", "/api/add", {"magnet": magnet, "auto_start": False})
        self.assertNotIn(mock.call("start", "abcdef0123"), self.guest.call_args_list)

    def test_options_passed_through(self):
        self.guest.return_value = dict(self.META_OK, precheck={"verdict": "WARNING", "findings": []})
        self.request("POST", "/api/add", {"magnet": "magnet:?xt=urn:btih:" + "b" * 40, "category": "media",
                                           "sha256": "c" * 64, "auto_release": False})
        args = self.guest.call_args_list[0][0]
        self.assertEqual(args[0], "add")
        self.assertIn("--no-auto-release", args)
        self.assertEqual(args[args.index("--category") + 1], "media")
        self.assertEqual(args[args.index("--sha256") + 1], "c" * 64)


XSS = '<img src=x onerror="document.title=\'PWNED\'">'
XSS2 = '<script>document.title="PWNED"</script>'


def hostile_state():
    finding = {"level": 2, "path": XSS + "/codec.exe", "msg": XSS2}
    item = {
        "id": "abcdef0123", "name": "Movie " + XSS, "total": XSS, "file_count": XSS, "category": "media",
        "status": "scanned", "phase": XSS, "error": XSS2, "auto_release": False, "released_to": XSS,
        "files": [{"path": XSS, "size": XSS}],
        "precheck": {"verdict": "OK", "findings": [finding]},
        "scan": {"verdict": "WARNING", "findings": [finding]},
    }
    stopped = dict(item, id='abcdef0124"><img src="x', status="vpn-failed", scan=None, name=XSS2)
    return {
        "vm": "Running", "free": 10**10, "items_error": None, "busy": {}, "errors": {"abcdef0123": XSS},
        "health": {"blocked": True, "checks": [
            {"id": "vpn", "state": "block", "title": XSS, "detail": XSS2, "fix": "import_vpn"}]},
        "health_error": None, "items": [item, stopped],
        "settings": {"vt_key_set": True, "vt_key_hint": XSS, "use_vpn": True, "vpn_config_present": True,
                     "download_dir": XSS, "seed_minutes": "0"},
    }


class VmAge(ServerBase):
    def age_check(self, days_old):
        lima = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, lima, ignore_errors=True)
        (lima / "lima.yaml").write_text("x")
        born = os.stat(lima / "lima.yaml").st_birthtime
        listing = subprocess.CompletedProcess([], 0, str(lima) + "\n", "")
        with mock.patch.object(self.srv.subprocess, "run", return_value=listing), \
             mock.patch.object(self.srv.time, "time", return_value=born + days_old * 86400 + 60):
            return self.srv.vm_age_check()

    def test_fresh_vm(self):
        self.assertEqual(self.age_check(3)["state"], "ok")

    def test_old_vm_suggests_a_rebuild(self):
        check = self.age_check(45)
        self.assertEqual(check["state"], "warn")
        self.assertIn("45 days", check["detail"])
        self.assertIn("safetorrent rebuild", check["detail"])

    def test_missing_vm_adds_nothing(self):
        with mock.patch.object(self.srv.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "")):
            self.assertIsNone(self.srv.vm_age_check())


class UntrustedItems(ServerBase):
    """Everything in an item comes from the VM, which a compromised download could control."""
    ID = "abcdef0123"

    def downloads(self) -> Path:
        d = Path(self.home) / "Downloads" / "SafeTorrents"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def reveal(self, released_to):
        self.srv.State.items = [{"id": self.ID, "status": "released", "released_to": released_to}]
        # Patched rather than read from HOME: setUp's stopall also undoes the class's HOME patch.
        with mock.patch.object(self.srv.subprocess, "run") as run, \
                mock.patch.object(self.srv, "download_dir", return_value=self.downloads()):
            status = self.request("POST", f"/api/items/{self.ID}/reveal", {})[0]
        return status, [c.args[0] for c in run.call_args_list]

    def test_reveal_refuses_paths_outside_downloads(self):
        self.downloads()
        for target in ("/etc", "-a/Applications/Calculator.app", "/System/Applications/Utilities/Terminal.app",
                       str(self.downloads() / ".." / ".."), str(self.downloads()), 5, None):
            with self.subTest(target=target):
                status, calls = self.reveal(target)
                self.assertEqual(status, 400)
                self.assertEqual(calls, [])

    def test_reveal_refuses_a_symlink_out_of_downloads(self):
        (self.downloads() / "Linked").symlink_to("/etc")
        status, calls = self.reveal(str(self.downloads() / "Linked"))
        self.assertEqual((status, calls), (400, []))

    def test_reveal_inside_downloads_works(self):
        show = self.downloads() / "Show"
        show.mkdir(exist_ok=True)
        status, calls = self.reveal(str(show))
        self.assertEqual(status, 200)
        self.assertEqual(calls, [["open", "-R", str(show.resolve())]])

    def test_bad_items_from_the_vm_are_dropped_or_coerced(self):
        self.refresh.stop()
        self.guest.return_value = {"free": "lots", "items": [
            {"id": "../x", "status": "scanned"}, "not a dict",
            {"id": self.ID, "status": "pwned", "total": "<b>x</b>", "file_count": -3,
             "files": [{"path": "a", "size": "<i>"}], "precheck": {"verdict": "<b>"},
             "scan": {"verdict": "CLEAN<b>", "findings": [{"level": "9", "path": 1, "msg": None}]}}]}
        self.srv.refresh_items()
        items = self.srv.State.items
        self.assertEqual([m["id"] for m in items], [self.ID])
        m = items[0]
        self.assertEqual((m["status"], m["total"], m["file_count"], m["files"][0]["size"]), ("broken", 0, 0, 0))
        self.assertEqual(m["precheck"]["verdict"], "WARNING")
        self.assertEqual(m["scan"]["verdict"], "SUSPICIOUS")  # never CLEAN, so never auto-released
        self.assertEqual(m["scan"]["findings"], [{"level": 3, "path": "1", "msg": ""}])
        self.assertEqual(self.srv.State.free, 0)

    def test_release_verdict_is_checked_too(self):
        base = {"id": self.ID, "status": "scanned"}
        self.assertEqual(self.srv.sanitize_item(dict(base, release_verdict="UNSCANNED"))["release_verdict"], "UNSCANNED")
        self.assertEqual(self.srv.sanitize_item(dict(base, release_verdict="UNVOUCHED"))["release_verdict"], "UNVOUCHED")
        self.assertEqual(self.srv.sanitize_item(dict(base, release_verdict="<b>"))["release_verdict"], "SUSPICIOUS")
        self.assertNotIn("release_verdict", self.srv.sanitize_item(base))

    def test_ordinary_items_pass_through(self):
        item = {"id": self.ID, "name": "Show", "status": "scanned", "total": 1000, "file_count": 2,
                "files": [{"path": "Show/a.mkv", "size": 900}], "auto_release": True,
                "precheck": {"verdict": "OK", "findings": []},
                "scan": {"verdict": "CLEAN", "findings": [{"level": 0, "path": "", "msg": "fine"}], "at": "now"}}
        self.assertEqual(self.srv.sanitize_item(item), item)


@unittest.skipUnless(os.path.exists(CHROME), "needs Google Chrome for the browser check")
class HostileNamesInBrowser(ServerBase):
    def test_unscanned_item_offers_only_copy_anyway(self):
        state = hostile_state()
        item = dict(state["items"][0], name="Tool", release_verdict="UNSCANNED")
        state["items"] = [item]
        self.srv.ROUTES[("GET", "/api/state")] = lambda _body: state
        out = self.dump_dom()
        self.assertIn('data-act="force-release"', out)
        self.assertNotIn('data-act="release"', out)

    def test_item_the_macs_own_check_held_offers_only_copy_anyway(self):
        state = hostile_state()
        item = dict(state["items"][0], name="Show", status="scanned", release_verdict="CLEAN",
                    scan={"verdict": "CLEAN", "findings": []}, auto_release=True)
        state["items"] = [item]
        state["errors"] = {item["id"]: "your Mac's own check held it back: Show/x.exe: a program; not copying anything."}
        self.srv.ROUTES[("GET", "/api/state")] = lambda _body: state
        out = self.dump_dom()
        self.assertIn('data-act="force-release"', out)
        self.assertNotIn('data-act="release"', out)
        self.assertIn("Held by your Mac", out)

    def test_unvouched_item_offers_only_copy_anyway(self):
        state = hostile_state()
        state["items"] = [dict(state["items"][0], name="Tool", release_verdict="UNVOUCHED")]
        self.srv.ROUTES[("GET", "/api/state")] = lambda _body: state
        out = self.dump_dom()
        self.assertIn('data-act="force-release"', out)
        self.assertNotIn('data-act="release"', out)

    def test_failed_auto_copy_offers_a_retry(self):
        state = hostile_state()
        item = dict(state["items"][0], name="Film", status="scanned", scan={"verdict": "CLEAN", "findings": []},
                    release_verdict="CLEAN", auto_release=True)
        state["items"] = [item]
        state["errors"] = {item["id"]: "the drive SSD isn't connected"}
        self.srv.ROUTES[("GET", "/api/state")] = lambda _body: state
        out = self.dump_dom()
        self.assertIn('data-act="release"', out)
        self.assertIn("Copy failed", out)
        self.assertNotIn("Copying soon", out)

    def dump_dom(self) -> str:
        code = self.request("POST", "/api/launch-code", {})[1]["code"]  # as the launcher does
        profile = tempfile.mkdtemp()
        # Chrome hangs on startup when HOME is the empty test home; only the server needs that one.
        env = dict(os.environ, HOME=pwd.getpwuid(os.getuid()).pw_dir)
        try:
            out = subprocess.run(
                [CHROME, "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
                 f"--user-data-dir={profile}", "--virtual-time-budget=6000", "--dump-dom",
                 f"http://127.0.0.1:{self.port}/#c={code}"],
                capture_output=True, text=True, timeout=90, env=env).stdout
        finally:
            shutil.rmtree(profile, ignore_errors=True)
        self.assertIn('class="item-name"', out, "page didn't render the downloads list")
        self.assertNotIn(code, self.srv.LAUNCH_CODES)  # the page used it up
        return out

    def test_torrent_names_render_as_text(self):
        self.srv.ROUTES[("GET", "/api/state")] = lambda _body: hostile_state()
        code = self.request("POST", "/api/launch-code", {})[1]["code"]  # as the launcher does
        profile = tempfile.mkdtemp()
        # Chrome hangs on startup when HOME is the empty test home; only the server needs that one.
        env = dict(os.environ, HOME=pwd.getpwuid(os.getuid()).pw_dir)
        try:
            out = subprocess.run(
                [CHROME, "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
                 f"--user-data-dir={profile}", "--virtual-time-budget=6000", "--dump-dom",
                 f"http://127.0.0.1:{self.port}/#c={code}"],
                capture_output=True, text=True, timeout=90, env=env).stdout
        finally:
            shutil.rmtree(profile, ignore_errors=True)
        self.assertIn('class="item-name"', out, "page didn't render the downloads list")
        self.assertIn("Movie &lt;img src=x onerror=", out)        # shown as text
        self.assertNotIn("<title>PWNED</title>", out)              # never ran
        self.assertNotIn('<img src="x"', out)
        self.assertNotIn("<script>document.title", out)
        self.assertNotIn(code, self.srv.LAUNCH_CODES)  # the page used it up


if __name__ == "__main__":
    unittest.main()
