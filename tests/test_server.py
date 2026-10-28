"""Tests for the GUI server: access control, input validation, secret handling,
and (with Google Chrome installed) that hostile torrent names can't run code
in the page. Uses a throwaway HOME; the VM and CLI are mocked out."""
import http.client
import importlib.util
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
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
        mock.patch.object(self.srv, "refresh_items").start()
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


class Settings(ServerBase):
    def conf(self) -> Path:
        return Path(self.home) / ".config" / "safetorrent" / "config"

    def test_validation(self):
        bad = [
            ({"vt_key": "not-a-key"}, "64 letters"),
            ({"seed_minutes": -1}, "between 0"),
            ({"seed_minutes": "abc"}, "whole number"),
            ({"download_dir": "~/x\nUSE_VPN=no"}, "folder"),
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
        "id": "abcdef0123", "name": "Movie " + XSS, "total": 1000, "file_count": 2, "category": "media",
        "status": "scanned", "phase": XSS, "error": XSS2, "auto_release": False, "released_to": XSS,
        "files": [{"path": XSS, "size": 10}],
        "precheck": {"verdict": "OK", "findings": [finding]},
        "scan": {"verdict": "WARNING", "findings": [finding]},
    }
    stopped = dict(item, id="abcdef0124", status="vpn-failed", scan=None, name=XSS2)
    return {
        "vm": "Running", "free": 10**10, "items_error": None, "busy": {}, "errors": {"abcdef0123": XSS},
        "health": {"blocked": True, "checks": [
            {"id": "vpn", "state": "block", "title": XSS, "detail": XSS2, "fix": "import_vpn"}]},
        "health_error": None, "items": [item, stopped],
        "settings": {"vt_key_set": True, "vt_key_hint": XSS, "use_vpn": True, "vpn_config_present": True,
                     "download_dir": XSS, "seed_minutes": "0"},
    }


@unittest.skipUnless(os.path.exists(CHROME), "needs Google Chrome for the browser check")
class HostileNamesInBrowser(ServerBase):
    def test_torrent_names_render_as_text(self):
        self.srv.ROUTES[("GET", "/api/state")] = lambda _body: hostile_state()
        profile = tempfile.mkdtemp()
        try:
            out = subprocess.run(
                [CHROME, "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
                 f"--user-data-dir={profile}", "--virtual-time-budget=6000", "--dump-dom",
                 f"http://127.0.0.1:{self.port}/#t={self.token}"],
                capture_output=True, text=True, timeout=90).stdout
        finally:
            shutil.rmtree(profile, ignore_errors=True)
        self.assertIn('class="item-name"', out, "page didn't render the downloads list")
        self.assertIn("Movie &lt;img src=x onerror=", out)        # shown as text
        self.assertNotIn("<title>PWNED</title>", out)              # never ran
        self.assertNotIn('<img src="x"', out)
        self.assertNotIn("<script>document.title", out)


if __name__ == "__main__":
    unittest.main()
