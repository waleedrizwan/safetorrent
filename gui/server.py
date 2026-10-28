#!/usr/bin/env python3
"""Local web GUI for safetorrent.

Listens on 127.0.0.1 only. Every API request must carry the per-install token
(from ~/.config/safetorrent/gui-token) in a custom header, and the Host header
must be localhost, so other websites can't drive it (CSRF / DNS rebinding).
All the real work is done by the VM agent and the `safetorrent` CLI.
"""
from __future__ import annotations

import base64
import hmac
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

os.environ["PATH"] = "/opt/homebrew/bin:/usr/local/bin:" + os.environ.get("PATH", "/usr/bin:/bin")

ROOT = Path(__file__).resolve().parent.parent
CLI = str(ROOT / "safetorrent")
CONF_DIR = Path.home() / ".config" / "safetorrent"
CONF = CONF_DIR / "config"
TOKEN_FILE = CONF_DIR / "gui-token"
PORT = int(os.environ.get("SAFETORRENT_PORT", "8765"))
VM = "safetorrent"
MAX_BODY = 12 * 1024 * 1024
ANSI = re.compile(r"\x1b\[[0-9;]*m")
GUEST_SH = (
    'cd; if [ -f st-in/st-guest.py ]; then '
    'sudo install -D -m 755 st-in/st-guest.py /opt/safetorrent/st-guest.py && rm st-in/st-guest.py; fi; '
    'exec sudo python3 /opt/safetorrent/st-guest.py --json "$@"'
)


class ApiError(Exception):
    pass


# ---------------------------------------------------------------- VM + CLI plumbing


def vm_status() -> str:
    res = subprocess.run(["limactl", "list", "--format", "{{.Status}}", VM], capture_output=True, text=True)
    return res.stdout.strip() or "Missing"


def guest(*args: str, timeout: int = 120):
    try:
        res = subprocess.run(["limactl", "shell", "--workdir", "/", VM, "--", "sh", "-c", GUEST_SH, "st-guest", *args],
                             capture_output=True, text=True, encoding="utf-8",
                             errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired:
        raise ApiError("The VM took too long to answer.") from None
    lines = res.stdout.strip().splitlines()
    try:
        out = json.loads(lines[-1])
    except (IndexError, ValueError):
        raise ApiError(ANSI.sub("", res.stderr.strip() or res.stdout.strip()) or "The VM command failed.") from None
    if isinstance(out, dict) and out.get("error"):
        raise ApiError(out["error"])
    return out


def cli(*args: str, timeout: int = 900) -> str:
    res = subprocess.run([CLI, *args], capture_output=True, text=True, encoding="utf-8", errors="replace",
                         timeout=timeout, stdin=subprocess.DEVNULL)
    text = ANSI.sub("", (res.stdout + res.stderr)).strip()
    if res.returncode != 0:
        msg = [ln for ln in text.splitlines() if ln.startswith("error:")]
        raise ApiError((msg[-1][6:].strip() if msg else text.splitlines()[-1] if text else "Command failed."))
    return text


def push_inbox(path: Path) -> None:
    res = subprocess.run(["limactl", "copy", str(path), f"{VM}:st-in/"], capture_output=True, text=True)
    if res.returncode != 0:
        raise ApiError("Couldn't hand the torrent to the VM: " + res.stderr.strip())


# ---------------------------------------------------------------- config file


def read_config() -> dict:
    cfg = {}
    if CONF.exists():
        for line in CONF.read_text().splitlines():
            s = line.strip()
            if s and not s.startswith("#") and "=" in s:
                k, v = s.split("=", 1)
                cfg[k.strip()] = v.split(" #", 1)[0].strip().strip("'\"")
    return cfg


def write_config(updates: dict) -> None:
    CONF_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    lines = CONF.read_text().splitlines() if CONF.exists() else []
    for key, value in updates.items():
        for i, line in enumerate(lines):
            if re.match(rf"\s*{key}=", line):
                lines[i] = f"{key}={value}"
                break
        else:
            lines.append(f"{key}={value}")
    tmp = CONF.with_suffix(".tmp")
    tmp.write_text("\n".join(lines) + "\n")
    os.chmod(tmp, 0o600)
    tmp.replace(CONF)


def public_settings() -> dict:
    cfg = read_config()
    key = cfg.get("VT_API_KEY", "")
    return {
        "vt_key_set": bool(key),
        "vt_key_hint": ("…" + key[-4:]) if key else "",
        "use_vpn": cfg.get("USE_VPN", "no").lower() in ("yes", "true", "1"),
        "vpn_config_present": (CONF_DIR / "wg0.conf").exists(),
        "download_dir": cfg.get("DOWNLOAD_DIR", "~/Downloads/SafeTorrents"),
        "seed_minutes": cfg.get("SEED_MINUTES", "0"),
    }


def download_dir() -> Path:
    raw = read_config().get("DOWNLOAD_DIR", "~/Downloads/SafeTorrents")
    return Path(os.path.expanduser(raw))


# ---------------------------------------------------------------- shared state + workers


class State:
    lock = threading.Lock()
    vm = "Unknown"
    health: dict | None = None
    health_error: str | None = None
    items: list = []
    free = 0
    items_error: str | None = None
    busy: dict = {}              # operation name -> human label
    release_errors: dict = {}    # item id -> message
    auto_released: set = set()
    wake = threading.Event()


def set_busy(key: str, label: str | None) -> None:
    with State.lock:
        if label:
            State.busy[key] = label
        else:
            State.busy.pop(key, None)


def refresh_health() -> None:
    try:
        health = guest("health", timeout=90)
        with State.lock:
            State.health, State.health_error = health, None
    except ApiError as e:
        with State.lock:
            State.health_error = str(e)


def refresh_items() -> None:
    try:
        data = guest("items", timeout=60)
        with State.lock:
            State.items, State.free, State.items_error = data["items"], data["free"], None
    except ApiError as e:
        with State.lock:
            State.items_error = str(e)


def release(item_id: str, force: bool = False) -> None:
    set_busy(f"release:{item_id}", "Copying to your Mac")
    try:
        cli("release", item_id, *(["--force"] if force else []))
        State.release_errors.pop(item_id, None)
    except Exception as e:
        State.release_errors[item_id] = str(e) if isinstance(e, ApiError) else f"Copy failed: {e}"
        raise
    finally:
        set_busy(f"release:{item_id}", None)
        refresh_items()


def ensure_vm_running() -> None:
    status = vm_status()
    State.vm = status
    if status == "Stopped":
        set_busy("vm", "Starting the VM")
        subprocess.run(["limactl", "start", VM], capture_output=True)
        set_busy("vm", None)
        State.vm = vm_status()
        if State.vm == "Running":
            try:
                cli("sync", timeout=120)
            except ApiError:
                pass


def items_worker() -> None:
    while True:
        try:
            State.vm = vm_status()
            if State.vm == "Running":
                before = {m["id"]: m["status"] for m in State.items}
                refresh_items()
                # A download that died of a VPN/safety problem means health changed: recheck now.
                if any(m["status"] in ("vpn-failed", "blocked") and before.get(m["id"]) != m["status"]
                       for m in State.items):
                    threading.Thread(target=refresh_health, daemon=True).start()
                for m in list(State.items):
                    verdict = (m.get("scan") or {}).get("verdict")
                    if (m["status"] == "scanned" and verdict == "CLEAN" and m.get("auto_release")
                            and m["id"] not in State.auto_released):
                        State.auto_released.add(m["id"])
                        threading.Thread(target=lambda i=m["id"]: _quiet(release, i), daemon=True).start()
        except Exception:
            traceback.print_exc()
        busy = any(m["status"] in ("queued", "downloading", "scanning") for m in State.items)
        State.wake.wait(2.5 if busy else 8)
        State.wake.clear()


def health_worker() -> None:
    while True:
        try:
            if vm_status() == "Running":
                refresh_health()
        except Exception:
            traceback.print_exc()
        time.sleep(30)


def _quiet(fn, *args) -> None:
    try:
        fn(*args)
    except Exception:
        traceback.print_exc()


def background(key: str, label: str, fn, *args) -> None:
    def job():
        set_busy(key, label)
        try:
            fn(*args)
        except ApiError as e:
            with State.lock:
                State.release_errors[key] = str(e)
        finally:
            set_busy(key, None)
            refresh_health()
            State.wake.set()
    threading.Thread(target=job, daemon=True).start()


# ---------------------------------------------------------------- API handlers


def api_state(_body) -> dict:
    with State.lock:
        return {
            "vm": State.vm, "health": State.health, "health_error": State.health_error,
            "items": State.items, "free": State.free, "items_error": State.items_error,
            "busy": dict(State.busy), "errors": dict(State.release_errors), "settings": public_settings(),
        }


def api_add(body) -> dict:
    if State.health and State.health.get("blocked"):
        raise ApiError("Downloads are blocked until the safety checks pass.")
    # Validate before creating the staging folder so a rejected request leaves nothing behind.
    if body.get("magnet"):
        magnet = body["magnet"].strip()
        if not magnet.startswith("magnet:?"):
            raise ApiError("That isn't a magnet link. It should start with magnet:?")
        suffix, data = ".magnet", magnet.encode()
    elif body.get("torrent_b64"):
        try:
            suffix, data = ".torrent", base64.b64decode(body["torrent_b64"], validate=True)
        except ValueError:
            raise ApiError("That .torrent file couldn't be read.") from None
    else:
        raise ApiError("Paste a magnet link or choose a .torrent file.")
    stage = Path(tempfile.mkdtemp())
    path = stage / ("src-" + secrets.token_hex(6) + suffix)
    path.write_bytes(data)
    args = ["add", path.name]
    if body.get("category") in ("media", "software", "docs", "iso"):
        args += ["--category", body["category"]]
    if body.get("sha256"):
        args += ["--sha256", body["sha256"].strip()]
    if body.get("auto_release") is False:
        args.append("--no-auto-release")
    set_busy("add", "Reading the torrent's file list")
    try:
        push_inbox(path)
        meta = guest(*args, timeout=400)
    finally:
        set_busy("add", None)
        path.unlink(missing_ok=True)
        stage.rmdir()
    if body.get("auto_start", True) and not meta.get("existed") and meta["precheck"]["verdict"] == "OK":
        guest("start", meta["id"])
        meta["started"] = True
    refresh_items()
    State.wake.set()
    return meta


def item_action(item_id: str, action: str, body) -> dict:
    if not re.fullmatch(r"[0-9a-f]{6,40}", item_id):
        raise ApiError("Unknown download.")
    if action == "start":
        guest("start", item_id, *(["--force"] if body.get("force") else []))
    elif action == "scan":
        guest("start", item_id, "--scan-only")
    elif action == "stop":
        guest("stop", item_id)
    elif action == "delete":
        guest("purge", item_id)
        State.auto_released.discard(item_id)
    elif action == "release":
        State.auto_released.add(item_id)
        release(item_id, bool(body.get("force")))
    elif action == "reveal":
        item = next((m for m in State.items if m["id"] == item_id), None)
        target = item and item.get("released_to")
        if not target or not Path(target).exists():
            raise ApiError("That download isn't on your Mac anymore.")
        subprocess.run(["open", "-R", target])
    else:
        raise ApiError("Unknown action.")
    refresh_items()
    State.wake.set()
    return {"ok": True}


def api_settings(body) -> dict:
    updates = {}
    if "vt_key" in body and body["vt_key"] is not None:
        key = body["vt_key"].strip()
        if key and not re.fullmatch(r"[0-9a-fA-F]{64}", key):
            raise ApiError("A VirusTotal API key is 64 letters and numbers (0-9, a-f).")
        updates["VT_API_KEY"] = key
    if "use_vpn" in body:
        if body["use_vpn"] and not (CONF_DIR / "wg0.conf").exists():
            raise ApiError("Import a WireGuard file from Proton first.")
        updates["USE_VPN"] = "yes" if body["use_vpn"] else "no"
    if "download_dir" in body:
        d = body["download_dir"].strip()
        if not d or "\n" in d:
            raise ApiError("Choose a folder for finished downloads.")
        updates["DOWNLOAD_DIR"] = d
    if "seed_minutes" in body:
        try:
            minutes = int(body["seed_minutes"])
        except (TypeError, ValueError):
            raise ApiError("Seeding time must be a whole number of minutes.") from None
        if not 0 <= minutes <= 10080:
            raise ApiError("Seeding time must be between 0 and 10080 minutes (a week).")
        updates["SEED_MINUTES"] = str(minutes)
    if updates:
        write_config(updates)
        cli("sync", timeout=120)
        refresh_health()
    return public_settings()


def api_vpn_import(body) -> dict:
    text = body.get("conf_text", "")
    if len(text) > 20000 or not all(s in text for s in ("[Interface]", "[Peer]", "PrivateKey", "Endpoint")):
        raise ApiError("That isn't a WireGuard config. On Proton's WireGuard page choose GNU/Linux and a P2P server.")
    fd, tmp = tempfile.mkstemp(suffix=".conf")
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, text.encode())
        os.close(fd)
        set_busy("vpn", "Testing the new VPN config")
        cli("vpn-import", tmp, timeout=180)
    finally:
        set_busy("vpn", None)
        Path(tmp).unlink(missing_ok=True)
        refresh_health()
    return {"ok": True}


def api_update(_body) -> dict:
    background("update", "Updating virus definitions", cli, "update")
    return {"ok": True}


def api_refresh(_body) -> dict:
    refresh_health()
    refresh_items()
    return api_state(None)


def api_vm_start(_body) -> dict:
    threading.Thread(target=lambda: (ensure_vm_running(), refresh_health()), daemon=True).start()
    return {"ok": True}


def api_open_downloads(_body) -> dict:
    d = download_dir()
    d.mkdir(parents=True, exist_ok=True)
    subprocess.run(["open", str(d)])
    return {"ok": True}


def api_quit(body) -> dict:
    def bye():
        time.sleep(0.3)
        if body.get("stop_vm"):
            subprocess.run(["limactl", "stop", VM], capture_output=True)
        os._exit(0)
    threading.Thread(target=bye, daemon=True).start()
    return {"ok": True}


ROUTES = {
    ("GET", "/api/state"): api_state,
    ("POST", "/api/refresh"): api_refresh,
    ("POST", "/api/add"): api_add,
    ("POST", "/api/settings"): api_settings,
    ("POST", "/api/vpn/import"): api_vpn_import,
    ("POST", "/api/update"): api_update,
    ("POST", "/api/vm/start"): api_vm_start,
    ("POST", "/api/open-downloads"): api_open_downloads,
    ("POST", "/api/quit"): api_quit,
}


class Handler(BaseHTTPRequestHandler):
    server_version = "safetorrent"

    def log_message(self, fmt, *args):
        if "/api/state" not in (args[0] if args else ""):
            sys.stderr.write("%s %s\n" % (self.log_date_time_string(), fmt % args))

    def send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                         "font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; "
                         "connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)

    def json(self, code: int, obj) -> None:
        self.send(code, json.dumps(obj).encode(), "application/json")

    def allowed(self) -> bool:
        host = self.headers.get("Host", "")
        if host not in (f"127.0.0.1:{PORT}", f"localhost:{PORT}"):
            return False
        if self.path.startswith("/api/"):
            given = self.headers.get("X-Safetorrent-Token", "")
            return hmac.compare_digest(given, TOKEN)
        return True

    def handle_any(self, method: str) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/ping":
            return self.send(200, b"safetorrent", "text/plain")
        if not self.allowed():
            return self.json(403, {"error": "Not allowed. Open SafeTorrent from its app icon."})
        if method == "GET" and path in ("/", "/index.html"):
            return self.send(200, (ROOT / "gui" / "index.html").read_bytes(), "text/html; charset=utf-8")
        body = {}
        if method == "POST":
            length = int(self.headers.get("Content-Length", "0"))
            if length > MAX_BODY:
                return self.json(413, {"error": "That file is too large to be a .torrent."})
            if not self.headers.get("Content-Type", "").startswith("application/json"):
                return self.json(415, {"error": "Expected JSON."})
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                return self.json(400, {"error": "Bad request."})
        try:
            m = re.fullmatch(r"/api/items/([0-9a-f]+)/([\w-]+)", path)
            if method == "POST" and m:
                return self.json(200, item_action(m.group(1), m.group(2), body))
            handler = ROUTES.get((method, path))
            if not handler:
                return self.json(404, {"error": "Not found."})
            return self.json(200, handler(body))
        except ApiError as e:
            return self.json(400, {"error": str(e)})
        except Exception as e:
            traceback.print_exc()
            return self.json(500, {"error": f"Unexpected error: {e}"})

    def do_GET(self):
        self.handle_any("GET")

    def do_POST(self):
        self.handle_any("POST")


def load_token() -> str:
    CONF_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not TOKEN_FILE.exists():
        TOKEN_FILE.write_text(secrets.token_urlsafe(32))
        os.chmod(TOKEN_FILE, 0o600)
    return TOKEN_FILE.read_text().strip()


TOKEN = load_token()


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    server.daemon_threads = True

    def boot():
        ensure_vm_running()
        if State.vm == "Running":
            try:
                cli("sync", timeout=120)
            except ApiError:
                pass
        threading.Thread(target=items_worker, daemon=True).start()
        threading.Thread(target=health_worker, daemon=True).start()

    threading.Thread(target=boot, daemon=True).start()
    print(f"safetorrent GUI on http://127.0.0.1:{PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
