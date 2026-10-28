#!/usr/bin/env python3
"""safetorrent guest agent.

Runs as root inside the isolated Lima VM. The macOS `safetorrent` command
copies this file in and calls it; nothing here can reach the Mac's files.

Pipeline for one torrent:
  1. precheck  - read the torrent's file list (no content downloaded yet) and
                 reject classic malware patterns (e.g. an .exe inside a movie).
  2. download  - aria2c, running as the unprivileged `torrent` user, whose
                 network access is firewalled (no LAN/host, VPN-only if enabled).
  3. scan      - real file-type sniffing, archive extraction, ClamAV, and
                 VirusTotal hash lookups.
  4. verdict   - CLEAN downloads are released to the Mac by the host script.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pwd
import re
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

QUARANTINE = Path("/srv/quarantine")
STATE_DIR = Path("/var/lib/safetorrent")
CONFIG_DIR = Path("/etc/safetorrent")
CLAMAV_DB = Path("/var/lib/clamav")
TORRENT_USER = "torrent"
DHT_BOOTSTRAP = "router.bittorrent.com:6881"
WG_FWMARK = "51820"  # wg-quick's default fwmark for wg0's encrypted packets
NOPASS = "-psafetorrent-no-password"  # bogus password so 7z never prompts

INFO, WARN, DANGER, INFECTED = 0, 1, 2, 3
PRE_VERDICT = ["OK", "WARNING", "REJECTED", "REJECTED"]
SCAN_VERDICT = ["CLEAN", "WARNING", "SUSPICIOUS", "INFECTED"]

DEFAULTS = {
    "VT_API_KEY": "",
    "VT_MAX_LOOKUPS": "20",
    "USE_VPN": "no",
    "SEED_MINUTES": "0",
    "STALL_TIMEOUT_MINUTES": "15",
    "METADATA_TIMEOUT_SECONDS": "300",
    "MAX_EXTRACT_GB": "50",
}

# ---------------------------------------------------------------- file kinds

VIDEO = set("mkv mp4 m4v avi mov wmv mpg mpeg ts m2ts webm flv 3gp vob".split())
AUDIO = set("mp3 flac aac m4a ogg oga opus wav alac ape wma aiff dsf".split())
IMAGE = set("jpg jpeg png gif bmp webp tif tiff heic".split())
SIDECAR = set("srt ass ssa sub idx vtt sup nfo txt sfv md5 sha1 sha256 cue log m3u m3u8 xml json".split())
DOCS = set("pdf epub mobi azw azw3 djvu cbz cbr fb2 docx xlsx pptx odt ods odp rtf md".split())
MACRO_DOCS = set("docm dotm xlsm xltm xlam pptm potm ppsm doc xls ppt".split())
ARCHIVES = set("zip rar 7z tar gz tgz bz2 tbz2 xz txz zst lz lzma cab arj".split())
DISK_IMAGES = set("iso img bin".split())
ALWAYS_DANGER = set("lnk scr pif hta vbe jse wsf wsh cpl".split())
EXEC = ALWAYS_DANGER | set(
    "exe msi msp msix appx dll sys com bat cmd ps1 psm1 vbs js reg jar "  # Windows
    "dmg pkg mpkg app command tool workflow scpt kext "  # macOS
    "sh bash zsh run appimage deb rpm so py pl rb desktop apk".split()  # Linux/other
)
JUNK = set("url website webloc".split())
MEDIA_KINDS = {"video", "audio", "image"}

QUALITY_RE = re.compile(r"(?i)(2160p|1080p|720p|\b4k\b|uhd|blu-?ray|bdrip|web-?dl|webrip|remux)")
BIDI_RE = re.compile("[\u200e\u200f\u202a-\u202e\u2066-\u2069]")
SPLIT_PART_RE = re.compile(r"^(r\d\d|z\d\d|\d{3})$")


def ext_of(path: str) -> str:
    parts = path.replace("\\", "/").split("/")
    if any(p.lower().endswith(".app") for p in parts[:-1]):
        return "app"  # anything inside a macOS .app bundle
    name = parts[-1]
    if "." not in name.lstrip("."):
        return ""
    return name.rsplit(".", 1)[1].lower()


def kind_of(ext: str) -> str:
    if ext in EXEC:
        return "exec"
    if ext in VIDEO:
        return "video"
    if ext in AUDIO:
        return "audio"
    if ext in IMAGE:
        return "image"
    if ext in SIDECAR:
        return "sidecar"
    if ext in MACRO_DOCS:
        return "macro"
    if ext in DOCS:
        return "doc"
    if ext in ARCHIVES or SPLIT_PART_RE.match(ext):
        return "archive"
    if ext in DISK_IMAGES:
        return "disk"
    if ext in JUNK:
        return "junk"
    return "other"


def detect_category(files: list[tuple[str, int]]) -> str:
    total = sum(s for _, s in files) or 1
    by_kind: dict[str, int] = {}
    for path, size in files:
        k = kind_of(ext_of(path))
        by_kind[k] = by_kind.get(k, 0) + size
    if sum(by_kind.get(k, 0) for k in MEDIA_KINDS) / total >= 0.7:
        return "media"
    if (by_kind.get("doc", 0) + by_kind.get("macro", 0)) / total >= 0.7:
        return "docs"
    if by_kind.get("disk", 0) / total >= 0.7:
        return "iso"
    return "software"


# ---------------------------------------------------------------- name rules


def finding(level: int, path: str, msg: str) -> dict:
    return {"level": level, "path": path, "msg": msg}


def check_names(files: list[tuple[str, int]], category: str, torrent_name: str = "",
                inner: bool = False) -> list[dict]:
    """Rules that only need file names and sizes (usable before downloading)."""
    out: list[dict] = []
    programs: list[str] = []
    for path, _size in files:
        base = path.replace("\\", "/").rsplit("/", 1)[-1]
        ext = ext_of(path)
        kind = kind_of(ext)
        dots = base.lower().split(".")
        if BIDI_RE.search(path):
            out.append(finding(DANGER, path, "contains hidden right-to-left characters used to fake a file's extension"))
        elif len(dots) >= 3 and dots[-1] in EXEC and kind_of(dots[-2]) not in ("exec", "other", "archive"):
            out.append(finding(DANGER, path, f"double extension: looks like .{dots[-2]} but is really a .{dots[-1]} program"))
        elif ext in ALWAYS_DANGER:
            out.append(finding(DANGER, path, f".{ext} files are almost always malware in torrents"))
        elif kind == "exec":
            if category in ("media", "docs"):
                out.append(finding(DANGER, path, f"a program/script inside a {category} torrent is a classic malware trick"))
            elif category == "iso":
                out.append(finding(WARN, path, "program file sitting outside the disk image"))
            else:
                programs.append(path)
        elif kind == "macro":
            level = DANGER if category == "media" else WARN
            out.append(finding(level, path, "Office format that can carry macros; open with macros disabled"))
        elif kind == "archive" and category == "media":
            out.append(finding(WARN, path, "archive inside a media torrent (unusual); it will be extracted and scanned"))
        elif kind == "disk" and category == "media":
            out.append(finding(WARN, path, "disk image inside a media torrent (unusual)"))
        elif kind == "junk":
            out.append(finding(INFO, path, "web shortcut, usually an ad; ignore it"))
        if "password" in base.lower():
            out.append(finding(WARN, path, "mentions a password; password-protected archives can't be virus-scanned"))
    if programs:
        out.append(finding(INFO, "", f"{len(programs)} program file(s), expected for software; each will be scanned"))
    if category == "media":
        videos = [(p, s) for p, s in files if kind_of(ext_of(p)) == "video"]
        if videos:
            path, size = max(videos, key=lambda f: f[1])
            if size < 50 * 1024**2 and QUALITY_RE.search(torrent_name + " " + path):
                out.append(finding(WARN, path, f"largest video is only {human(size)}, far too small for its claimed quality; likely a fake"))
    if not inner and (not files or sum(s for _, s in files) == 0):
        out.append(finding(DANGER, "", "torrent has no content"))
    return out


# ---------------------------------------------------------------- content sniffing

EXEC_MAGIC = [
    (b"MZ", "Windows program"),
    (b"\x7fELF", "Linux program"),
    (b"\xcf\xfa\xed\xfe", "macOS program"),
    (b"\xce\xfa\xed\xfe", "macOS program"),
    (b"\xfe\xed\xfa\xce", "macOS program"),
    (b"\xfe\xed\xfa\xcf", "macOS program"),
    (b"\xca\xfe\xba\xbe", "macOS/Java program"),
    (b"L\x00\x00\x00\x01\x14\x02\x00", "Windows shortcut"),
]


def _ftyp(h: bytes) -> bool:
    return h[4:8] in (b"ftyp", b"moov", b"mdat", b"free", b"wide", b"skip", b"pnot")


def _mp3(h: bytes) -> bool:
    return h[:3] == b"ID3" or (len(h) > 1 and h[0] == 0xFF and h[1] & 0xE0 == 0xE0)


def _zip(h: bytes) -> bool:
    return h[:2] == b"PK"


EXPECTED_MAGIC = {
    "mkv": lambda h: h[:4] == b"\x1a\x45\xdf\xa3",
    "webm": lambda h: h[:4] == b"\x1a\x45\xdf\xa3",
    "mp4": _ftyp, "m4v": _ftyp, "mov": _ftyp, "m4a": _ftyp, "3gp": _ftyp,
    "avi": lambda h: h[:4] == b"RIFF" and h[8:12] == b"AVI ",
    "wav": lambda h: h[:4] == b"RIFF" and h[8:12] == b"WAVE",
    "mp3": _mp3,
    "flac": lambda h: h[:4] == b"fLaC" or h[:3] == b"ID3",
    "ogg": lambda h: h[:4] == b"OggS", "oga": lambda h: h[:4] == b"OggS", "opus": lambda h: h[:4] == b"OggS",
    "wmv": lambda h: h[:4] == b"\x30\x26\xb2\x75", "wma": lambda h: h[:4] == b"\x30\x26\xb2\x75",
    "flv": lambda h: h[:3] == b"FLV",
    "ts": lambda h: h[:1] == b"\x47",
    "m2ts": lambda h: h[4:5] == b"\x47",
    "mpg": lambda h: h[:3] == b"\x00\x00\x01", "mpeg": lambda h: h[:3] == b"\x00\x00\x01",
    "pdf": lambda h: b"%PDF" in h[:1024],
    "epub": _zip, "cbz": _zip, "docx": _zip, "xlsx": _zip, "pptx": _zip, "zip": _zip,
    "rar": lambda h: h[:4] == b"Rar!", "cbr": lambda h: h[:4] == b"Rar!",
    "7z": lambda h: h[:6] == b"7z\xbc\xaf\x27\x1c",
    "jpg": lambda h: h[:3] == b"\xff\xd8\xff", "jpeg": lambda h: h[:3] == b"\xff\xd8\xff",
    "png": lambda h: h[:8] == b"\x89PNG\r\n\x1a\n",
    "gif": lambda h: h[:4] == b"GIF8",
}


def sniff(path: str, head: bytes) -> list[dict]:
    """Compare a file's real contents with what its extension claims."""
    if not head:
        return []
    ext = ext_of(path)
    kind = kind_of(ext)
    if kind in ("video", "audio", "image", "doc", "sidecar"):
        for magic, desc in EXEC_MAGIC:
            if head.startswith(magic):
                return [finding(DANGER, path, f"is really a {desc} disguised as .{ext}")]
        if kind in MEDIA_KINDS and head.startswith(b"#!"):
            return [finding(DANGER, path, f"is really a script disguised as .{ext}")]
    check = EXPECTED_MAGIC.get(ext)
    if check and not check(head):
        return [finding(WARN, path, f"doesn't look like a real .{ext} file")]
    return []


# ---------------------------------------------------------------- torrents


class _Bdecoder:
    def __init__(self, data: bytes):
        self.d = data
        self.i = 0
        self.info_span: tuple[int, int] | None = None

    def parse(self, depth: int = 0):
        if depth > 64:
            raise ValueError("nested too deeply")
        c = self.d[self.i:self.i + 1]
        if c == b"i":
            end = self.d.index(b"e", self.i)
            value = int(self.d[self.i + 1:end])
            self.i = end + 1
            return value
        if c == b"l":
            self.i += 1
            items = []
            while self.d[self.i:self.i + 1] != b"e":
                items.append(self.parse(depth + 1))
            self.i += 1
            return items
        if c == b"d":
            self.i += 1
            obj = {}
            while self.d[self.i:self.i + 1] != b"e":
                key = self.parse(depth + 1)
                start = self.i
                obj[key] = self.parse(depth + 1)
                if depth == 0 and key == b"info":
                    self.info_span = (start, self.i)
            self.i += 1
            return obj
        if c.isdigit():
            colon = self.d.index(b":", self.i)
            start = colon + 1
            self.i = start + int(self.d[self.i:colon])
            if self.i > len(self.d):
                raise ValueError("truncated torrent file")
            return self.d[start:self.i]
        raise ValueError(f"invalid torrent data at byte {self.i}")


def _text(b) -> str:
    return b.decode("utf-8", "replace") if isinstance(b, bytes) else str(b)


def parse_torrent(data: bytes) -> dict:
    dec = _Bdecoder(data)
    try:
        meta = dec.parse()
    except (ValueError, IndexError) as e:
        raise ValueError(f"not a valid .torrent file ({e})") from None
    if not isinstance(meta, dict) or dec.info_span is None:
        raise ValueError("not a valid .torrent file (no info section)")
    info = meta[b"info"]
    if b"pieces" not in info:
        raise ValueError("BitTorrent v2-only torrents aren't supported by the downloader")
    name = _text(info.get(b"name.utf-8", info.get(b"name", b"unnamed")))
    files: list[tuple[str, int]] = []
    if b"files" in info:
        for f in info[b"files"]:
            if b"p" in f.get(b"attr", b"") or b"l" in f.get(b"attr", b""):
                continue  # BEP 47 padding file or symlink: no data of its own
            parts = f.get(b"path.utf-8", f.get(b"path", []))
            files.append(("/".join([name] + [_text(p) for p in parts]), int(f[b"length"])))
    else:
        files.append((name, int(info[b"length"])))
    start, end = dec.info_span
    return {
        "name": name,
        "infohash": hashlib.sha1(data[start:end]).hexdigest(),
        "files": files,
        "total": sum(s for _, s in files),
        "private": bool(info.get(b"private")),
    }


# ---------------------------------------------------------------- helpers


def human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n} B"


def paint(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if sys.stdout.isatty() else text


VERDICT_COLOR = {"OK": "32", "CLEAN": "1;32", "WARNING": "33", "SUSPICIOUS": "1;31", "REJECTED": "1;31", "INFECTED": "1;41;97"}
LEVEL_ICON = {INFECTED: ("✖", "1;31"), DANGER: ("✖", "31"), WARN: ("⚠", "33"), INFO: ("·", "2")}


def print_findings(findings: list[dict], limit: int = 40) -> None:
    if not findings:
        print("  no problems found")
        return
    ordered = sorted(findings, key=lambda f: -f["level"])
    for f in ordered[:limit]:
        icon, code = LEVEL_ICON[f["level"]]
        where = f"{f['path']}: " if f["path"] else ""
        print(f"  {paint(icon, code)} {where}{f['msg']}")
    if len(ordered) > limit:
        print(f"  … and {len(ordered) - limit} more (see `safetorrent report`)")


def max_level(findings: list[dict]) -> int:
    return max((f["level"] for f in findings), default=INFO)


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    kw.setdefault("stdin", subprocess.DEVNULL)
    return subprocess.run(cmd, **kw)


def as_torrent_user(cmd: list[str]) -> list[str]:
    return ["runuser", "-u", TORRENT_USER, "--"] + cmd


class StError(Exception):
    """A problem to show the user; main() prints it as text or JSON."""


def die(msg: str):
    raise StError(msg)


def emit(obj) -> None:
    print(json.dumps(obj))


def load_config() -> dict:
    cfg = dict(DEFAULTS)
    path = CONFIG_DIR / "config"
    if path.exists():
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            cfg[key.strip()] = value.split(" #", 1)[0].strip().strip("'\"")
    return cfg


def inbox() -> Path:
    user = os.environ.get("SUDO_USER")
    return Path(pwd.getpwnam(user).pw_dir if user else "/root") / "st-in"


def item_dir(item_id: str) -> Path:
    if not re.fullmatch(r"[0-9a-f]{6,40}", item_id):
        die(f"not a valid download id: {item_id}")
    matches = sorted(QUARANTINE.glob(item_id + "*"))
    if not matches:
        die(f"no download with id {item_id} (see `safetorrent list`)")
    if len(matches) > 1:
        die(f"id {item_id} is ambiguous")
    return matches[0]


def load_meta(d: Path) -> dict:
    return json.loads((d / "meta.json").read_text())


def save_meta(d: Path, meta: dict) -> None:
    tmp = d / "meta.json.tmp"
    tmp.write_text(json.dumps(meta, indent=2))
    tmp.replace(d / "meta.json")


def walk_files(root: Path) -> list[tuple[str, int]]:
    out = []
    for dirpath, _dirs, names in os.walk(root):
        for n in names:
            p = Path(dirpath) / n
            if p.is_symlink() or not p.is_file():
                continue
            out.append((str(p.relative_to(root)), p.stat().st_size))
    return sorted(out)


def read_head(path: Path, n: int = 1024) -> bytes:
    with open(path, "rb") as fh:
        return fh.read(n)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------- network isolation


def iptables(binary: str, *args: str, check: bool = True) -> int:
    return run([binary, "-w", *args], check=check, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode


def apply_firewall(use_vpn: bool) -> None:
    """Restrict what the `torrent` user (aria2, 7z, clamscan) may reach.

    Always: no access to the Mac (host.lima.internal) or any private LAN range.
    With the VPN enabled: all traffic must leave through wg0 (kill switch).
    """
    private = {
        "iptables": "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,100.64.0.0/10",
        "ip6tables": "fc00::/7,fe80::/10",
    }
    for binary, nets in private.items():
        if iptables(binary, "-N", "ST_OUT", check=False) != 0:
            iptables(binary, "-F", "ST_OUT")
        if iptables(binary, "-C", "OUTPUT", "-m", "owner", "--uid-owner", TORRENT_USER, "-j", "ST_OUT", check=False) != 0:
            iptables(binary, "-I", "OUTPUT", "1", "-m", "owner", "--uid-owner", TORRENT_USER, "-j", "ST_OUT")
        iptables(binary, "-A", "ST_OUT", "-o", "lo", "-j", "RETURN")
        iptables(binary, "-A", "ST_OUT", "-d", nets, "-j", "REJECT")
        if use_vpn:
            iptables(binary, "-A", "ST_OUT", "-o", "wg0", "-j", "RETURN")
            # The kernel sends the encrypted tunnel packets on behalf of the
            # user whose traffic they carry; wg-quick tags them with this mark.
            iptables(binary, "-A", "ST_OUT", "-m", "mark", "--mark", WG_FWMARK, "-j", "RETURN")
            iptables(binary, "-A", "ST_OUT", "-j", "REJECT")


def public_ip_as_torrent_user() -> str | None:
    res = run(as_torrent_user(["curl", "-4", "-s", "--max-time", "15", "https://api.ipify.org"]),
              capture_output=True, text=True)
    ip = res.stdout.strip()
    return ip if res.returncode == 0 and re.fullmatch(r"[\d.]+", ip) else None


VPN_EXPIRED_HELP = ("Proton isn't accepting this WireGuard config (it has probably expired). "
                    "Download a new one from account.protonvpn.com > WireGuard (GNU/Linux, a P2P server) "
                    "and import it.")
VPN_STATE = STATE_DIR / "vpn-state.json"


def wg_up() -> bool:
    return run(["ip", "link", "show", "wg0"], capture_output=True).returncode == 0


def handshake_age() -> float | None:
    res = run(["wg", "show", "wg0", "latest-handshakes"], capture_output=True, text=True)
    stamps = [int(line.split()[1]) for line in res.stdout.splitlines() if len(line.split()) == 2]
    if not stamps or max(stamps) == 0:
        return None
    return time.time() - max(stamps)


def vpn_up() -> str:
    conf = Path("/etc/wireguard/wg0.conf")
    if not conf.exists():
        die("The VPN is switched on but no WireGuard config has been imported yet.")
    if not wg_up():
        res = run(["wg-quick", "up", "wg0"], capture_output=True, text=True)
        if res.returncode != 0:
            die("The VPN config couldn't be loaded: " + (res.stderr.strip().splitlines() or ["unknown error"])[-1])
    ip = public_ip_as_torrent_user()
    if not ip:
        # One retry from scratch before blaming the config.
        vpn_down()
        run(["wg-quick", "up", "wg0"], capture_output=True)
        ip = public_ip_as_torrent_user()
    if not ip:
        die(VPN_EXPIRED_HELP)
    VPN_STATE.write_text(json.dumps({"ip": ip, "at": time.time()}))
    return ip


def vpn_healthy() -> str | None:
    """Cheap check (recent handshake) with a full reconnect as fallback. Returns exit IP."""
    if wg_up():
        age = handshake_age()
        if age is not None and age < 200 and VPN_STATE.exists():
            return json.loads(VPN_STATE.read_text())["ip"]
    try:
        return vpn_up()
    except StError:
        return None


def vpn_down() -> None:
    if run(["ip", "link", "show", "wg0"], capture_output=True).returncode != 0:
        return
    if run(["wg-quick", "down", "wg0"], capture_output=True).returncode != 0:
        # Config already gone: remove the interface and its DNS entry directly.
        run(["ip", "link", "delete", "wg0"], capture_output=True)
        run(["resolvconf", "-d", "wg0", "-f"], capture_output=True)


def sync_inbox() -> None:
    """Move config/VPN files the host just copied in to root-only locations."""
    box = inbox()
    wg_conf = Path("/etc/wireguard/wg0.conf")
    new_wg = box / "wg0.conf"
    if (box / "no-vpn-config").exists():
        vpn_down()  # needs the old config, so tear down before deleting it
        wg_conf.unlink(missing_ok=True)
        (box / "no-vpn-config").unlink()
    elif new_wg.exists() and (not wg_conf.exists() or wg_conf.read_bytes() != new_wg.read_bytes()):
        vpn_down()  # VPN config changed: restart with the new one
    for name, dest in (("config", CONFIG_DIR / "config"), ("wg0.conf", wg_conf)):
        src = box / name
        if src.exists():
            dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            shutil.copyfile(src, dest)
            os.chmod(dest, 0o600)
            src.unlink()


def vpn_enabled(cfg: dict) -> bool:
    return cfg["USE_VPN"].lower() in ("yes", "true", "1")


def prepare(cfg: dict) -> str | None:
    """Make networking safe before anything touches a torrent. Returns VPN exit IP."""
    sync_inbox()
    cfg.update(load_config())
    ensure_firewall(vpn_enabled(cfg))
    if vpn_enabled(cfg):
        return vpn_up()
    vpn_down()
    return None


# ---------------------------------------------------------------- health gate

VT_STATE = STATE_DIR / "vt-state.json"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def firewall_ok(use_vpn: bool) -> bool:
    for binary, private_rules in (("iptables", 5), ("ip6tables", 2)):
        rules = run([binary, "-w", "-S", "ST_OUT"], capture_output=True, text=True).stdout.splitlines()
        jump = run([binary, "-w", "-C", "OUTPUT", "-m", "owner", "--uid-owner", TORRENT_USER, "-j", "ST_OUT"],
                   capture_output=True).returncode == 0
        blocks_lan = sum(1 for r in rules if r.startswith("-A ST_OUT -d ") and "-j REJECT" in r) == private_rules
        kill_switch = bool(rules) and rules[-1].startswith("-A ST_OUT -j REJECT")
        if not (jump and blocks_lan and kill_switch == use_vpn):
            return False
    return True


def ensure_firewall(use_vpn: bool) -> None:
    # Only rebuild when wrong: rebuilding briefly empties the chain.
    if not firewall_ok(use_vpn):
        apply_firewall(use_vpn)


def vt_key_ok(key: str) -> bool | None:
    """Validate the VirusTotal key at most once a day (uses one lookup)."""
    fingerprint = hashlib.sha256(key.encode()).hexdigest()
    if VT_STATE.exists():
        state = json.loads(VT_STATE.read_text())
        if state["key"] == fingerprint and time.time() - state["at"] < 86400:
            return state["ok"]
    status, _ = vt_lookup(EICAR_SHA256, key)
    if status in ("error", "ratelimit"):
        return None
    ok = status in ("found", "unknown")
    VT_STATE.write_text(json.dumps({"key": fingerprint, "ok": ok, "at": time.time()}))
    return ok


def virusdb_check() -> tuple:
    daily = sorted(CLAMAV_DB.glob("daily.c[lv]d"))
    if not daily:
        return "block", "Virus definitions missing", "ClamAV has nothing to scan with", "update"
    age = (time.time() - daily[0].stat().st_mtime) / 86400
    if age > 7:
        return ("block", "Virus definitions are out of date",
                f"Last updated {age:.0f} days ago; scans would miss new malware", "update")
    if age > 3:
        return "warn", "Virus definitions are getting old", f"Last updated {age:.0f} days ago", "update"
    return "ok", "Virus definitions are current", "Updated today" if age < 1 else f"Updated {age:.0f} day(s) ago"


def disk_check(free: int) -> tuple:
    if free < 5 * 1024**3:
        return "block", "Quarantine is almost full", f"Only {human(free)} free; delete old downloads", "purge"
    if free < 20 * 1024**3:
        return "warn", "Quarantine is filling up", f"{human(free)} free"
    return "ok", "Space for downloads", f"{human(free)} free"


def check_health(cfg: dict) -> dict:
    """Every check a download depends on. 'block' results stop all downloads."""
    sync_inbox()
    cfg.update(load_config())
    checks: list[dict] = []

    def add(key: str, state: str, title: str, detail: str, fix: str | None = None):
        checks.append({"id": key, "state": state, "title": title, "detail": detail, "fix": fix})

    shared = [ln.split()[1] for ln in Path("/proc/mounts").read_text().splitlines()
              if ln.split()[2] in ("virtiofs", "9p", "fuse.sshfs")]
    if shared:
        add("isolation", "block", "Mac folders are shared into the VM",
            "Downloads could reach your files: " + ", ".join(shared), "rebuild")
    else:
        add("isolation", "ok", "VM is sealed off", "No Mac folders are shared with it")

    use_vpn = vpn_enabled(cfg)
    ensure_firewall(use_vpn)
    if firewall_ok(use_vpn):
        add("firewall", "ok", "Firewall is up",
            "The downloader can't reach your Mac or home network" + (" and only uses the VPN" if use_vpn else ""))
    else:
        add("firewall", "block", "Firewall rules are missing", "Couldn't lock down the downloader's network access")

    if use_vpn:
        if not Path("/etc/wireguard/wg0.conf").exists():
            add("vpn", "block", "No VPN config imported", "Import a WireGuard file from Proton", "import_vpn")
        else:
            ip = vpn_healthy()
            if ip:
                add("vpn", "ok", "Proton VPN connected", f"Peers see {ip}, not your home IP")
            else:
                add("vpn", "block", "Proton VPN isn't passing traffic", VPN_EXPIRED_HELP, "import_vpn")
    else:
        vpn_down()
        add("vpn", "warn", "VPN is off", "Other people in the torrent can see your real IP address", "enable_vpn")

    add("virusdb", *virusdb_check())

    key = cfg["VT_API_KEY"]
    if not key:
        add("virustotal", "warn", "VirusTotal isn't set up", "Only ClamAV will check programs and archives", "settings")
    else:
        ok = vt_key_ok(key)
        if ok is False:
            add("virustotal", "warn", "VirusTotal rejected your API key", "Check the key in settings", "settings")
        elif ok is None:
            add("virustotal", "warn", "VirusTotal is unreachable", "Scans will fall back to ClamAV only")
        else:
            add("virustotal", "ok", "VirusTotal key works", "Programs and archives get a second opinion")

    add("disk", *disk_check(shutil.disk_usage(QUARANTINE).free))

    blocked = [c for c in checks if c["state"] == "block"]
    return {"checks": checks, "blocked": bool(blocked), "at": now()}


def enforce(cfg: dict) -> dict:
    health = check_health(cfg)
    if health["blocked"]:
        problems = "; ".join(f"{c['title']} ({c['detail']})" for c in health["checks"] if c["state"] == "block")
        die("Downloads are blocked until this is fixed: " + problems)
    return health


# ---------------------------------------------------------------- pipeline steps


def obtain_torrent(src: Path, cfg: dict) -> bytes:
    if src.suffix == ".torrent":
        return src.read_bytes()
    magnet = src.read_text().strip()
    if not magnet.startswith("magnet:?") or "xt=urn:btih:" not in magnet.lower():
        die("that doesn't look like a BitTorrent magnet link (needs xt=urn:btih:)")
    tmp = STATE_DIR / "metadata"
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir()
    shutil.chown(tmp, TORRENT_USER, TORRENT_USER)
    print("Fetching the torrent's file list from peers (nothing is downloaded yet)…", flush=True)
    timeout = cfg["METADATA_TIMEOUT_SECONDS"]
    run(as_torrent_user([
        "timeout", timeout, "aria2c", "--bt-metadata-only=true", "--bt-save-metadata=true",
        f"--dir={tmp}", "--enable-dht=true", f"--dht-file-path={STATE_DIR / 'dht.dat'}",
        f"--dht-entry-point={DHT_BOOTSTRAP}", "--bt-enable-lpd=false",
        "--console-log-level=error", "--summary-interval=0", "--quiet=true", magnet,
    ]))
    found = sorted(tmp.glob("*.torrent"))
    if not found:
        die(f"couldn't get the torrent's file list within {timeout}s. The torrent may be dead "
            "(no peers); try again later or use a .torrent file.")
    return found[0].read_bytes()


def set_phase(d: Path, meta: dict, phase: str) -> None:
    meta["phase"] = phase
    save_meta(d, meta)


def download(d: Path, meta: dict, cfg: dict, background: bool = False) -> bool:
    """Run aria2c. In the background, log progress to a file for the GUI.

    A watchdog checks the VPN every 15s; if the tunnel dies and can't be
    revived, the download is stopped (the kill switch already blocks traffic).
    """
    files_dir = d / "files"
    resuming = bool(walk_files(files_dir))
    if not background:
        print(paint(f"\nDownloading into the VM's quarantine ({human(meta['total'])})…", "1"), flush=True)
    meta.update(status="downloading", phase="Connecting to peers")
    meta.pop("error", None)
    save_meta(d, meta)
    log = d / "aria2.log"
    cmd = as_torrent_user([
        "aria2c", f"--dir={files_dir}", f"--seed-time={cfg['SEED_MINUTES']}",
        f"--bt-stop-timeout={int(cfg['STALL_TIMEOUT_MINUTES']) * 60}",
        "--file-allocation=none", f"--check-integrity={str(resuming).lower()}", "--bt-enable-lpd=false",
        "--enable-dht=true", f"--dht-file-path={STATE_DIR / 'dht.dat'}",
        f"--dht-entry-point={DHT_BOOTSTRAP}", "--auto-file-renaming=false",
        "--allow-overwrite=true", "--console-log-level=warn",
        f"--summary-interval={2 if background else 0}",
        f"--show-console-readout={'false' if background else 'true'}",
        str(d / "source.torrent"),
    ])
    out = open(log, "w") if background else None
    proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT if out else None,
                            start_new_session=background)
    ok, reason = False, None
    try:
        while True:
            try:
                ok = proc.wait(timeout=15) == 0
                break
            except subprocess.TimeoutExpired:
                if vpn_enabled(cfg) and not vpn_healthy():
                    reason = "The VPN stopped passing traffic, so the download was stopped. " + VPN_EXPIRED_HELP
                    break
    except KeyboardInterrupt:
        reason = "Stopped."
    if proc.poll() is None:
        stop = (lambda sig: os.killpg(proc.pid, sig)) if background else proc.send_signal
        stop(signal.SIGTERM)  # aria2c saves its resume state on SIGTERM
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            stop(signal.SIGKILL)
    if out:
        out.close()
    run(["chmod", "-R", "a+rX", str(files_dir)])
    if ok:
        meta.update(status="downloaded", phase="")
    else:
        meta.update(status="vpn-failed" if reason and "VPN" in reason else "incomplete",
                    phase="", error=reason or "The download stopped before finishing (no peers, or stalled).")
    save_meta(d, meta)
    if not ok and not background:
        print(paint("\n" + meta["error"], "33"))
        print(f"Resume it with:  safetorrent resume {meta['id']}")
    return ok


PROGRESS_RE = re.compile(r"\[#\w+ ([\d.]+\w+)/([\d.]+\w+)\((\d+)%\)([^\]]*)\]")
SEEDING_RE = re.compile(r"\[#\w+ SEED\(([\d.]+)\)([^\]]*)\]")


def download_progress(d: Path) -> dict | None:
    log = d / "aria2.log"
    if not log.exists():
        return None
    with open(log, "rb") as fh:
        fh.seek(max(0, log.stat().st_size - 8192))
        tail = fh.read().decode("utf-8", "replace")
    line = (re.findall(r"\[#\w+ [^\]]*\]", tail) or [""])[-1]
    field = lambda name: (re.search(name + r":([\w.]+)", line) or [None, None])[1]
    seeding = SEEDING_RE.match(line)
    if seeding:  # finished; aria2 prints only the share ratio while seeding
        return {"seeding": True, "ratio": seeding.group(1), "percent": 100, "peers": field("CN")}
    m = PROGRESS_RE.match(line)
    if not m:
        return None
    done, total, pct, _rest = m.groups()
    return {"done": done, "total": total, "percent": int(pct), "peers": field("CN"),
            "speed": field("DL"), "eta": field("ETA")}


def extract_archives(d: Path, files: list[tuple[str, int]], root: Path, cfg: dict, category: str,
                     depth: int = 0) -> list[dict]:
    """Extract archives (as the torrent user) so their contents get checked too."""
    out: list[dict] = []
    sevenz = shutil.which("7z") or shutil.which("7zz")
    extracted_root = d / "extracted"
    max_bytes = int(cfg["MAX_EXTRACT_GB"]) * 1024**3
    for rel, size in files:
        name = rel.lower()
        if kind_of(ext_of(rel)) != "archive":
            continue
        m = re.search(r"\.part(\d+)\.rar$", name)
        if (m and int(m.group(1)) != 1) or re.search(r"\.(r\d\d|z\d\d)$", name) or (
                re.search(r"\.\d{3}$", name) and not name.endswith(".001")):
            continue  # later volume of a multi-part archive
        src = root / rel
        dest = extracted_root / (rel + ".d") if depth == 0 else src.parent / (src.name + ".d")
        listing = run(as_torrent_user([sevenz, "l", "-slt", NOPASS, "--", str(src)]),
                      capture_output=True, text=True, errors="replace")
        text = listing.stdout + listing.stderr
        if re.search(r"Wrong password|Encrypted = \+|Can not open encrypted", text):
            out.append(finding(DANGER, rel, "password-protected archive: can't be scanned (a common way to smuggle malware)"))
            continue
        unpacked = sum(int(n) for n in re.findall(r"^Size = (\d+)", listing.stdout, re.M))
        free = shutil.disk_usage(QUARANTINE).free
        if unpacked > min(max_bytes, free * 0.9) or (unpacked > 1024**3 and size and unpacked / size > 1000):
            out.append(finding(DANGER, rel, f"archive would unpack to {human(unpacked)}: too big to scan safely (possible zip bomb)"))
            continue
        run(["install", "-d", "-o", TORRENT_USER, "-g", TORRENT_USER, str(dest)])
        res = run(as_torrent_user(["timeout", "3600", sevenz, "x", "-y", NOPASS, f"-o{dest}", "--", str(src)]),
                  capture_output=True, text=True, errors="replace")
        if res.returncode != 0:
            if re.search(r"Wrong password|encrypted", res.stdout + res.stderr, re.I):
                out.append(finding(DANGER, rel, "password-protected archive: can't be scanned"))
            else:
                out.append(finding(WARN, rel, "archive couldn't be fully extracted (damaged or unsupported); only partly scanned"))
        inner = walk_files(dest)
        inner_rel = [(str(Path(rel + ".d") / p), s) for p, s in inner]
        out += check_names(inner_rel, category, inner=True)
        for (p, _s), (prel, _) in zip(inner, inner_rel):
            out += sniff(prel, read_head(dest / p))
        if depth < 2:
            nested = extract_archives(d, inner, dest, cfg, category, depth + 1)
            for f in nested:
                f["path"] = str(Path(rel + ".d") / f["path"])
            out += nested
    return out


def clamav_scan(d: Path) -> list[dict]:
    daily = sorted(CLAMAV_DB.glob("daily.c[lv]d"))
    if not daily:
        die("the virus database hasn't downloaded yet; run `safetorrent update` and try again")
    out: list[dict] = []
    age_days = (time.time() - daily[0].stat().st_mtime) / 86400
    if age_days > 3:
        out.append(finding(WARN, "", f"virus definitions are {age_days:.0f} days old; run `safetorrent update`"))
    if sys.stdout.isatty():
        print("Scanning with ClamAV (loading signatures takes ~30s)…", flush=True)
    targets = [str(p) for p in (d / "files", d / "extracted") if p.exists()]
    res = run(as_torrent_user([
        "clamscan", "-r", "-i", "--no-summary", "--stdout", "--scan-archive=yes",
        "--max-filesize=500M", "--max-scansize=2000M", "--alert-encrypted=no", *targets,
    ]), capture_output=True, text=True, errors="replace")
    for line in res.stdout.splitlines():
        m = re.match(r"^(.*): (.+) FOUND$", line)
        if m:
            rel = os.path.relpath(m.group(1), d)
            rel = rel.split("/", 1)[1] if "/" in rel else rel  # drop files/ or extracted/
            out.append(finding(INFECTED, rel, f"ClamAV detected {m.group(2)}"))
    if res.returncode == 2 and not out:
        out.append(finding(WARN, "", "ClamAV reported an error; scan may be incomplete: "
                           + (res.stderr.strip().splitlines() or ["unknown"])[-1]))
    return out


def vt_lookup(sha: str, key: str) -> tuple[str, dict | None]:
    req = urllib.request.Request(f"https://www.virustotal.com/api/v3/files/{sha}", headers={"x-apikey": key})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            stats = json.load(r)["data"]["attributes"]["last_analysis_stats"]
            return "found", stats
    except urllib.error.HTTPError as e:
        return {404: "unknown", 401: "badkey", 403: "badkey", 429: "ratelimit"}.get(e.code, "error"), None
    except (urllib.error.URLError, TimeoutError, KeyError, ValueError):
        return "error", None


def virustotal(d: Path, cfg: dict, category: str, on_progress=None) -> list[dict]:
    key = cfg["VT_API_KEY"]
    if not key:
        return [finding(INFO, "", "VirusTotal check skipped (no VT_API_KEY in ~/.config/safetorrent/config)")]
    rank = {"exec": 0, "macro": 1, "archive": 2, "disk": 3, "doc": 4}
    candidates = []
    for sub in ("files", "extracted"):
        root = d / sub
        if not root.exists():
            continue
        for rel, size in walk_files(root):
            kind = kind_of(ext_of(rel))
            head = read_head(root / rel, 16)
            if any(head.startswith(m) for m, _ in EXEC_MAGIC):
                kind = "exec"
            if kind in rank and size > 0:
                candidates.append((rank[kind], rel, root / rel, kind))
    if not candidates:
        return []
    candidates.sort()
    limit = int(cfg["VT_MAX_LOOKUPS"])
    out: list[dict] = []
    if len(candidates) > limit:
        out.append(finding(WARN if category == "software" else INFO, "",
                           f"only the {limit} riskiest of {len(candidates)} files were checked on VirusTotal (VT_MAX_LOOKUPS)"))
    seen: dict[str, tuple[str, dict | None]] = {}
    clean = unknown_other = 0
    todo = candidates[:limit]
    for n, (_r, rel, path, kind) in enumerate(todo, 1):
        if on_progress:
            on_progress(f"VirusTotal lookup {n} of {len(todo)}")
        else:
            print(f"\rVirusTotal lookup {n}/{len(todo)}…", end="", flush=True)
        sha = sha256_file(path)
        if sha not in seen:
            if seen:
                time.sleep(15.5)  # free API tier: 4 lookups per minute
            status, stats = vt_lookup(sha, key)
            if status == "ratelimit":
                time.sleep(61)
                status, stats = vt_lookup(sha, key)
            seen[sha] = (status, stats)
        status, stats = seen[sha]
        if status == "badkey":
            print()
            return out + [finding(WARN, "", "VirusTotal rejected the API key; check VT_API_KEY")]
        if status in ("error", "ratelimit"):
            out.append(finding(WARN, rel, "VirusTotal lookup failed (network or rate limit)"))
        elif status == "unknown":
            if kind == "exec":
                out.append(finding(WARN, rel, "program never seen by VirusTotal: new or rare, so no second opinion"))
            else:
                unknown_other += 1
        else:
            bad, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
            engines = sum(stats.values())
            if bad >= 3:
                out.append(finding(INFECTED, rel, f"flagged as malicious by {bad}/{engines} antivirus engines on VirusTotal"))
            elif bad >= 1:
                out.append(finding(DANGER, rel, f"flagged by {bad}/{engines} engines on VirusTotal (could be a false positive; be careful)"))
            elif sus >= 2:
                out.append(finding(WARN, rel, f"{sus} engines on VirusTotal call it suspicious"))
            else:
                clean += 1
    if not on_progress:
        print("\r" + " " * 40 + "\r", end="")
    if clean:
        out.append(finding(INFO, "", f"{clean} file(s) known to VirusTotal with zero detections"))
    if unknown_other:
        out.append(finding(INFO, "", f"{unknown_other} archive/document file(s) not yet seen by VirusTotal"))
    return out


def verify_checksum(d: Path, expected: str) -> list[dict]:
    expected = expected.lower().strip()
    files = sorted(walk_files(d / "files"), key=lambda f: -f[1])
    for rel, _ in files:
        if sha256_file(d / "files" / rel) == expected:
            return [finding(INFO, rel, "matches the publisher's SHA-256 checksum ✓")]
    return [finding(DANGER, "", "no file matches the SHA-256 checksum you provided; the download may be tampered with")]




def scan(d: Path, meta: dict, cfg: dict, quiet: bool = False) -> int:
    if not quiet:
        print(paint("\nScanning…", "1"), flush=True)
    meta["status"] = "scanning"
    shutil.rmtree(d / "extracted", ignore_errors=True)
    run(["install", "-d", "-o", TORRENT_USER, "-g", TORRENT_USER, str(d / "extracted")])
    files = walk_files(d / "files")
    category = meta["category"]
    set_phase(d, meta, "Checking what each file really is")
    findings = check_names(files, category, meta["name"])
    for rel, _ in files:
        findings += sniff(rel, read_head(d / "files" / rel))
    set_phase(d, meta, "Unpacking archives")
    findings += extract_archives(d, files, d / "files", cfg, category)
    set_phase(d, meta, "Virus scan (ClamAV)")
    findings += clamav_scan(d)
    set_phase(d, meta, "VirusTotal lookups")
    findings += virustotal(d, cfg, category, (lambda msg: set_phase(d, meta, msg)) if quiet else None)
    if meta.get("sha256"):
        set_phase(d, meta, "Checking the publisher's checksum")
        findings += verify_checksum(d, meta["sha256"])
    level = max_level(findings)
    meta.update(status="scanned", phase="", scan={"verdict": SCAN_VERDICT[level], "findings": findings, "at": now()})
    save_meta(d, meta)
    if not quiet:
        print_report(meta)
    return level


def print_report(meta: dict) -> None:
    print(f"\n{paint(meta['name'], '1')}  [{meta['id']}]")
    print(f"  {human(meta['total'])}, {meta['file_count']} file(s), category: {meta['category']}, status: {meta['status']}")
    if meta.get("released_to"):
        print(f"  released to: {meta['released_to']}")
    if meta.get("error"):
        print(paint(f"  {meta['error']}", "33"))
    scan_ = meta.get("scan")
    if scan_:
        v = scan_["verdict"]
        print(f"\nScan result: {paint(v, VERDICT_COLOR[v])}")
        print_findings(scan_["findings"])
    else:
        v = meta["precheck"]["verdict"]
        print(f"\nPre-download check: {paint(v, VERDICT_COLOR[v])}")
        print_findings(meta["precheck"]["findings"])


def precheck(src: Path, cfg: dict, category: str | None, sha256: str | None,
             auto_release: bool) -> tuple[dict, dict, bool]:
    """Fetch the file list and apply name rules. Returns (meta, torrent info, already existed)."""
    if not src.exists():
        die(f"missing {src}")
    try:
        data = obtain_torrent(src, cfg)
    finally:
        src.unlink(missing_ok=True)
    info = parse_torrent(data)
    item_id = info["infohash"][:10]
    d = QUARANTINE / item_id
    (QUARANTINE / ".last").write_text(item_id)
    if (d / "meta.json").exists():
        meta = load_meta(d)
        if meta["status"] not in ("prechecked", "rejected", "skipped"):
            return meta, info, True
    if sha256 and not re.fullmatch(r"[0-9a-fA-F]{64}", sha256.strip()):
        die("that checksum isn't a SHA-256 (64 hex characters)")
    auto_category = category is None
    category = category or detect_category(info["files"])
    findings = check_names(info["files"], category, info["name"])
    level = max_level(findings)
    d.mkdir(exist_ok=True)
    shutil.chown(d, TORRENT_USER, TORRENT_USER)
    (d / "source.torrent").write_bytes(data)
    run(["install", "-d", "-o", TORRENT_USER, "-g", TORRENT_USER, str(d / "files")])
    biggest = sorted(info["files"], key=lambda f: -f[1])
    meta = {
        "id": item_id, "name": info["name"], "infohash": info["infohash"], "total": info["total"],
        "file_count": len(info["files"]), "files": [{"path": p, "size": sz} for p, sz in biggest[:200]],
        "category": category, "category_auto": auto_category,
        "added": now(), "sha256": sha256.strip().lower() if sha256 else None, "auto_release": auto_release,
        "status": "rejected" if level >= DANGER else "prechecked", "phase": "",
        "precheck": {"verdict": PRE_VERDICT[level], "findings": findings},
    }
    save_meta(d, meta)
    return meta, info, False


def check_space(meta: dict) -> None:
    have = sum(sz for _, sz in walk_files(QUARANTINE / meta["id"] / "files"))
    need = (meta["total"] - have) * 1.05 + 1024**3
    free = shutil.disk_usage(QUARANTINE).free
    if need > free:
        die(f"Not enough space in the VM ({human(free)} free, need {human(need)}). "
            "Delete old downloads, or grow the disk (see README).")


def unit_name(item_id: str) -> str:
    return f"st-{item_id}"


def active_units() -> set[str]:
    res = run(["systemctl", "list-units", "--type=service", "--state=active,activating", "--plain",
               "--no-legend", "st-*"], capture_output=True, text=True)
    return {line.split()[0][3:].removesuffix(".service") for line in res.stdout.splitlines() if line.strip()}


def item_view(d: Path, running: set[str]) -> dict:
    meta = load_meta(d)
    busy = meta["status"] in ("queued", "downloading", "scanning")
    just_queued = meta["status"] == "queued" and time.time() - meta.get("queued_at", 0) < 15
    if busy and meta["id"] not in running and not just_queued:
        # The background job died (e.g. the VM restarted): make the state honest.
        meta.update(status="downloaded" if meta["status"] == "scanning" else "incomplete", phase="",
                    error=meta.get("error") or "Interrupted (the VM may have restarted). Resume it to continue.")
        save_meta(d, meta)
    meta["running"] = meta["id"] in running
    if meta["status"] == "downloading":
        meta["progress"] = download_progress(d)
    return meta


# ---------------------------------------------------------------- commands


def cmd_get(args, cfg) -> int:
    health = enforce(cfg)
    vpn = next(c for c in health["checks"] if c["id"] == "vpn")
    print(("✓ " if vpn["state"] == "ok" else "⚠ ") + vpn["title"] + ": " + vpn["detail"])
    meta, info, existed = precheck(inbox() / args.source, cfg, args.category, args.sha256, True)
    d = QUARANTINE / meta["id"]
    if existed:
        print(f"Already have this torrent (id {meta['id']}).")
        print_report(meta)
        if meta["status"] in ("incomplete", "vpn-failed", "downloaded"):
            print(f"Resume it with: safetorrent resume {meta['id']}")
        return 0

    print(f"\n{paint(info['name'], '1')}  [{meta['id']}]")
    auto = "" if args.category else " (auto-detected; override with --category)"
    print(f"  {human(info['total'])} in {len(info['files'])} file(s), category: {meta['category']}{auto}")
    for f in meta["files"][:12]:
        print(f"    {human(f['size']):>9}  {f['path']}")
    if len(info["files"]) > 12:
        print(f"    … and {len(info['files']) - 12} more")
    v = meta["precheck"]["verdict"]
    level = max_level(meta["precheck"]["findings"])
    print(f"\nPre-download check: {paint(v, VERDICT_COLOR[v])}")
    print_findings(meta["precheck"]["findings"])

    if level >= DANGER and not args.force:
        print("\nNothing was downloaded. If you're sure, re-run with --force "
              "(it will still be scanned and won't be released unless you force that too).")
        return 0
    if level == WARN and not args.yes:
        if not sys.stdin.isatty() or input("\nDownload it into quarantine anyway? [y/N] ").strip().lower() != "y":
            meta["status"] = "skipped"
            save_meta(d, meta)
            print("Skipped.")
            return 0
    meta["forced"] = level >= DANGER
    check_space(meta)
    if download(d, meta, cfg):
        scan(d, meta, cfg)
    return 0


def cmd_add(args, cfg) -> int:
    enforce(cfg)
    meta, _info, existed = precheck(inbox() / args.source, cfg, args.category, args.sha256, not args.no_auto_release)
    meta["existed"] = existed
    emit(meta)
    return 0


def cmd_start(args, cfg) -> int:
    d = item_dir(args.id)
    meta = load_meta(d)
    if args.id in active_units() or meta["id"] in active_units():
        die("That download is already running.")
    if args.scan_only:
        sync_inbox()
        cfg.update(load_config())
        if meta["status"] not in ("downloaded", "scanned", "released"):
            die("It hasn't finished downloading yet, so there's nothing complete to scan.")
    else:
        enforce(cfg)
        if meta["status"] in ("scanned", "released"):
            die("It's already downloaded and scanned.")
        if meta["precheck"]["verdict"] == "REJECTED":
            if not args.force:
                die("The pre-check rejected this torrent. Force it only if you're sure.")
            meta["forced"] = True
        check_space(meta)
    meta.update(status="queued", phase="Starting", queued_at=time.time())
    meta.pop("error", None)
    save_meta(d, meta)
    cmd = ["systemd-run", f"--unit={unit_name(meta['id'])}", "--collect", "--quiet",
           "/usr/bin/python3", "/opt/safetorrent/st-guest.py", "run", meta["id"]]
    res = run(cmd + (["--scan-only"] if args.scan_only else []), capture_output=True, text=True)
    if res.returncode != 0:
        meta.update(status="incomplete", phase="", error="Couldn't start: " + res.stderr.strip())
        save_meta(d, meta)
        die(meta["error"])
    emit({"ok": True}) if args.json else print("Started in the background.")
    return 0


def cmd_run(args, cfg) -> int:
    """Background job (systemd): download with watchdog, then scan."""
    d = item_dir(args.id)
    meta = load_meta(d)
    try:
        if not args.scan_only:
            enforce(cfg)
            if not download(d, meta, cfg, background=True):
                return 0
        scan(d, meta, cfg, quiet=True)
    except StError as e:
        meta.update(status="blocked" if not args.scan_only else "downloaded", phase="", error=str(e))
        save_meta(d, meta)
    except Exception as e:  # keep the item in an honest state for the GUI
        meta.update(status="incomplete" if meta["status"] != "scanning" else "downloaded", phase="",
                    error=f"Unexpected error: {e}")
        save_meta(d, meta)
        raise
    return 0


def cmd_stop(args, cfg) -> int:
    d = item_dir(args.id)
    meta = load_meta(d)
    run(["systemctl", "stop", unit_name(meta["id"])], capture_output=True)
    meta = load_meta(d)
    # "incomplete" too: a status refresh can race us and mark it interrupted first.
    if meta["status"] in ("queued", "downloading", "incomplete"):
        meta.update(status="incomplete", phase="", error="Paused. Resume it to continue where it left off.")
    elif meta["status"] == "scanning" or (meta["status"] == "downloaded" and "Interrupted" in meta.get("error", "")):
        meta.update(status="downloaded", phase="", error="Scan was stopped before finishing.")
    save_meta(d, meta)
    emit({"ok": True}) if args.json else print("Stopped.")
    return 0


def cmd_items(args, cfg) -> int:
    running = active_units()
    items = [item_view(m.parent, running) for m in QUARANTINE.glob("*/meta.json")]
    items.sort(key=lambda m: m["added"], reverse=True)
    emit({"items": items, "free": shutil.disk_usage(QUARANTINE).free})
    return 0


def cmd_item(args, cfg) -> int:
    emit(item_view(item_dir(args.id), active_units()))
    return 0


def cmd_health(args, cfg) -> int:
    health = check_health(cfg)
    if args.json:
        emit(health)
        return 0
    marks = {"ok": paint("✓", "32"), "warn": paint("⚠", "33"), "block": paint("✖", "31")}
    for c in health["checks"]:
        print(f"  {marks[c['state']]} {c['title']}: {c['detail']}")
    print("\n" + (paint("Downloads are blocked until the ✖ items are fixed.", "31") if health["blocked"]
                  else paint("Downloads allowed.", "32")))
    return 1 if health["blocked"] else 0


def cmd_resume(args, cfg) -> int:
    enforce(cfg)
    d = item_dir(args.id)
    meta = load_meta(d)
    (QUARANTINE / ".last").write_text(meta["id"])
    if meta["id"] in active_units():
        die("It's already running in the background (see the GUI, or `safetorrent stop`).")
    if meta["status"] in ("scanned", "released"):
        print("Already downloaded and scanned.")
        print_report(meta)
        return 0
    if meta["status"] != "downloaded":
        check_space(meta)
        if not download(d, meta, cfg):
            return 0
    scan(d, meta, cfg)
    return 0


def cmd_rescan(args, cfg) -> int:
    sync_inbox()
    cfg.update(load_config())
    d = item_dir(args.id)
    meta = load_meta(d)
    (QUARANTINE / ".last").write_text(meta["id"])
    if meta["status"] not in ("downloaded", "scanned", "released"):
        die(f"can't scan: download status is '{meta['status']}'")
    scan(d, meta, cfg)
    return 0


def cmd_list(args, cfg) -> int:
    running = active_units()
    items = [item_view(m.parent, running) for m in QUARANTINE.glob("*/meta.json")]
    if not items:
        print("Quarantine is empty.")
        return 0
    items.sort(key=lambda m: m["added"])
    print(f"{'ID':<11} {'RESULT':<11} {'STATUS':<12} {'SIZE':>9}  NAME")
    for m in items:
        v = (m.get("scan") or {}).get("verdict") or m["precheck"]["verdict"]
        print(f"{m['id']:<11} {paint(f'{v:<11}', VERDICT_COLOR[v])} {m['status']:<12} {human(m['total']):>9}  {m['name']}")
    print(f"\nVM free space: {human(shutil.disk_usage(QUARANTINE).free)}")
    return 0


def cmd_report(args, cfg) -> int:
    print_report(load_meta(item_dir(args.id)))
    return 0


def cmd_last(args, cfg) -> int:
    last = QUARANTINE / ".last"
    print(last.read_text().strip() if last.exists() else "")
    return 0


def safe_folder_name(name: str, fallback: str) -> str:
    """A torrent's name as a single, harmless folder name on the Mac."""
    cleaned = re.sub(r"[\x00-\x1f\x7f/\\:]", "_", BIDI_RE.sub("", name)).strip(". ")[:120]
    return cleaned or fallback


def cmd_release_info(args, cfg) -> int:
    meta = load_meta(item_dir(args.id))
    verdict = (meta.get("scan") or {}).get("verdict", "-")
    print("\t".join([meta["id"], meta["status"], verdict, safe_folder_name(meta["name"], meta["id"])]))
    return 0


def cmd_mark_released(args, cfg) -> int:
    d = item_dir(args.id)
    meta = load_meta(d)
    meta.update(status="released", released_to=args.dest, released_at=now())
    meta.pop("error", None)
    save_meta(d, meta)
    return 0


def cmd_purge(args, cfg) -> int:
    targets = [p.parent for p in QUARANTINE.glob("*/meta.json")] if args.id == "all" else [item_dir(args.id)]
    for d in targets:
        run(["systemctl", "stop", unit_name(d.name)], capture_output=True)
        shutil.rmtree(d)
        if not args.json:
            print(f"removed {d.name}")
    if args.json:
        emit({"ok": True, "removed": [d.name for d in targets]})
    return 0


def cmd_vpn(args, cfg) -> int:
    try:
        ip = prepare(cfg)
        error = None
    except StError as e:
        ip, error = None, str(e)
    on = vpn_enabled(cfg)
    if args.json:
        emit({"on": on, "ip": ip if on else public_ip_as_torrent_user(), "error": error})
        return 0
    if error:
        die(error)
    if ip:
        print(paint("VPN on", "32") + f": torrent traffic exits from {ip} (kill switch active)")
    else:
        direct = public_ip_as_torrent_user()
        print(paint("VPN off", "33") + f": torrent traffic exits from {direct or 'unknown'} (your real IP)")
        print("Enable it with USE_VPN=yes in ~/.config/safetorrent/config (see README).")
    return 0


def cmd_update(args, cfg) -> int:
    print("Updating virus definitions…", flush=True)
    run(["systemctl", "stop", "clamav-freshclam"])
    res = run(["freshclam", "--quiet"])
    run(["systemctl", "start", "clamav-freshclam"])
    if res.returncode not in (0, 1):
        print(paint("freshclam reported a problem; definitions may be stale", "33"))
    print("Installing security updates for the VM's tools…", flush=True)
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
    run(["apt-get", "update", "-qq"], env=env)
    run(["apt-get", "upgrade", "-y", "-qq"], env=env)
    return cmd_health(args, cfg)


def main() -> int:
    p = argparse.ArgumentParser(prog="st-guest")
    p.add_argument("--json", action="store_true", help="machine-readable output (for the GUI)")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("get", "add"):
        g = sub.add_parser(name)
        g.add_argument("source")
        g.add_argument("--category", choices=["media", "software", "docs", "iso"])
        g.add_argument("--sha256")
        if name == "get":
            g.add_argument("--yes", action="store_true")
            g.add_argument("--force", action="store_true")
        else:
            g.add_argument("--no-auto-release", action="store_true")
    st = sub.add_parser("start")
    st.add_argument("id")
    st.add_argument("--force", action="store_true")
    st.add_argument("--scan-only", action="store_true")
    rn = sub.add_parser("run")
    rn.add_argument("id")
    rn.add_argument("--scan-only", action="store_true")
    for name in ("resume", "rescan", "report", "release-info", "purge", "stop", "item"):
        sub.add_parser(name).add_argument("id")
    mr = sub.add_parser("mark-released")
    mr.add_argument("id")
    mr.add_argument("dest")
    for name in ("list", "items", "last", "vpn", "update", "health", "doctor"):
        sub.add_parser(name)
    args = p.parse_args()
    handlers = {
        "get": cmd_get, "add": cmd_add, "start": cmd_start, "run": cmd_run, "stop": cmd_stop,
        "items": cmd_items, "item": cmd_item, "health": cmd_health, "doctor": cmd_health,
        "resume": cmd_resume, "rescan": cmd_rescan, "report": cmd_report,
        "release-info": cmd_release_info, "mark-released": cmd_mark_released, "purge": cmd_purge,
        "list": cmd_list, "last": cmd_last, "vpn": cmd_vpn, "update": cmd_update,
    }
    try:
        if os.geteuid() != 0:
            die("must run as root inside the VM")
        return handlers[args.cmd](args, load_config())
    except StError as e:
        if args.json:
            emit({"error": str(e)})
        else:
            print(paint(f"error: {e}", "31"), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\ninterrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
