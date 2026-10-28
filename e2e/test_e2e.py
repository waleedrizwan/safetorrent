"""End-to-end tests against the real VM: real Lima, aria2c, firewall, VPN, 7-Zip,
ClamAV and VirusTotal. Nothing is faked.

    python3 -m unittest discover -s e2e -v                              # ~2 min
    SAFETORRENT_E2E_INTERNET=1 python3 -m unittest discover -s e2e -v   # + real public torrents

Needs the VM from `safetorrent setup` and a passing `safetorrent health`. Runs the
real `safetorrent` command with a throwaway HOME whose config is a copy of yours
with DOWNLOAD_DIR pointed at a temp folder, so nothing lands in your Downloads.
Test torrents are purged from the VM afterwards.

The local tests build their torrents inside the VM (see vm_fixtures.py) and seed
them from the VM's loopback, so the files with the EICAR test string or a fake
program header never exist on the Mac.
"""

import http.server
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import unittest
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SAFETORRENT = ROOT / "safetorrent"
VM = "safetorrent"
WORK = "/var/lib/st-e2e"
PORT = 8731
INTERNET = os.environ.get("SAFETORRENT_E2E_INTERNET") == "1"
REAL_CONF_DIR = Path.home() / ".config" / "safetorrent"
DEBIAN_BT = "https://cdimage.debian.org/debian-cd/current/arm64/bt-cd/"
SINTEL_MAGNET = ("magnet:?xt=urn:btih:08ada5a7a6183aae1e09d831df6748d566095a10&dn=Sintel"
                 "&tr=udp%3A%2F%2Ftracker.opentrackr.org%3A1337%2Fannounce"
                 "&tr=udp%3A%2F%2Fexplodie.org%3A6969&tr=udp%3A%2F%2Ftracker.leechers-paradise.org%3A6969")

INFO, WARN, DANGER, INFECTED = range(4)

tmp: Path
env: dict
released: Path
torrents: Path
manifest: dict
used_ids: set = set()


def sh(cmd, timeout=600, check=True, **kw) -> subprocess.CompletedProcess:
    res = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout,
                         stdin=subprocess.DEVNULL, **kw)
    if check and res.returncode != 0:
        raise AssertionError(f"{cmd} exited {res.returncode}\n{res.stdout}\n{res.stderr}")
    return res


def st(*args, timeout=900, check=True) -> subprocess.CompletedProcess:
    """The real host command, as the user would run it."""
    return sh([str(SAFETORRENT), *args], timeout=timeout, check=check, env=env)


def vm(script: str, root: bool = True, check=True, timeout=600) -> subprocess.CompletedProcess:
    """A shell script inside the VM, as root or as the VM's default (non-torrent) user."""
    cmd = ["limactl", "shell", "--workdir", "/", VM, "--"] + (["sudo"] if root else []) + ["sh", "-c", script]
    return sh(cmd, timeout=timeout, check=check, env=env)


def as_torrent(script: str, timeout=60) -> subprocess.CompletedProcess:
    return vm(f"runuser -u torrent -- sh -c {sh_quote(script)}", check=False, timeout=timeout)


def sh_quote(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


def item(item_id: str) -> dict:
    return json.loads(vm(f"python3 /opt/safetorrent/st-guest.py item {item_id}").stdout)


def purge(item_id: str) -> None:
    st("purge", item_id, check=False)


def setUpModule():
    global tmp, env, released, torrents, manifest
    if not shutil.which("limactl"):
        raise unittest.SkipTest("Lima isn't installed (run `safetorrent setup`)")
    if sh(["limactl", "list", "-q", VM], check=False).stdout.strip() != VM:
        raise unittest.SkipTest("the safetorrent VM doesn't exist (run `safetorrent setup`)")

    tmp = Path(tempfile.mkdtemp(prefix="st-e2e-"))
    unittest.addModuleCleanup(cleanup)  # runs even if the rest of the setup fails
    released = tmp / "released"
    conf_dir = tmp / "home" / ".config" / "safetorrent"
    conf_dir.mkdir(parents=True)
    conf = (REAL_CONF_DIR / "config").read_text() if (REAL_CONF_DIR / "config").exists() else ""
    conf = re.sub(r"(?m)^\s*DOWNLOAD_DIR=.*\n?", "", conf) + f"\nDOWNLOAD_DIR={released}\n"
    (conf_dir / "config").write_text(conf)
    (conf_dir / "config").chmod(0o600)
    if (REAL_CONF_DIR / "wg0.conf").exists():
        # A link, not a copy: the VPN key stays where it is. (Without it, the push
        # would tell the VM to drop its VPN config.)
        (conf_dir / "wg0.conf").symlink_to(REAL_CONF_DIR / "wg0.conf")
    env = dict(os.environ, HOME=str(tmp / "home"),
               LIMA_HOME=os.environ.get("LIMA_HOME", str(Path.home() / ".lima")))

    st("start", timeout=300)
    health = st("health", timeout=300, check=False)
    if health.returncode != 0:
        raise AssertionError("`safetorrent health` says downloads are blocked; fix that first:\n" + health.stdout)

    sh(["limactl", "copy", str(Path(__file__).with_name("vm_fixtures.py")), f"{VM}:/tmp/vm_fixtures.py"], env=env)
    vm(f"python3 /tmp/vm_fixtures.py build {WORK} {PORT} && rm /tmp/vm_fixtures.py", timeout=300)
    vm("systemctl stop st-e2e-web 2>/dev/null; systemctl reset-failed st-e2e-web 2>/dev/null; "
       f"systemd-run --quiet --unit st-e2e-web -p User=nobody -p WorkingDirectory={WORK}/www "
       f"python3 -m http.server --bind 127.0.0.1 {PORT}")
    torrents = tmp / "torrents"
    sh(["limactl", "copy", "-r", f"{VM}:{WORK}/torrents", str(torrents)], env=env)
    manifest = json.loads((torrents / "manifest.json").read_text())
    # Leftovers from an interrupted run. By name: the archives embed timestamps, so ids change per build.
    for leftover in json.loads(vm("python3 /opt/safetorrent/st-guest.py items").stdout)["items"]:
        if leftover["name"].startswith("ST-E2E "):
            purge(leftover["id"])


def tearDownModule():
    pass  # Python 3.9 runs module cleanups (cleanup() below) only if this exists


def cleanup():
    if "env" in globals():
        for item_id in used_ids:
            purge(item_id)
        vm(f"systemctl stop st-e2e-web; rm -rf {WORK}", check=False)
    shutil.rmtree(tmp, ignore_errors=True)


def get(source: str, *options: str, timeout=900) -> tuple[subprocess.CompletedProcess, str]:
    """`safetorrent get` with --no-release, so the app (if open) never copies a test
    download into your real Downloads folder. Returns the output and the item id."""
    out = st("get", source, "--no-release", *options, timeout=timeout)
    item_id = vm("python3 /opt/safetorrent/st-guest.py last").stdout.strip()
    used_ids.add(item_id)
    return out, item_id


def findings(meta: dict, level: int) -> list[dict]:
    return [f for f in meta["scan"]["findings"] if f["level"] == level]


class Isolation(unittest.TestCase):
    """The VM really is cut off, checked from inside the running VM."""

    def test_no_mac_folders_are_mounted(self):
        mounts = vm("cat /proc/mounts").stdout
        self.assertNotRegex(mounts, r" (virtiofs|9p|fuse\.sshfs) ")
        self.assertNotEqual(vm("test -e /Users", check=False).returncode, 0, "/Users exists in the VM")

    def mac_server(self) -> int:
        class Quiet(http.server.SimpleHTTPRequestHandler):
            def log_message(self, *_args):
                pass
        server = http.server.ThreadingHTTPServer(("0.0.0.0", 0), Quiet)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server.server_address[1]

    def assertOnlyTorrentUserBlocked(self, url: str, control_required: bool) -> None:
        # The VM's normal user isn't firewalled: if it can reach the URL, the
        # torrent user failing proves the firewall, not some unrelated outage.
        control = vm(f"curl -s -o /dev/null -m 5 {url}", root=False, check=False)
        if control.returncode != 0:
            msg = f"the VM's normal user can't reach {url} either, so this check would prove nothing"
            if control_required:
                self.fail(msg)
            self.skipTest(msg)
        blocked = as_torrent(f"curl -s -o /dev/null -m 5 {url}")
        self.assertNotEqual(blocked.returncode, 0, f"the torrent user reached the Mac at {url}")

    def test_torrent_user_cannot_reach_the_mac(self):
        self.assertOnlyTorrentUserBlocked(f"http://host.lima.internal:{self.mac_server()}/", control_required=True)

    def test_torrent_user_cannot_reach_the_macs_home_network_address(self):
        lan = sh(["ipconfig", "getifaddr", "en0"], check=False).stdout.strip()
        if not lan:
            self.skipTest("the Mac has no address on en0")
        # Lima's network often can't reach this address at all; then it's skipped.
        self.assertOnlyTorrentUserBlocked(f"http://{lan}:{self.mac_server()}/", control_required=False)

    def test_loopback_is_the_only_private_address_allowed(self):
        gateway = vm("ip route show default | awk '{print $3; exit}'").stdout.strip()
        self.assertNotEqual(as_torrent(f"curl -s -o /dev/null -m 5 http://{gateway}/").returncode, 0)
        self.assertEqual(as_torrent(f"curl -s -o /dev/null -m 5 http://127.0.0.1:{PORT}/").returncode, 0)

    def vpn_on(self) -> bool:
        return "USE_VPN=yes" in (REAL_CONF_DIR / "config").read_text().replace(" ", "")

    def test_peers_see_the_vpn_not_your_ip(self):
        if not self.vpn_on():
            self.skipTest("USE_VPN is off")
        home_ip = urllib.request.urlopen("https://api.ipify.org", timeout=15).read().decode().strip()
        res = as_torrent("curl -4 -s -m 15 https://api.ipify.org")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertRegex(res.stdout.strip(), r"^\d+\.\d+\.\d+\.\d+$")
        self.assertNotEqual(res.stdout.strip(), home_ip)

    def test_kill_switch_blocks_traffic_when_the_tunnel_drops(self):
        if not self.vpn_on():
            self.skipTest("USE_VPN is off")
        self.addCleanup(lambda: st("vpn", timeout=120, check=False))  # bring the tunnel back
        vm("wg-quick down wg0")
        control = vm("curl -4 -s -o /dev/null -m 10 https://api.ipify.org", root=False, check=False)
        self.assertEqual(control.returncode, 0, "the VM itself has no internet; the check would prove nothing")
        for flag in ("-4", "-6"):
            with self.subTest(flag=flag):
                leak = as_torrent(f"curl {flag} -s -m 10 https://api.ipify.org")
                self.assertNotEqual(leak.returncode, 0, f"traffic left without the VPN: {leak.stdout}")


class LocalTorrents(unittest.TestCase):
    """The full pipeline on torrents seeded from inside the VM."""

    def run_fixture(self, slug: str, *options: str) -> dict:
        fixture = manifest[slug]
        out, item_id = get(str(torrents / f"{slug}.torrent"), *options)
        self.assertEqual(item_id, fixture["id"], out.stdout)
        self.output = out.stdout
        return item(item_id)

    def assertNotReleased(self, meta: dict):
        res = st("release", meta["id"], check=False)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("stays in quarantine", res.stderr)
        self.assertFalse((released / meta["name"]).exists())

    def test_clean_download_is_released_intact(self):
        meta = self.run_fixture("st-e2e-clean-clip")
        self.assertEqual(meta["precheck"]["verdict"], "OK")
        self.assertEqual(meta["category"], "media")
        self.assertEqual(meta["scan"]["verdict"], "CLEAN", self.output)

        files = f"/srv/quarantine/{meta['id']}/files"
        tamper = as_torrent(f"echo x >> '{files}/ST-E2E Clean Clip/clip.mkv' || touch '{files}/new'")
        self.assertNotEqual(tamper.returncode, 0, "the torrent user could change a scanned download")

        res = st("release", meta["id"])
        dest = released / meta["name"]
        self.assertTrue(dest.is_dir(), res.stdout)
        expected = manifest["st-e2e-clean-clip"]["files"]
        got = {p.relative_to(dest).as_posix(): sh(["shasum", "-a", "256", str(p)]).stdout.split()[0]
               for p in dest.rglob("*") if p.is_file()}
        self.assertEqual(got, expected)
        for rel in expected:
            attr = sh(["xattr", "-p", "com.apple.quarantine", str(dest / rel)], check=False)
            self.assertIn("safetorrent", attr.stdout, f"{rel} has no Gatekeeper quarantine flag")
        self.assertEqual(item(meta["id"])["status"], "released")

    def test_eicar_is_infected_and_kept(self):
        meta = self.run_fixture("st-e2e-eicar-notes")
        self.assertEqual(meta["precheck"]["verdict"], "OK")
        self.assertEqual(meta["scan"]["verdict"], "INFECTED", self.output)
        hits = findings(meta, INFECTED)
        self.assertTrue(any(f["path"] == "ST-E2E Eicar Notes/notes.txt" and "Eicar" in f["msg"] for f in hits), hits)
        self.assertNotReleased(meta)

    def test_eicar_two_archives_deep_is_found(self):
        meta = self.run_fixture("st-e2e-eicar-nested-zip")
        self.assertEqual(meta["scan"]["verdict"], "INFECTED", self.output)
        paths = [f["path"] for f in findings(meta, INFECTED)]
        self.assertTrue(any("bundle.zip.d/inner.zip.d/readme.txt" in p for p in paths), paths)
        self.assertNotReleased(meta)

    def test_program_disguised_as_video_is_suspicious(self):
        meta = self.run_fixture("st-e2e-disguised-program")
        self.assertEqual(meta["precheck"]["verdict"], "OK")  # the names look innocent
        self.assertEqual(meta["scan"]["verdict"], "SUSPICIOUS", self.output)
        msgs = [f["msg"] for f in findings(meta, DANGER) if f["path"].endswith("Holiday Video.mkv")]
        self.assertTrue(any("Windows program" in m for m in msgs), meta["scan"]["findings"])
        self.assertNotReleased(meta)

    def test_password_protected_archive_is_suspicious(self):
        meta = self.run_fixture("st-e2e-password-archive")
        self.assertEqual(meta["scan"]["verdict"], "SUSPICIOUS", self.output)
        msgs = [f["msg"] for f in findings(meta, DANGER) if f["path"].endswith("locked.zip")]
        self.assertTrue(any("password-protected" in m for m in msgs), meta["scan"]["findings"])
        self.assertNotReleased(meta)

    def test_zip_bomb_is_not_unpacked(self):
        meta = self.run_fixture("st-e2e-zip-bomb")
        self.assertEqual(meta["scan"]["verdict"], "SUSPICIOUS", self.output)
        msgs = [f["msg"] for f in findings(meta, DANGER) if f["path"].endswith("bomb.7z")]
        self.assertTrue(any("zip bomb" in m for m in msgs), meta["scan"]["findings"])
        unpacked = vm(f"find /srv/quarantine/{meta['id']}/extracted -type f | wc -l").stdout.strip()
        self.assertEqual(unpacked, "0")
        self.assertNotReleased(meta)

    def test_rejected_torrent_downloads_nothing(self):
        meta = self.run_fixture("st-e2e-rejected-double-extension")
        self.assertEqual(meta["precheck"]["verdict"], "REJECTED")
        self.assertEqual(meta["status"], "rejected")
        self.assertIn("Nothing was downloaded", self.output)
        self.assertEqual(vm(f"find /srv/quarantine/{meta['id']}/files -type f | wc -l").stdout.strip(), "0")


@unittest.skipUnless(INTERNET, "set SAFETORRENT_E2E_INTERNET=1 to download real public torrents (~850 MB)")
class PublicTorrents(unittest.TestCase):
    """Real, legal torrents from real swarms, verified against the publisher's files."""

    def test_debian_netinst_iso_with_checksum(self):
        page = urllib.request.urlopen(DEBIAN_BT, timeout=30).read().decode()
        name = re.search(r'href="(debian-[\d.]+-arm64-netinst\.iso)\.torrent"', page).group(1)
        sums = urllib.request.urlopen(DEBIAN_BT + "SHA256SUMS", timeout=30).read().decode()
        sha = re.search(rf"^([0-9a-f]{{64}})\s+{re.escape(name)}$", sums, re.M).group(1)
        path = tmp / f"{name}.torrent"
        path.write_bytes(urllib.request.urlopen(f"{DEBIAN_BT}{name}.torrent", timeout=30).read())

        out, item_id = get(str(path), "--sha256", sha, timeout=3600)
        meta = item(item_id)
        self.assertEqual(meta["category"], "iso")
        self.assertEqual(meta["scan"]["verdict"], "CLEAN", out.stdout)
        self.assertTrue(any(f.get("verified") for f in meta["scan"]["findings"]), out.stdout)

        st("release", item_id, timeout=600)
        iso = released / name
        self.assertEqual(sh(["shasum", "-a", "256", str(iso)], timeout=600).stdout.split()[0], sha)

    def test_sintel_by_magnet_link(self):
        out, item_id = get(SINTEL_MAGNET, timeout=3600)
        meta = item(item_id)
        self.assertEqual(meta["category"], "media")
        self.assertEqual(meta["scan"]["verdict"], "CLEAN", out.stdout)
        st("release", item_id, timeout=600)
        movie = released / "Sintel" / "Sintel.mp4"
        self.assertTrue(movie.is_file())
        with open(movie, "rb") as fh:
            self.assertEqual(fh.read(12)[4:8], b"ftyp")  # a real MP4


if __name__ == "__main__":
    socket.setdefaulttimeout(30)
    unittest.main()
