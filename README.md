# safetorrent

Download torrents inside an isolated Linux VM, scan them, and copy them to
your Mac only when they come back clean.

```
safetorrent get "magnet:?xt=urn:btih:…"
```

1. **Pre-check (nothing downloaded yet).** Reads the torrent's file list and
   rejects classic malware tricks: a program inside a movie torrent,
   `movie.mp4.exe` double extensions, hidden right-to-left characters, `.lnk`/`.scr`
   files, and 1080p "movies" that are 2 MB. Warnings ask before continuing.
2. **Download in quarantine.** `aria2c` runs inside a Lima VM as an
   unprivileged user. The VM shares no folders with the Mac, and a firewall
   stops the download user from reaching your Mac or anything on your home
   network. With the VPN on, a kill switch blocks all torrent traffic unless
   the tunnel is up.
3. **Scan.**
   - Checks each file's real contents against its extension (catches a program renamed to `.mp4`).
   - Extracts archives and disk images (`.iso`, `.img`, `.dmg`), up to 3 levels deep, and checks what's inside.
   - Flags password-protected archives and zip bombs.
   - Runs ClamAV over everything, one scan at a time. If ClamAV doesn't finish, the result is
     SUSPICIOUS, never CLEAN. Files too big for ClamAV (over 500 MB) give a warning unless
     they're real media, were unpacked and scanned inside, or match your `--sha256`.
   - Looks up programs, archives and documents on VirusTotal.
   - With `--sha256`, verifies the download against the publisher's checksum.
4. **Release.** A CLEAN result is copied to `~/Downloads/SafeTorrents`, with
   macOS's quarantine flag re-applied so Gatekeeper still checks apps on first
   open. WARNING waits for you to run `safetorrent release <id>`. SUSPICIOUS and
   INFECTED results stay in the VM.

## The app

Double-click **SafeTorrent** in `~/Applications` (or run `safetorrent gui`). It
opens in its own window and starts the VM if needed.

- **Safety checks (left).** Everything a download depends on: the VM is sealed,
  the firewall is up, Proton is passing traffic, virus definitions are current,
  VirusTotal works, and there's disk space. Any red check **blocks downloads**
  (the VM agent refuses them, whether you use the app or the terminal) and shows
  the button that fixes it, such as *Import new Proton file* or *Update now*.
- **Check a torrent.** Paste a magnet link or drop a `.torrent` file. The file list
  is checked first. If it passes, the torrent downloads into quarantine; if it
  has warnings, it waits for you; if it's rejected, nothing downloads.
- **Downloads.** Each one moves through four stages: file list checked,
  quarantine, scan, on your Mac. Clean results are copied automatically.
  Pause, resume, scan again, release or delete from the same card.

What's enforced automatically:

- **The VPN is watched during downloads.** If Proton stops passing traffic, the
  app reconnects once. If that fails, the download stops, the check turns red,
  and new downloads are blocked until you import a fresh Proton file.
- **Imported Proton files are tested first.** A file that doesn't work is
  refused, and your previous one is kept.
- **Old virus definitions block downloads.** Over 3 days old gives a warning;
  over 7 days blocks downloads.
- **The firewall is verified on every check,** and rebuilt only if it's wrong.

The app listens only on `127.0.0.1:8765`, and every request needs a secret token
from `~/.config/safetorrent/gui-token`, so other websites can't control it.
Logs are in `~/Library/Logs/safetorrent-gui.log`.

## Setup

```bash
~/code/safetorrent/safetorrent setup
```

This installs [Lima](https://lima-vm.io), creates the VM (Ubuntu 24.04, 3 GB RAM,
80 GB sparse disk), creates `~/.config/safetorrent/config`, and puts
`safetorrent` on your PATH.

### VirusTotal (recommended)

1. Sign up at <https://www.virustotal.com>. It's free.
2. Click your avatar and choose **API key**.
3. Paste the key into `~/.config/safetorrent/config` as `VT_API_KEY=…`.

The free tier allows 4 lookups a minute, so programs and archives are checked
first, up to `VT_MAX_LOOKUPS` files per torrent. Only file hashes are sent to
VirusTotal, never the files themselves.

### Proton VPN

Torrenting on Proton needs a **paid plan** (Plus or higher) and a **P2P server**.
Free servers block it.

1. Go to <https://account.protonvpn.com> → **Downloads** → **WireGuard configuration**.
2. Choose platform **GNU/Linux** and a server marked **P2P**, then create it.
3. Save the file as `~/.config/safetorrent/wg0.conf`.
4. Set `USE_VPN=yes` in `~/.config/safetorrent/config`.
5. Run `safetorrent vpn`. It should show a Proton IP, not yours.

Or, in the app, click **Import new Proton file** and drop the file in. That does
all of the above, and tests the file first.

If the tunnel drops, downloads stop instead of falling back to your real IP.
Proton rotates these configs occasionally. If `safetorrent vpn` says the VPN
isn't passing traffic, download a fresh one.

## Commands

| Command | What it does |
|---|---|
| `get <magnet or .torrent> [--category media\|software\|docs\|iso] [--sha256 H] [--yes] [--force] [--no-release]` | Full pipeline |
| `list` | Everything in quarantine and its verdict |
| `report <id>` | Full findings |
| `release <id> [--force]` | Copy to the Mac (`--force` needed for SUSPICIOUS/INFECTED) |
| `resume <id>` | Continue a stopped download |
| `rescan <id>` | Scan again, e.g. after `update` |
| `purge <id>` / `purge all` | Delete from the VM |
| `vpn` | VPN status and the IP that peers see |
| `vpn-import <file.conf>` | Swap in a new Proton WireGuard file (tested first, rolled back if it fails) |
| `health` | The safety checks; exits non-zero if downloads are blocked |
| `stop <id>` | Pause a background download |
| `gui` | Open the app |
| `update` | New virus definitions and VM security updates (the VM also refreshes definitions on its own while running) |
| `doctor` | Health check |
| `stop` / `start` / `shell` | Manage the VM. Stop it when you're not using it to free the RAM |

## What it can't do

- **It lowers risk a lot, but nothing is 100%.** Brand-new malware can get past
  both ClamAV and VirusTotal. A VirusTotal note that a program was "never seen"
  means nobody can vouch for it.
- **Cracked software is the riskiest category** no matter how it's scanned.
  Movies, music and ebooks are low-risk once they pass the pre-check.
- **The VM only protects your Mac until release.** When you open a file on
  your Mac, you're trusting the scan.
- **Reputation** comes from the file-list checks, not from the site you got
  the torrent from. Still prefer trusted uploaders and verified release groups.

## Housekeeping

- Grow the VM disk: `limactl stop safetorrent && limactl edit safetorrent --disk 150 && limactl start safetorrent`
- Run the tests: `python3 -m unittest discover -s tests`
- Rebuild the app launcher (e.g. after moving the project): `gui/make-app.sh`
- Uninstall: `limactl delete -f safetorrent && rm /opt/homebrew/bin/safetorrent && rm -rf ~/.config/safetorrent`

## Layout

- `safetorrent`: macOS command (bash). Manages the VM, copies files in and out, releases downloads.
- `vm/st-guest.py`: runs as root inside the VM. Does the pre-check, download, scan and firewall.
- `vm/safetorrent.yaml`: Lima VM definition (isolation settings, packages).
- `config.example`: template for `~/.config/safetorrent/config`.
- `gui/server.py`: local web server for the app (Python standard library only).
- `gui/index.html`: the app's interface.
- `gui/launch.sh`, `gui/make-app.sh`: start the app / build `SafeTorrent.app`.
