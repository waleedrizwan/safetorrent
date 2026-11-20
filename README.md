# safetorrent

I wanted to grab torrents on my Mac without trusting them, so this downloads
them inside a throwaway Linux VM, scans them, and only copies them over if
they come back clean.

```
safetorrent get "magnet:?xt=urn:btih:…"
```

## What it does

1. Looks at the file list before downloading anything and rejects the obvious
   tricks (`movie.mp4.exe`, a program inside a "movie", a 2 MB 1080p film).
2. Downloads inside a Lima VM that shares no folders with the Mac and can't
   reach your home network. Optional Proton VPN with a kill switch.
3. Scans everything: real file type vs. extension, unpacks archives and disk
   images, ClamAV, and VirusTotal hash lookups.
4. Copies clean results to `~/Downloads/SafeTorrents`. Anything iffy waits for
   you; anything bad stays in the VM.

There's also a small app (`safetorrent gui`) if you'd rather click than type.

## Setup

```bash
./safetorrent setup
```

That installs Lima, builds the VM and puts `safetorrent` on your PATH. Then
optionally:

- **VirusTotal:** put a free API key in `~/.config/safetorrent/config` as `VT_API_KEY=…`.
- **Proton VPN:** needs a paid plan and a P2P server. Drop the WireGuard file in
  through the app, or run `safetorrent vpn-import wg0.conf`.

## Commands you'll actually use

```
safetorrent get <magnet|file.torrent>   download, scan, release
safetorrent list                        what's in quarantine
safetorrent report <id>                 why it got the verdict it did
safetorrent release <id>                copy a WARNING download over anyway
safetorrent purge <id|all>              delete from the VM
safetorrent health                      are the safety checks green
safetorrent update                      new virus definitions
safetorrent stop                        shut the VM down to free RAM
```

`safetorrent` with no arguments lists the rest.

## Heads up

This cuts the risk a lot, but it's not magic. New malware can slip past ClamAV
and VirusTotal, and cracked software is risky no matter what. Once you open a
file on your Mac, you're trusting the scan.

## Tests

```bash
python3 -m unittest discover -s tests      # fast, fakes the VM
python3 -m unittest discover -s e2e -v     # real VM, needs setup done
```

## License

MIT
