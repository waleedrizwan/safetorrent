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
3. In films, shows and books, rebuilds videos, pictures, subtitles and PDFs to
   strip anything hidden in them (attached fonts, metadata, scripts).
4. Scans everything: real file type vs. extension, unpacks archives and disk
   images, ClamAV, YARA rules, and hash lookups on VirusTotal and CIRCL
   hashlookup.
5. Checks the copy again on the Mac (the same rules, plus Apple's code-signing
   checks for any app), then copies clean results to `~/Downloads/SafeTorrents`.
   Anything iffy waits for you; anything bad stays in the VM.

There's also a small app (`safetorrent gui`) if you'd rather click than type.

## Setup

```bash
./safetorrent setup
```

That installs Lima, builds the VM and puts `safetorrent` on your PATH. (Set up
before YARA and media rebuilding were added? Run `safetorrent update` once to
install them.) Then optionally:

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
safetorrent update                      new virus definitions, YARA rules, tools
safetorrent stop                        shut the VM down to free RAM
safetorrent rebuild                     fresh VM (do it monthly; empties quarantine)
```

`safetorrent` with no arguments lists the rest.

## Heads up

This cuts the risk a lot, but it's not magic. New malware can slip past every
scanner, and cracked software is risky no matter what. Once you open a file on
your Mac, you're trusting the scan. A few specifics:

- A program nothing vouches for (VirusTotal has never seen it, or saw it only
  days ago; it isn't a known published file; an app isn't signed and notarized)
  is held as UNVOUCHED. That's what brand-new malware looks like. Copy it only
  if you trust where it came from: `safetorrent release <id> --force`.
- Rebuilt media isn't byte-identical to the torrent's, so you can't seed it
  back. `DISARM_MEDIA=no` in the config keeps the originals.
- VirusTotal and CIRCL hashlookup see the hashes of the files they're asked
  about (not the files). `HASHLOOKUP=no` turns the second one off.
- Once something is in your Downloads, macOS reads it by itself (thumbnails,
  Spotlight) before you open it.

## Tests

```bash
python3 -m unittest discover -s tests      # fast, fakes the VM
python3 -m unittest discover -s e2e -v     # real VM, needs setup done
```

## License

MIT
