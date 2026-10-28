"""Runs as root inside the safetorrent VM: builds the end-to-end test torrents.

Every torrent's files are served over HTTP on the VM's own loopback and listed
as a web seed (BEP 19), so aria2c downloads them with no peers and no internet.
The torrent user's firewall lets loopback through, so this is the real download
path. Only the .torrent files leave the VM: nothing malicious-looking (EICAR,
fake programs) ever touches the Mac.

    python3 vm_fixtures.py build <workdir> <port>   # writes torrents + manifest.json
"""

import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import zipfile
import zlib
from pathlib import Path

PIECE = 16 * 1024

# Split so this file itself never contains the EICAR string (scanners would flag it).
EICAR = (b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")


def bencode(v) -> bytes:
    if isinstance(v, int):
        return b"i%de" % v
    if isinstance(v, str):
        v = v.encode()
    if isinstance(v, bytes):
        return b"%d:%s" % (len(v), v)
    if isinstance(v, list):
        return b"l" + b"".join(bencode(x) for x in v) + b"e"
    if isinstance(v, dict):
        return b"d" + b"".join(bencode(k) + bencode(v[k]) for k in sorted(v)) + b"e"
    raise TypeError(type(v))


def png() -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return len(data).to_bytes(4, "big") + kind + data + zlib.crc32(kind + data).to_bytes(4, "big")
    raw = b"".join(b"\x00" + b"\x80\x40\x20" * 8 for _ in range(8))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", bytes.fromhex("0000000800000008080200000000"))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


def mkv(size: int) -> bytes:
    # An EBML header followed by deterministic filler: enough for the content sniffer.
    filler = hashlib.sha256(b"safetorrent-e2e").digest()
    return (b"\x1a\x45\xdf\xa3" + filler * (size // len(filler) + 1))[:size]


def zip_bytes(entries: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return buf.getvalue()


def sevenz(dest: Path, src: Path, *switches: str) -> None:
    subprocess.run(["7z", "a", "-bd", "-y", *switches, str(dest), str(src)], check=True, stdout=subprocess.DEVNULL)


# name -> {relative path: bytes}. Each becomes a multi-file torrent named after the key.
def fixtures(scratch: Path) -> dict:
    out = {
        "ST-E2E Clean Clip": {
            "clip.mkv": mkv(256 * 1024),
            "cover.png": png(),
            "clip.en.srt": b"1\n00:00:01,000 --> 00:00:03,000\nHello from the safetorrent end-to-end test.\n",
        },
        "ST-E2E Eicar Notes": {
            "notes.txt": EICAR,
            "cover.png": png(),
        },
        "ST-E2E Eicar Nested Zip": {
            "bundle.zip": zip_bytes({"inner.zip": zip_bytes({"readme.txt": EICAR})}),
            "readme.txt": b"An archive two levels deep with the EICAR test string at the bottom.\n",
        },
        "ST-E2E Disguised Program": {
            # A harmless stub that starts like a Windows program, named as a video.
            "Holiday Video.mkv": b"MZ" + b"\x00" * 4094,
            "cover.png": png(),
        },
        "ST-E2E Rejected Double Extension": {
            "Film.mp4.exe": b"not really a program\n",
        },
    }
    # 7-Zip-only cases: an encrypted archive, and a bomb (~1.5 GB of zeros in a few hundred KB).
    pw = scratch / "locked.zip"
    (scratch / "payload.txt").write_bytes(b"you can't see me\n")
    sevenz(pw, scratch / "payload.txt", "-tzip", "-psecret")
    out["ST-E2E Password Archive"] = {"locked.zip": pw.read_bytes(), "readme.txt": b"Password: secret\n"}
    zeros = scratch / "zeros.bin"
    with open(zeros, "wb") as fh:
        fh.truncate(1536 * 1024**2)
    bomb = scratch / "bomb.7z"
    sevenz(bomb, zeros, "-t7z", "-mx=9")
    zeros.unlink()
    out["ST-E2E Zip Bomb"] = {"bomb.7z": bomb.read_bytes(), "readme.txt": b"Unpacks to 1.5 GB.\n"}
    return out


def build(work: Path, port: int) -> None:
    if work.exists():
        shutil.rmtree(work)
    www, torrents, scratch = work / "www", work / "torrents", work / "scratch"
    for p in (www, torrents, scratch):
        p.mkdir(parents=True)
    manifest = {}
    for name, files in fixtures(scratch).items():
        blob = b""
        entries = []
        hashes = {}
        for rel in sorted(files):
            data = files[rel]
            target = www / name / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            blob += data
            entries.append({"length": len(data), "path": rel.split("/")})
            hashes[rel] = hashlib.sha256(data).hexdigest()
        pieces = b"".join(hashlib.sha1(blob[i:i + PIECE]).digest() for i in range(0, len(blob), PIECE))
        info = {"name": name, "piece length": PIECE, "pieces": pieces, "files": entries}
        torrent = bencode({"info": info, "url-list": [f"http://127.0.0.1:{port}/"],
                           "created by": "safetorrent e2e"})
        slug = name.lower().replace(" ", "-")
        (torrents / f"{slug}.torrent").write_bytes(torrent)
        infohash = hashlib.sha1(bencode(info)).hexdigest()
        manifest[slug] = {"name": name, "id": infohash[:10], "files": hashes}
    (torrents / "manifest.json").write_text(json.dumps(manifest, indent=2))
    shutil.rmtree(scratch)
    for root, dirs, names in os.walk(work):
        for n in dirs:
            os.chmod(Path(root) / n, 0o755)
        for n in names:
            os.chmod(Path(root) / n, 0o644)
    os.chmod(work, 0o755)


if __name__ == "__main__":
    if len(sys.argv) != 4 or sys.argv[1] != "build":
        sys.exit(__doc__)
    build(Path(sys.argv[2]), int(sys.argv[3]))
