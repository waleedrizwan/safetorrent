"""Check that a copy from the VM is exactly what the VM scanned.

    /usr/bin/python3 -I verify_manifest.py <copied folder> <manifest.json>

The manifest maps each file's path (relative to the download) to [size, sha256],
recorded when the scan finished. The copy must hold exactly those files, with those
sizes and hashes, and nothing but regular files and folders. Exits 0 if it does;
otherwise prints what's wrong and exits 1. Runs on macOS's own Python 3.9.
"""
import hashlib
import json
import os
import stat
import sys


def fail(msg: str) -> None:
    print(msg, file=sys.stderr)
    sys.exit(1)


def load(path: str) -> dict:
    try:
        with open(path, "rb") as fh:
            data = json.loads(fh.read().decode())
    except (OSError, ValueError) as e:
        fail(f"the record of what was scanned can't be read ({e})")
    ok = isinstance(data, dict) and all(
        isinstance(k, str) and isinstance(v, list) and len(v) == 2 and isinstance(v[0], int)
        and not isinstance(v[0], bool) and v[0] >= 0 and isinstance(v[1], str) and len(v[1]) == 64
        for k, v in data.items())
    if not ok:
        fail("the record of what was scanned is malformed")
    return data


def sha256(path: str) -> str:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    h = hashlib.sha256()
    with os.fdopen(fd, "rb") as fh:
        if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
            fail(f"not a regular file: {path}")
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    if len(sys.argv) != 3:
        fail(__doc__.strip())
    root, manifest = sys.argv[1], load(sys.argv[2])
    found = {}
    for dirpath, dirs, names in os.walk(root):  # doesn't follow links to folders
        for n in dirs + names:
            p = os.path.join(dirpath, n)
            mode = os.lstat(p).st_mode
            if stat.S_ISREG(mode):
                found[os.path.relpath(p, root)] = p
            elif not stat.S_ISDIR(mode):
                fail(f"not a regular file or folder: {os.path.relpath(p, root)}")
    extra = sorted(set(found) - set(manifest))
    missing = sorted(set(manifest) - set(found))
    if extra or missing:
        fail("the copy doesn't match what was scanned: "
             + "; ".join(([f"never scanned: {', '.join(extra[:5])}"] if extra else [])
                         + ([f"missing: {', '.join(missing[:5])}"] if missing else [])))
    for rel, (size, digest) in sorted(manifest.items()):
        p = found[rel]
        if os.lstat(p).st_size != size or sha256(p) != digest.lower():
            fail(f"the copy doesn't match what was scanned: {rel} changed after the scan")


if __name__ == "__main__":
    main()
