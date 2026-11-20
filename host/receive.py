"""Unpack the tar stream the VM sends into an empty staging folder on the Mac.

    guest send <id> | sandbox-exec -f receive.sb -D STAGE=<stage> \\
        /usr/bin/python3 -I receive.py <stage> <manifest.json>

The VM is untrusted, so the stream is too. Only regular files and folders are
accepted; absolute paths, "..", links, devices, FIFOs and names with control
characters are refused, as is anything bigger in total than what was scanned (the
manifest's sizes). Every file and folder is created relative to the stage's own file
descriptor, never following a symlink, and never overwriting. receive.sb also denies
writes anywhere outside the stage, so even a bug here can't write elsewhere.

Exits 0 when everything was received; otherwise prints why and exits 1, leaving the
caller to delete the stage. Runs on macOS's own Python 3.9: tarfile's extraction
filters don't exist there, so each member is checked by hand.
"""
import json
import os
import sys
import tarfile

CONTROL = {chr(c) for c in range(32)} | {"\x7f"}
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


class Refused(Exception):
    pass


def scanned_total(path: str) -> int:
    try:
        with open(path, "rb") as fh:
            data = json.loads(fh.read().decode())
        return sum(int(v[0]) for v in data.values())
    except (OSError, ValueError, TypeError, KeyError, IndexError, AttributeError) as e:
        raise Refused(f"the record of what was scanned can't be read ({e})") from None


def parts_of(name: str) -> list:
    if not isinstance(name, str) or name.startswith("/"):
        raise Refused(f"absolute path: {name!r}")
    if any(c in CONTROL for c in name):
        raise Refused(f"name with control characters: {name!r}")
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if ".." in parts:
        raise Refused(f"path leading out of the folder: {name!r}")
    return parts


def open_dir(stage_fd: int, parts: list) -> int:
    """The folder at parts under the stage, created if needed; never through a symlink."""
    fd = os.dup(stage_fd)
    try:
        for p in parts:
            try:
                os.mkdir(p, 0o755, dir_fd=fd)
            except FileExistsError:
                pass
            nxt = os.open(p, DIR_FLAGS, dir_fd=fd)  # fails on a symlink or a file
            os.close(fd)
            fd = nxt
        return fd
    except BaseException:
        os.close(fd)
        raise


def write_file(stage_fd: int, parts: list, src, size: int, mode: int, mtime: float) -> None:
    parent = open_dir(stage_fd, parts[:-1])
    try:
        fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
    finally:
        os.close(parent)
    with os.fdopen(fd, "wb") as out:
        written = 0
        for chunk in iter(lambda: src.read(1 << 20), b""):
            written += len(chunk)
            if written > size:
                raise Refused("a file was longer than its header said")
            out.write(chunk)
        if written != size:
            raise Refused("the stream ended in the middle of a file")
        # Plain permissions only: no setuid/setgid/sticky, nothing others can change.
        os.fchmod(out.fileno(), 0o755 if mode & 0o100 else 0o644)
        if os.utime in os.supports_fd:
            os.utime(out.fileno(), (mtime, mtime))


def receive(stage: str, limit: int, stream) -> None:
    stage_fd = os.open(stage, DIR_FLAGS)
    try:
        if os.listdir(stage_fd):
            raise Refused("the staging folder isn't empty")
        total = 0
        with tarfile.open(fileobj=stream, mode="r|") as tar:
            for m in tar:
                parts = parts_of(m.name)
                if m.isdir():
                    if parts:
                        os.close(open_dir(stage_fd, parts))
                    continue
                if not m.isreg() or not parts:
                    raise Refused(f"symlinks or special files aren't allowed: {m.name!r}")
                total += m.size
                if total > limit:
                    raise Refused("the VM sent more than was scanned")
                src = tar.extractfile(m)
                if src is None:
                    raise Refused(f"unreadable member: {m.name!r}")
                write_file(stage_fd, parts, src, m.size, m.mode, m.mtime)
    except (tarfile.TarError, OSError, UnicodeError) as e:
        raise Refused(f"the copy from the VM is damaged or unsafe ({e})") from None
    finally:
        os.close(stage_fd)


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    try:
        receive(sys.argv[1], scanned_total(sys.argv[2]), sys.stdin.buffer)
    except Refused as e:
        print(f"refused the copy from the VM: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
