"""The Mac's own check of a copy from the VM, before it's put in place.

    sandbox-exec -f receive.sb -D STAGE=<stage> \\
        /usr/bin/python3 -I recheck.py <stage> <torrent name>

The VM's verdict is only as trustworthy as the VM: if something in a download took
over the VM, it could report CLEAN for anything. This doesn't ask the VM anything.
It runs the same file-name and file-type rules again, using this Mac's copy of the
rules (vm/st-guest.py, never the VM's), and checks every Mac app, installer and
program with macOS's own code-signing tools:

  - an app or installer must pass Gatekeeper's assessment (signed by a developer Apple
    knows, notarized, and unmodified since signing; cracked apps fail this);
  - a loose program must carry a valid Developer ID or Apple signature.

Prints what it found and exits 1 if anything should stop the release (the caller can
override with --force), 0 otherwise. Nothing here opens or runs the files' code.
Runs on macOS's own Python 3.9.
"""
from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

st_spec = importlib.util.spec_from_file_location(
    "st_guest", Path(__file__).resolve().parent.parent / "vm" / "st-guest.py")
assert st_spec and st_spec.loader
st = importlib.util.module_from_spec(st_spec)
st_spec.loader.exec_module(st)

MACHO = tuple(m for m, desc in st.EXEC_MAGIC if "macOS" in desc)
APP_BUNDLES = ("app",)
INSTALLERS = ("pkg", "mpkg")
TRUSTED_AUTHORITIES = ("Developer ID Application:", "Apple Mac OS Application Signing", "Software Signing",
                       "macOS Software Signing")
MAX_CODE_ITEMS = 500
TIMEOUT = 120


def tool(*cmd: str) -> tuple[int, str]:
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=TIMEOUT,
                             stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired) as e:
        return 99, str(e)
    return res.returncode, res.stdout + res.stderr


def field(output: str, name: str) -> str:
    return next((ln.split("=", 1)[1].strip() for ln in output.splitlines() if ln.startswith(name + "=")), "")


def gatekeeper(path: str, kind: str) -> tuple[bool, str]:
    """(vouched for, explanation) for an app bundle or an installer package."""
    rc, out = tool("/usr/sbin/spctl", "--assess", "--type", "install" if kind in INSTALLERS else "execute",
                   "-vv", path)
    if rc == 0 and "override=" not in out:
        return True, f"signed and notarized: {field(out, 'origin') or field(out, 'source') or 'accepted'}"
    if kind not in INSTALLERS:
        crc, cout = tool("/usr/bin/codesign", "--verify", "--deep", "--strict", path)
        if crc != 0:
            why = first_message(cout, path) or "no valid signature"
            if "not signed at all" in why:
                return False, "unsigned app: nobody vouches for it, and Gatekeeper will block it"
            return False, (f"its signature is broken ({why}): it was changed after the developer "
                           "signed it, which is what cracked apps look like")
        signed, detail = trusted_signature(path)
        if "override=" in out:  # Gatekeeper is turned off on this Mac: judge by the signature alone
            return signed, detail
        if not signed:
            return False, detail
        return False, f"{detail}, but Gatekeeper rejects it ({field(out, 'source') or 'not notarized'})"
    return False, f"Gatekeeper rejects this installer ({field(out, 'source') or first_message(out, path) or 'no details'})"


def first_message(output: str, path: str) -> str:
    """codesign/spctl print "<path>: <message>" first; just the message."""
    lines = output.strip().splitlines()
    return lines[0][len(path) + 2:] if lines and lines[0].startswith(path + ": ") else (lines[0] if lines else "")


def trusted_signature(path: str) -> tuple[bool, str]:
    rc, _ = tool("/usr/bin/codesign", "--verify", "--strict", path)
    if rc != 0:
        return False, "unsigned program (or its signature is broken): nobody vouches for it"
    _, info = tool("/usr/bin/codesign", "-dv", "--verbose=2", path)
    authority = field(info, "Authority")
    if authority.startswith(TRUSTED_AUTHORITIES):
        return True, f"signed by {authority}"
    if "Signature=adhoc" in info:
        return False, "only ad-hoc signed (no developer identity): nobody vouches for it"
    return False, f"signed by {authority or 'an unknown signer'}, which Apple doesn't vouch for"


def code_items(stage: Path) -> list[tuple[str, str]]:
    """(path relative to the stage, kind) for each app, installer, disk image and loose
    Mac program. Apps and bundled installers are checked whole, not file by file."""
    items: list[tuple[str, str]] = []
    for dirpath, dirs, names in os.walk(stage):
        rel_dir = Path(dirpath).relative_to(stage)
        for n in list(dirs):
            ext = st.ext_of(n + "/x")  # the folder's own bundle type, if it is one
            if ext in APP_BUNDLES or ext in INSTALLERS:
                items.append((str(rel_dir / n), ext))
                dirs.remove(n)
        for n in names:
            ext = st.ext_of(n)
            rel = str(rel_dir / n)
            if ext in INSTALLERS or ext == "dmg":
                items.append((rel, ext))
            elif ext != "class":  # Java classes share the universal-binary magic number
                try:
                    head = st.read_head(stage / rel, 8)
                except OSError:
                    continue
                if head.startswith(MACHO):
                    items.append((rel, "program"))
    return sorted(items)


def recheck(stage: Path, name: str) -> list[dict]:
    files = st.walk_files(stage)
    category = st.detect_category(files, name)
    findings = st.check_names(files, category, name, inner=True)
    for rel, _size in files:
        findings += st.sniff(rel, st.read_head(stage / rel), category)
    items = code_items(stage)
    if len(items) > MAX_CODE_ITEMS:
        return findings + [st.finding(st.DANGER, "", f"{len(items)} programs: too many to check signatures for")]
    for rel, kind in items:
        path = str(stage / rel)
        if kind == "dmg":
            # Mounting it would have the Mac's kernel parse an untrusted disk image. The
            # quarantine flag makes Gatekeeper check the apps inside when they're opened.
            rc, _ = tool("/usr/bin/codesign", "--verify", "--strict", path)
            signer = field(tool("/usr/bin/codesign", "-dv", "--verbose=2", path)[1], "Authority") if rc == 0 else ""
            findings.append(st.finding(st.INFO, rel, f"disk image {'signed by ' + signer if signer else 'is unsigned'}; "
                                                     "Gatekeeper checks the apps inside when you open them"))
            continue
        ok, why = gatekeeper(path, kind) if kind != "program" else trusted_signature(path)
        findings.append(st.finding(st.INFO if ok else st.WARN, rel, why, **({} if ok else {"unvouched": True})))
    return findings


def blocking(findings: list[dict]) -> list[dict]:
    return [f for f in findings if f["level"] >= st.DANGER or (f.get("unvouched") and f["level"] >= st.WARN)]


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    stage = Path(sys.argv[1])
    findings = recheck(stage, sys.argv[2])
    for f in sorted(findings, key=lambda f: -f["level"]):
        icon = "✖" if f in blocking(findings) else "·" if f["level"] == st.INFO else "⚠"
        where = f"{st.shown(f['path'])}: " if f["path"] else ""
        print(f"  {icon} {where}{st.shown(f['msg'])}", file=sys.stderr)
    return 1 if blocking(findings) else 0


if __name__ == "__main__":
    sys.exit(main())
