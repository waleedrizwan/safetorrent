"""The Mac's own check of a copy from the VM (host/recheck.py), with macOS's real
code-signing tools where the test needs them."""
import importlib.util
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("recheck", ROOT / "host" / "recheck.py")
rc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rc)
st = rc.st
MB = 1024**2
PE = b"MZ\x90\x00" + b"\0" * 60
MKV = b"\x1a\x45\xdf\xa3" + b"\0" * 60
ON_MAC = sys.platform == "darwin"


class Base(unittest.TestCase):
    def setUp(self):
        self.stage = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.stage, ignore_errors=True)

    def put(self, rel, data=b"x"):
        p = self.stage / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return p

    def blocked(self, name="Show"):
        return [(f["path"], f["msg"]) for f in rc.blocking(rc.recheck(self.stage, name))]


class Rules(Base):
    def test_clean_show_passes(self):
        self.put("Show/ep1.mkv", MKV)
        self.put("Show/ep1.srt", b"1\n00:00:01,000 --> 00:00:02,000\nhi\n")
        self.assertEqual(self.blocked(), [])

    def test_program_in_a_show_is_caught_without_asking_the_vm(self):
        self.put("Show/ep1.mkv", MKV)
        self.put("Show/Codec_Installer.exe", PE)
        self.assertEqual([p for p, _ in self.blocked()], ["Show/Codec_Installer.exe"])

    def test_disguised_program_is_caught(self):
        self.put("Show/ep1.mkv", PE)
        self.assertEqual([p for p, _ in self.blocked()], ["Show/ep1.mkv"])

    def test_windows_program_in_software_isnt_held_here(self):
        self.put("Tool/setup.exe", PE)  # the VM's VirusTotal check covers it; macOS can't judge its signature
        self.assertEqual(self.blocked("Tool"), [])


class CodeItems(Base):
    def test_finds_apps_installers_images_and_loose_mac_programs(self):
        self.put("T/A.app/Contents/MacOS/A", b"\xcf\xfa\xed\xfe")
        self.put("T/Inst.pkg", b"xar!")
        self.put("T/Disk.dmg", b"x")
        self.put("T/bin/tool", b"\xcf\xfa\xed\xfe")
        self.put("T/lib/Thing.class", b"\xca\xfe\xba\xbe")
        self.put("T/readme.txt", b"hi")
        self.assertEqual(rc.code_items(self.stage), [("T/A.app", "app"), ("T/Disk.dmg", "dmg"),
                                                      ("T/Inst.pkg", "pkg"), ("T/bin/tool", "program")])

    def test_disk_images_are_never_held(self):
        self.put("T/Disk.dmg", b"not really a disk image")
        with mock.patch.object(rc, "tool", return_value=(1, "")):
            found = rc.recheck(self.stage, "T")
        self.assertEqual(rc.blocking(found), [])
        self.assertIn("Gatekeeper checks the apps inside", " ".join(f["msg"] for f in found))

    def test_gatekeeper_accepted_app_is_vouched(self):
        answers = {"spctl": (0, "x.app: accepted\nsource=Notarized Developer ID\norigin=Developer ID Application: A (T)\n")}
        with mock.patch.object(rc, "tool", side_effect=lambda *cmd: answers[Path(cmd[0]).name]):
            ok, why = rc.gatekeeper("/s/x.app", "app")
        self.assertTrue(ok)
        self.assertIn("Developer ID Application: A", why)

    def test_gatekeeper_turned_off_falls_back_to_the_signature(self):
        def tool(*cmd):
            if cmd[0].endswith("spctl"):
                return 0, "x.app: accepted\noverride=security disabled\n"
            if "-dv" in cmd:
                return 0, "Signature=adhoc\n"
            return 0, ""
        with mock.patch.object(rc, "tool", side_effect=tool):
            ok, why = rc.gatekeeper("/s/x.app", "app")
        self.assertFalse(ok)
        self.assertIn("ad-hoc", why)


@unittest.skipUnless(ON_MAC, "needs macOS's codesign and spctl")
class RealSignatures(Base):
    def app(self, sign=True):
        app = self.stage / "T" / "A.app"
        # A copy of /bin/ls would carry Apple's signature along; a script carries none.
        self.put("T/A.app/Contents/MacOS/A", b"#!/bin/sh\necho hi\n").chmod(0o755)
        self.put("T/A.app/Contents/Info.plist", b'<?xml version="1.0"?><plist version="1.0"><dict>'
                 b"<key>CFBundleExecutable</key><string>A</string><key>CFBundleIdentifier</key>"
                 b"<string>test.a</string></dict></plist>")
        if sign:
            subprocess.run(["codesign", "-f", "-s", "-", str(app)], check=True, capture_output=True)
        return app

    def held(self):
        return {p: msg for p, msg in self.blocked("T")}

    def test_unsigned_app_is_held(self):
        self.app(sign=False)
        self.assertIn("unsigned app", self.held()["T/A.app"])

    def test_ad_hoc_signed_app_is_held(self):
        self.app()
        self.assertIn("ad-hoc", self.held()["T/A.app"])

    def test_app_changed_after_signing_is_held_as_tampered(self):
        app = self.app()
        with open(app / "Contents" / "Info.plist", "ab") as fh:
            fh.write(b"\n")
        self.assertIn("changed after the developer signed it", self.held()["T/A.app"])

    def test_apple_signed_program_is_vouched(self):
        self.put("T/ls", Path("/bin/ls").read_bytes())
        self.assertEqual(self.held(), {})
        self.assertIn("Software Signing", " ".join(f["msg"] for f in rc.recheck(self.stage, "T")))

    def test_ad_hoc_signed_program_is_held(self):
        p = self.put("T/tool", Path("/bin/ls").read_bytes())
        subprocess.run(["codesign", "-f", "-s", "-", str(p)], check=True, capture_output=True)
        self.assertIn("ad-hoc", self.held()["T/tool"])

    def test_runs_inside_the_release_sandbox(self):
        self.app(sign=False)
        self.put("T/ls", Path("/bin/ls").read_bytes())
        stage = str(self.stage.resolve())
        res = subprocess.run(["/usr/bin/sandbox-exec", "-f", str(ROOT / "host" / "receive.sb"), "-D", f"STAGE={stage}",
                              "/usr/bin/python3", "-I", str(ROOT / "host" / "recheck.py"), stage, "T"],
                             capture_output=True, text=True, timeout=120)
        self.assertEqual(res.returncode, 1, res.stderr)
        self.assertIn("✖ T/A.app: unsigned app", res.stderr)
        self.assertIn("· T/ls: signed by", res.stderr)


if __name__ == "__main__":
    unittest.main()
