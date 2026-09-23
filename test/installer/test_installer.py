"""Run only fixture binaries in isolated homes; never install a real agent or service."""
import io
import hashlib
import re
import os
from pathlib import Path
import platform
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[2]


class InstallerTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="agentjail-installer-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.home = self.base / "home"
        self.home.mkdir()
        self.bin = self.base / "tools"
        self.bin.mkdir()
        self.assets = self.base / "assets"
        self.assets.mkdir()
        arch = {"aarch64": "arm64", "x86_64": "amd64"}.get(platform.machine(), platform.machine())
        self.archive = self.assets / f"agentjail-v0.0.0-{platform.system().lower()}-{arch}.tar.gz"
        with tarfile.open(self.archive, "w:gz") as tar:
            for name in ["agentjail", "agentjail-hook"]:
                data = b'#!/bin/sh\nprintf "%s\\n" "$*" >> "$HOME/executed"\nexit "${FIXTURE_INSTALL_STATUS:-0}"\n'
                entry = tarfile.TarInfo(name)
                entry.mode = 0o755
                entry.size = len(data)
                tar.addfile(entry, io.BytesIO(data))
        self.env = {
            "HOME": str(self.home), "PATH": str(self.bin) + ":/usr/bin:/bin:/usr/sbin:/sbin",
            "SHELL": "/bin/sh", "AGENTJAIL_VERSION": "v0.0.0",
            "AGENTJAIL_ASSUME_YES": "1", "LOCAL_TARBALL": str(self.archive),
            "TMPDIR": str(self.base), "LANG": "C", "ASSETS": str(self.assets),
        }
        self.script = ROOT / "install.sh"

    def install(self):
        return subprocess.run(["/bin/sh", str(self.script)], env=self.env, text=True, capture_output=True, timeout=20)

    def assert_ok(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_partial_failure_preserves_path_and_exit(self):
        self.env["FIXTURE_INSTALL_STATUS"] = "17"
        result = self.install()
        self.assertEqual(result.returncode, 17, result.stdout + result.stderr)
        self.assertIn("setup is incomplete", result.stderr)
        self.assertNotIn("hook is active", result.stdout)
        self.assertNotIn("setup completed", result.stdout)
        self.assertTrue((self.home / ".agentjail/env").exists())
        self.assertIn("managed environment", (self.home / ".profile").read_text())

    def test_custom_directory_is_literal_and_activation_is_idempotent(self):
        # Shell metacharacters must remain literal directory-name bytes.
        custom = self.home / "custom ' $(touch injected) `touch injected` \\ [x]"
        self.env["AGENTJAIL_HOME"] = str(custom)
        self.assert_ok(self.install())
        rc = self.home / ".profile"
        self.assert_ok(self.install())
        self.assertEqual(rc.read_text().count("# added by agentjail installer"), 1)
        result = subprocess.run(["sh", "-c", '. "$HOME/.profile"; . "$HOME/.profile"; printf "%s" "$PATH"'], env=self.env, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.split(":"), [str(custom / "bin")] + self.env["PATH"].split(":"))
        self.assertFalse((ROOT / "injected").exists())
        self.assertFalse((self.home / "injected").exists())

    def test_legacy_path_is_repaired_and_user_lines_preserved(self):
        rc = self.home / ".profile"
        rc.write_text('# user before\n# added by agentjail installer\nexport PATH="$HOME/.agentjail/bin:$PATH"\n# user after\n')
        self.env["AGENTJAIL_HOME"] = str(self.home / "other")
        self.assert_ok(self.install())
        content = rc.read_text()
        self.assertIn("# user before\n# user after", content)
        self.assertEqual(content.count("# added by agentjail installer"), 1)
        self.assertNotIn('export PATH="$HOME/.agentjail/bin', content)

    def test_symlinked_profile_retains_target_permissions_and_user_content(self):
        target = self.home / "dot files/profile"
        target.parent.mkdir()
        target.write_text("# user configuration\nexport USER_SETTING=retained\n")
        target.chmod(0o640)
        rc = self.home / ".profile"
        rc.symlink_to("dot files/profile")
        self.assert_ok(self.install())
        self.assertTrue(rc.is_symlink())
        self.assertEqual(target.stat().st_mode & 0o777, 0o640)
        self.assertIn("export USER_SETTING=retained", target.read_text())
        self.assertEqual(target.read_text(), rc.read_text())
        self.assertFalse(list(target.parent.glob("*.agentjail.*")))

    def test_path_opt_out_does_not_claim_profile_updated(self):
        self.env["AGENTJAIL_NO_MODIFY_PATH"] = "1"
        result = self.install()
        self.assert_ok(result)
        self.assertFalse((self.home / ".profile").exists())
        self.assertNotIn("profile was updated", result.stdout)

    def test_fish_activation_and_config(self):
        fish = shutil.which("fish")
        if not fish:
            self.skipTest("fish required; installer CI installs it")
        self.env["SHELL"] = fish
        custom = self.home / "fish ' \\ $() `literal` [x]"
        self.env["AGENTJAIL_HOME"] = str(custom)
        result = self.install()
        self.assert_ok(result)
        self.assertIn("env.fish", result.stdout)
        self.assert_ok(self.install())
        rc = self.home / ".config/fish/config.fish"
        self.assertEqual(rc.read_text().count("# added by agentjail installer"), 1)
        result = subprocess.run([fish, "--no-config", "-c", 'source "$HOME/.config/fish/config.fish"; source "$HOME/.config/fish/config.fish"; printf "%s\\n" $PATH'], env=self.env, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), [str(custom / "bin")] + self.env["PATH"].split(":"))

    def fake_curl(self):
        script = self.bin / "curl"
        script.write_text("""#!/bin/sh
printf '%s\\n' "$*" >> "$HOME/curl-args"
out=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out=$2; shift 2 ;;
    https://*) url=$1; shift ;;
    *) shift ;;
  esac
done
if [ "${FIXTURE_CURL_FAIL:-0}" = "1" ]; then exit 28; fi
case "$url" in
  */v1/latest) printf '%s\\n' '{"version":"v0.0.0"}' ;;
  *) cp "$ASSETS/${url##*/}" "$out" ;;
esac
""")
        script.chmod(0o755)

    def test_network_failure_has_deadlines_and_recovery(self):
        self.fake_curl()
        del self.env["LOCAL_TARBALL"]
        self.env["AGENTJAIL_VERSION"] = "latest"
        self.env["FIXTURE_CURL_FAIL"] = "1"
        # A verifier seam is supplied so this failure tests network behavior.
        verifier = self.bin / "minisign"
        verifier.write_text("#!/bin/sh\nexit 0\n")
        verifier.chmod(0o755)
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("release lookup failed", result.stderr)
        args = (self.home / "curl-args").read_text()
        for flag in ["--connect-timeout 10", "--max-time 120", "--retry 2", "--retry-max-time 240"]:
            self.assertIn(flag, args)
        self.assertFalse((self.home / "executed").exists())

    def prepare_signed_release(self):
        minisign = shutil.which("minisign")
        if not minisign:
            self.skipTest("minisign required; installer CI installs it")
        (self.bin / "minisign").symlink_to(minisign)
        self.fake_curl()
        del self.env["LOCAL_TARBALL"]
        manifest = self.assets / "SHA256SUMS"
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        manifest.write_text(f"{digest}  {self.archive.name}\n")
        public = self.base / "fixture.pub"
        private = self.base / "fixture.key"
        for args in [
            ["-G", "-W", "-p", str(public), "-s", str(private)],
            ["-S", "-s", str(private), "-m", str(manifest), "-q"],
        ]:
            result = subprocess.run([minisign] + args, text=True, capture_output=True, env=self.env)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        script = (ROOT / "install.sh").read_text()
        script, replacements = re.subn(r"SIGNING_PUBLIC_KEY='[^']+'", "SIGNING_PUBLIC_KEY='" + public.read_text().splitlines()[1] + "'", script)
        self.assertEqual(replacements, 1)
        self.script = self.base / "fixture-install.sh"
        self.script.write_text(script)
        tar = shutil.which("tar")
        spy = self.bin / "tar"
        spy.write_text('#!/bin/sh\nprintf extracted >> "$HOME/extracted"\nexec ' + shlex.quote(tar) + ' "$@"\n')
        spy.chmod(0o755)

    def assert_payload_untouched(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.home / "extracted").exists(), "untrusted payload extracted")
        self.assertFalse((self.home / "executed").exists(), "untrusted payload executed")
        self.assertFalse((self.home / ".agentjail/bin").exists(), "untrusted payload installed")

    def test_signed_release_verified_before_install(self):
        self.prepare_signed_release()
        result = self.install()
        self.assert_ok(result)
        self.assertIn("release signature verified", result.stdout)
        self.assertTrue((self.home / "executed").exists())
        self.assertTrue((self.home / "extracted").exists())
        requests = (self.home / "curl-args").read_text().splitlines()
        self.assertEqual(len(requests), 3)
        for request in requests:
            self.assertIn("--connect-timeout 10 --max-time 120 --retry 2 --retry-max-time 240", request)

    def test_modified_manifest_is_rejected_before_extraction(self):
        self.prepare_signed_release()
        manifest = self.assets / "SHA256SUMS"
        manifest.write_text(manifest.read_text() + "# tampered\n")
        result = self.install()
        self.assert_payload_untouched(result)
        self.assertIn("signature verification failed", result.stderr)

    def test_missing_signature_is_rejected_before_extraction(self):
        self.prepare_signed_release()
        (self.assets / "SHA256SUMS.minisig").unlink()
        result = self.install()
        self.assert_payload_untouched(result)
        self.assertIn("signature unavailable", result.stderr)

    def test_modified_archive_is_rejected_before_extraction(self):
        self.prepare_signed_release()
        self.archive.write_bytes(self.archive.read_bytes() + b"tampered")
        result = self.install()
        self.assert_payload_untouched(result)
        self.assertIn("SHA256 mismatch", result.stderr)

    def test_missing_verifier_has_no_unsigned_fallback(self):
        del self.env["LOCAL_TARBALL"]
        self.env["PATH"] = str(self.bin)
        result = self.install()
        self.assert_payload_untouched(result)
        self.assertIn("minisign is required", result.stderr)
        self.assertFalse((self.home / "curl-args").exists())

    def test_installer_key_matches_release_build_key(self):
        installer_key = re.search(r"SIGNING_PUBLIC_KEY='([^']+)'", (ROOT / "install.sh").read_text()).group(1)
        release = (ROOT / ".github/workflows/release.yml").read_text()
        build_key = re.search(r"SigningPubKey=([^ ]+)", release).group(1)
        self.assertEqual(installer_key, build_key)


if __name__ == "__main__":
    unittest.main()
