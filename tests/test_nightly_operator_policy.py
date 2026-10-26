"""Exercise the operator consumer's real shell/jq policy against nightly assets."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("bash") and shutil.which("jq"), "native bash and jq required")
class NightlyOperatorPolicy(unittest.TestCase):
    def shell(self, script, directory):
        return subprocess.run(["bash", "--noprofile", "--norc", "-euo", "pipefail", "-c", script],
                              cwd=directory, capture_output=True, text=True, timeout=20,
                              env={**os.environ, "POLICY_SCRIPT": str(ROOT / "scripts/nightly-release-assets.sh")})

    def test_consumer_matches_publisher_and_refuses_missing_proofs(self):
        signed = json.loads((ROOT / "release/nightly-assets.json").read_text())["signed_inputs"]
        checksums = set(signed) | {name + ".sigstore.json" for name in signed}
        proofs = {name + ".provenance.jsonl" for name in (
            "install.sh", "marty-deploy-linux-amd64", "prepared-selfhost-bundle.zip",
            "prepared-selfhost-images.json", "installer-inventory.json")}
        expected = checksums | proofs | {"RELEASE-SHA256SUMS"}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = self.shell('source "$POLICY_SCRIPT"; printf "%s\\n" "${NIGHTLY_RELEASE_ASSETS[@]}"', directory)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(set(result.stdout.splitlines()), expected)
            self.assertEqual(len(result.stdout.splitlines()), 44)
            response = dict(prerelease=True, draft=False,
                            assets=[dict(name=name, state="uploaded", size=1) for name in sorted(expected)])
            (root / "release.json").write_text(json.dumps(response))
            (root / "sums").write_text("".join("0" * 64 + "  " + name + "\n" for name in sorted(checksums)))
            check = 'source "$POLICY_SCRIPT"; nightly_release_require_remote_allowlist release.json; nightly_release_require_checksum_names sums'
            result = self.shell(check, directory)
            self.assertEqual(result.returncode, 0, result.stderr)
            response["assets"][0]["size"] = "invalid"
            (root / "release.json").write_text(json.dumps(response))
            self.assertNotEqual(self.shell(check, directory).returncode, 0)
            response["assets"][0]["size"] = 1
            response["assets"] = [entry for entry in response["assets"] if entry["name"] not in proofs]
            (root / "release.json").write_text(json.dumps(response))
            self.assertNotEqual(self.shell(check, directory).returncode, 0)


if __name__ == "__main__":
    unittest.main()
