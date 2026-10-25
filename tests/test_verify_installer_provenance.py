"""Verifier invocation and identity tests; mocked output is not crypto evidence."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import verify_installer_provenance as verifier


@pytest.fixture
def candidate(tmp_path):
    tmp_path.chmod(0o700)
    paths = {}
    for name in ("subject", "bundle", "gh", "cosign", "signature_bundle"):
        paths[name] = tmp_path / name
        paths[name].write_bytes(b"fixture, not authentic crypto material")
    args = dict(gh=paths["gh"], workflow=".github/workflows/nightly-release.yml",
                source_sha="a" * 40, run_id=42, run_attempt=2)
    certificate = {
        "issuer": verifier.ISSUER, "runnerEnvironment": "github-hosted",
        "sourceRepositoryURI": "https://github.com/ElevenID/marty-ui",
        "sourceRepositoryIdentifier": "1140864197", "sourceRepositoryDigest": "a" * 40,
        "sourceRepositoryRef": "refs/heads/main",
        "runInvocationURI": "https://github.com/ElevenID/marty-ui/actions/runs/42/attempts/2",
        "buildSignerURI": "https://github.com/ElevenID/marty-ui/.github/workflows/nightly-release.yml@refs/heads/main",
    }
    result = [{"attestation": {}, "verificationResult": {"signature": {"certificate": certificate}}}]
    return paths, args, result, certificate


def test_exact_verifier_arguments_and_optional_blob_signature(candidate):
    paths, args, result, _ = candidate
    calls = []

    def run(argv):
        calls.append(argv)
        return json.dumps(result) if len(calls) == 1 else "Verified OK"

    verifier.verify_subject(paths["subject"], paths["bundle"], **args,
                            cosign=paths["cosign"], signature_bundle=paths["signature_bundle"], runner=run)
    assert calls[0] == [str(paths["gh"]), "attestation", "verify", str(paths["subject"]),
                        "--bundle", str(paths["bundle"]), "--repo", "ElevenID/marty-ui",
                        "--signer-workflow", "ElevenID/marty-ui/.github/workflows/nightly-release.yml",
                        "--source-ref", "refs/heads/main", "--source-digest", "a" * 40,
                        "--deny-self-hosted-runners", "--predicate-type",
                        "https://slsa.dev/provenance/v1", "--format", "json"]
    assert calls[1] == [str(paths["cosign"]), "verify-blob", str(paths["subject"]),
                        "--bundle", str(paths["signature_bundle"]), "--certificate-identity",
                        "https://github.com/ElevenID/marty-ui/.github/workflows/nightly-release.yml@refs/heads/main",
                        "--certificate-oidc-issuer", verifier.ISSUER]


@pytest.mark.parametrize("field", ["issuer", "runnerEnvironment", "sourceRepositoryURI",
                                  "sourceRepositoryIdentifier", "sourceRepositoryDigest",
                                  "sourceRepositoryRef", "runInvocationURI", "buildSignerURI"])
@pytest.mark.parametrize("missing", [False, True])
def test_certificate_identity_must_match_and_be_present(candidate, field, missing):
    paths, args, result, cert = candidate
    if missing:
        cert.pop(field)
    else:
        cert[field] += "wrong"
    with pytest.raises(ValueError, match="identity"):
        verifier.verify_subject(paths["subject"], paths["bundle"], **args,
                                runner=lambda _: json.dumps(result))


@pytest.mark.parametrize("output", ["null", "{}", "[]", "[{},{}]", "[null]", "not json",
                                    '[{"attestation":{},"verificationResult":null}]',
                                    '{"a":1,"a":2}'])
def test_malformed_or_ambiguous_verifier_result_rejected(candidate, output):
    paths, args, _, _ = candidate
    with pytest.raises(ValueError):
        verifier.verify_subject(paths["subject"], paths["bundle"], **args, runner=lambda _: output)


@pytest.mark.parametrize("name,value", [("run_id", True), ("run_attempt", 0),
                                        ("source_sha", None), ("workflow", None),
                                        ("source_sha", "x" * 40), ("workflow", "../evil.yml"),
                                        ("gh", Path("gh"))])
def test_invalid_expected_identity_or_ambient_tool_refused(candidate, name, value):
    paths, args, _, _ = candidate
    args[name] = value
    with pytest.raises(ValueError):
        verifier.verify_subject(paths["subject"], paths["bundle"], **args,
                                runner=lambda _: pytest.fail("must not invoke verifier"))


def test_legacy_identity_conflict_refused(candidate):
    paths, args, result, cert = candidate
    cert["githubWorkflowSHA"] = "b" * 40
    with pytest.raises(ValueError):
        verifier.verify_subject(paths["subject"], paths["bundle"], **args,
                                runner=lambda _: json.dumps(result))


def test_blob_signature_cannot_be_silently_skipped(candidate):
    paths, args, _, _ = candidate
    with pytest.raises(ValueError, match="required together"):
        verifier.verify_subject(paths["subject"], paths["bundle"], **args,
                                signature_bundle=paths["signature_bundle"],
                                runner=lambda _: pytest.fail("must not invoke verifier"))


def test_missing_subject_refused(candidate):
    paths, args, _, _ = candidate
    with pytest.raises(ValueError, match="unavailable"):
        verifier.verify_subject(paths["subject"].with_name("absent"), paths["bundle"], **args,
                                runner=lambda _: pytest.fail("must not invoke verifier"))


def test_command_discards_ambient_credentials_and_overrides(monkeypatch):
    for key in ("GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN",
                "HTTPS_PROXY", "SIGSTORE_ROOT_FILE", "GH_CONFIG_DIR", "HOME"):
        monkeypatch.setenv(key, "private-sentinel")

    def run(argv, **kwargs):
        assert "private-sentinel" not in kwargs["env"].values()
        assert kwargs["env"]["GH_HOST"] == "github.com"
        assert Path(kwargs["env"]["GH_CONFIG_DIR"]).is_dir()
        assert kwargs["timeout"] == 120
        assert kwargs["check"] is False
        return subprocess.CompletedProcess(argv, 0, "[]", "")

    monkeypatch.setattr(verifier.subprocess, "run", run)
    assert verifier.command(["/absolute/gh", "attestation"]) == "[]"


@pytest.mark.parametrize("failure", ["exit", "timeout", "os"])
def test_verifier_failures_are_sanitized(monkeypatch, failure):
    def run(argv, **kwargs):
        if failure == "timeout":
            raise subprocess.TimeoutExpired("private-sentinel", 120)
        if failure == "os":
            raise OSError("private-sentinel")
        return subprocess.CompletedProcess(argv, 1, "private-sentinel", "private-sentinel")

    monkeypatch.setattr(verifier.subprocess, "run", run)
    with pytest.raises(ValueError, match="^installer provenance verifier failed$"):
        verifier.command(["/absolute/gh"])


@pytest.mark.skipif(os.name != "posix", reason="Linux privacy mode admission")
def test_nonprivate_staging_refused(candidate):
    paths, args, _, _ = candidate
    paths["subject"].parent.chmod(0o755)
    with pytest.raises(ValueError, match="private"):
        verifier.verify_subject(paths["subject"], paths["bundle"], **args,
                                runner=lambda _: pytest.fail("must not invoke verifier"))
