"""Mock verifier tests check orchestration, not genuine cryptographic acceptance."""
import json
import os
from pathlib import Path
import sys
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_candidate_authorize as a
import installer_release as r

@pytest.fixture
def inputs(tmp_path):
    tmp_path.chmod(0o700)
    for name in r.ARTIFACTS:
        (tmp_path / name).write_bytes(b"synthetic " + name.encode())
    (tmp_path / "prepared-selfhost-images.json").write_bytes(r.encode(dict(
        schema="marty.selfhost-image-lock/v1", release="marty-ui@1.2.3",
        services={"gateway":"ghcr.io/elevenid/services@sha256:"+"a"*64},
        openbao_didcomm_image="ghcr.io/elevenid/plugin@sha256:"+"b"*64)))
    build=dict(source_sha="a"*40, release_tag="v1.2.3", build_run_id=42, build_run_attempt=2)
    (tmp_path / "installer-inventory.json").write_bytes(r.encode(r.inventory(tmp_path, expected_services={"gateway"}, **build)))
    for name in ["installer-inventory.json", *r.ARTIFACTS]:
        for suffix in (".provenance.jsonl", ".sigstore.json"):
            (tmp_path / (name+suffix)).write_bytes(b"synthetic proof")
    for name in ("gh", "cosign"):
        (tmp_path / name).write_bytes(b"synthetic tool")
    run=dict(repository=dict(full_name=r.REPOSITORY), path=r.acceptance.WORKFLOW,
        head_sha="c"*40, head_branch="main", event="workflow_dispatch", status="in_progress",
        conclusion=None, id=99, run_attempt=3)
    (tmp_path / "run.json").write_bytes(r.encode(run))
    cert=dict(issuer=a.provenance.ISSUER, runnerEnvironment="github-hosted",
        sourceRepositoryURI="https://github.com/ElevenID/marty-ui", sourceRepositoryIdentifier="1140864197",
        sourceRepositoryDigest="a"*40, sourceRepositoryRef="refs/heads/main",
        runInvocationURI="https://github.com/ElevenID/marty-ui/actions/runs/42/attempts/2",
        buildSignerURI="https://github.com/ElevenID/marty-ui/.github/workflows/cd.yml@refs/heads/main")
    calls=[]
    def runner(argv):
        calls.append(argv)
        return json.dumps([dict(attestation={}, verificationResult=dict(signature=dict(certificate=cert)))]) if argv[1]=="attestation" else "verified"
    options=dict(assets=tmp_path, acceptance_run=tmp_path/"run.json", gh=tmp_path/"gh", cosign=tmp_path/"cosign",
        **build, harness_source_sha="c"*40, run_id=99, run_attempt=3, output=tmp_path/"authorization.json",
        clock=lambda:100000, runner=runner)
    return options,calls,cert

@pytest.mark.skipif(os.name != "posix", reason="Linux exclusive output contract")
def test_verifies_all_five_before_exclusive_unsigned_write(inputs):
    options,calls,_=inputs
    record=a.authorize(**options)
    assert len(calls)==10 and all(c[0]==str(options["gh"]) for c in calls[::2])
    assert all(c[1]=="verify-blob" for c in calls[1::2])
    assert r.decode(options["output"].read_bytes())==record
    assert record["phase"]=="staged" and record["issued_at"]==100000
    assert options["output"].stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError): a.authorize(**options)


@pytest.mark.skipif(os.name != "posix", reason="Linux exclusive output contract")
def test_published_authorization_uses_same_exact_proof_checks(inputs):
    options,calls,_=inputs
    options['phase']='published'
    record=a.authorize(**options)
    assert record['phase']=='published' and r.decode(options['output'].read_bytes())==record
    assert len(calls)==10

@pytest.mark.parametrize("field,value", [("run_id",100),("run_attempt",4),("harness_source_sha","d"*40),
    ("build_run_attempt",3),("source_sha","b"*40)])
def test_wrong_independent_identity_writes_nothing(inputs,field,value):
    options,_,_=inputs; options[field]=value
    with pytest.raises(ValueError): a.authorize(**options)
    assert not options["output"].exists()

@pytest.mark.parametrize("field", ["runInvocationURI","buildSignerURI","sourceRepositoryDigest","issuer"])
def test_wrong_crypto_identity_writes_nothing(inputs,field):
    options,_,cert=inputs; cert[field]="wrong"
    with pytest.raises(ValueError): a.authorize(**options)
    assert not options["output"].exists()

def test_missing_proof_and_payload_tamper_refuse(inputs):
    options,_,_=inputs
    path=options["assets"] / "install.sh.provenance.jsonl"
    path.unlink()
    with pytest.raises(ValueError): a.authorize(**options)
    path.write_bytes(b"synthetic proof")
    (options["assets"] / "install.sh").write_bytes(b"tampered")
    with pytest.raises(ValueError): a.authorize(**options)
    assert not options["output"].exists()

def test_mutation_during_verification_refused(inputs):
    options,_,_=inputs; original=options["runner"]
    def changed(argv):
        result=original(argv)
        (options["assets"] / "install.sh").write_bytes(b"tampered")
        return result
    options["runner"]=changed
    with pytest.raises(ValueError): a.authorize(**options)
    assert not options["output"].exists()

@pytest.mark.skipif(os.name != "posix", reason="Linux nofollow durable output")
def test_partial_and_symlink_output_are_never_replaced(tmp_path):
    tmp_path.chmod(0o700); output=tmp_path/"out"
    output.write_bytes(b"")
    with pytest.raises(FileExistsError): a.write_exclusive(output,b"new")
    output.unlink(); output.symlink_to(tmp_path/"victim")
    with pytest.raises(FileExistsError): a.write_exclusive(output,b"new")
    assert not (tmp_path/"victim").exists()

@pytest.mark.skipif(os.name != "posix", reason="Linux exclusive output")
def test_issuance_uses_clock_after_all_verifications(inputs):
    options,calls,_=inputs
    options["clock"]=lambda:100000+len(calls)*10
    record=a.authorize(**options)
    assert record["issued_at"]==100100
    assert record["expires_at"]==103700

@pytest.mark.skipif(os.name != "posix", reason="Linux durable output")
def test_failed_fsync_preserves_unreusable_partial_output(tmp_path,monkeypatch):
    tmp_path.chmod(0o700); output=tmp_path/"out"
    def fail(_): raise OSError("synthetic fsync failure")
    monkeypatch.setattr(a.os,"fsync",fail)
    with pytest.raises(OSError): a.write_exclusive(output,b"new")
    assert output.is_file() and output.read_bytes()==b""
    with pytest.raises(FileExistsError): a.write_exclusive(output,b"replacement")
