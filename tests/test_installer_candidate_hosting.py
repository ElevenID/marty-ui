"""Versioned authority/file contracts; fixtures are not signed acceptance."""
import copy
import json
import os
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_candidate_hosting as hosting
import installer_release as release
import installer_candidate_public_bootstrap as bootstrap

FIXTURES = Path(__file__).resolve().parents[1] / "rust/crates/deployment-catalog/tests/fixtures"


def configuration(source="managed-ca", environment="production"):
    tls = dict(termination="marty-keyless", certificate_source=source)
    if source == "acme":
        tls.update(http01_host_port=18080, acme=dict(environment=environment,
                   directory_url=hosting.DIRECTORIES[environment], profile="shortlived",
                   terms_url="https://letsencrypt.org/documents/fixture-terms.pdf", terms_agreed=True))
    return dict(schema="elevenid.installation-hosting/v1", mode="direct",
                public_origin="https://marty.example.com", public_entry_origin="https://192.0.2.20",
                listener=dict(bind_address="0.0.0.0", port=18443), tls=tls)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def test_shared_python_native_hosting_context_and_exact_raw_binding():
    cases = json.loads((FIXTURES / "installer-candidate-hosting-v2.json").read_text())
    for case in cases:
        raw = case["hosting_input"].encode()
        roots = None if case["staging_roots"] is None else case["staging_roots"].encode()
        binding = hosting.from_bytes(raw, staging_roots=roots)
        assert bootstrap._hosting_from_bytes(raw, staging_roots=roots) == binding
        auth = release.decode(case["authorization"].encode())
        assert binding == auth["hosting"]
        context = release.candidate_context(auth)
        assert release.candidate_context_sha256(context) == case["context_sha256"]
        receipt = release.bind_controller_consumption(case["controller"].encode(),
            case["authorization"].encode(), case["inventory"].encode(), expected=context,
            expected_engine="test-engine-12345678", now=case["now"])
        assert receipt["hosting"] == binding
        with pytest.raises(ValueError):
            hosting.require_bytes(binding, raw + b" ", staging_roots=roots)


@pytest.mark.parametrize("mutation", ["agreement", "duplicate", "unknown", "ip-identity", "wildcard",
    "oversize", "environment", "profile", "boolean-port", "connector", "noncanonical", "missing-trust",
    "extra-trust", "prod-trust"])
def test_closed_hosting_authority_refuses_unbound_or_unsupported_input(mutation):
    value = configuration("acme")
    roots = None
    if mutation == "agreement": value["tls"]["acme"]["terms_agreed"] = False
    elif mutation == "unknown": value["shell"] = "ignored"
    elif mutation == "ip-identity": value["public_origin"] = "https://192.0.2.1"
    elif mutation == "wildcard": value["public_entry_origin"] = "https://*.example.com"
    elif mutation == "environment": value["tls"]["acme"]["environment"] = "staging"
    elif mutation == "profile": value["tls"]["acme"]["profile"] = "other"
    elif mutation == "boolean-port": value["listener"]["port"] = True
    elif mutation == "connector": value["connector"] = dict(kind="cloudflare-tunnel", token_file="/private/token")
    elif mutation == "noncanonical": value["public_origin"] = "https://Marty.example.com"
    elif mutation == "missing-trust": value = configuration("acme", "staging")
    elif mutation == "extra-trust": value, roots = configuration(), b"unbound roots"
    elif mutation == "prod-trust": roots = b"unbound roots"
    raw = encoded(value)
    if mutation == "duplicate": raw = raw.replace(b'"mode": "direct"', b'"mode": "direct", "mode": "direct"')
    if mutation == "oversize": raw += b" " * hosting.MAX_BYTES
    with pytest.raises(ValueError): hosting.from_bytes(raw, staging_roots=roots)
    with pytest.raises(ValueError): bootstrap._hosting_from_bytes(raw, staging_roots=roots)


@pytest.mark.parametrize("mutation", ["v1-added", "v1-null", "v2-missing", "mismatched-pair", "summary", "trust", "uuid"])
def test_versioned_grants_refuse_scope_or_receipt_substitution(mutation):
    case = json.loads((FIXTURES / "installer-candidate-hosting-v2.json").read_text())[1]
    auth, receipt = release.decode(case["authorization"].encode()), release.decode(case["controller"].encode())
    expected = release.candidate_context(auth)
    if mutation == "v1-added": auth["schema"] = release.CANDIDATE_SCHEMA
    elif mutation == "v1-null": auth.update(schema=release.CANDIDATE_SCHEMA, hosting=None)
    elif mutation == "v2-missing": auth.pop("hosting")
    elif mutation == "mismatched-pair":
        receipt.pop("hosting")
        receipt["schema"] = release.CONTROLLER_SCHEMA
    elif mutation == "summary": auth["hosting"]["public_entry_origin"] = "https://192.0.2.21"
    elif mutation == "trust": auth["hosting"]["staging_trust"] = dict(sha256="a" * 64, size_bytes=12)
    elif mutation == "uuid": receipt["installation_id"] = "12345678-1234-1234-8234-123456789abc"
    with pytest.raises(ValueError):
        release.bind_controller_consumption(release.encode(receipt), release.encode(auth),
            case["inventory"].encode(), expected=expected, expected_engine="test-engine-12345678", now=case["now"])


@pytest.mark.parametrize("mutation", ["same-bytes", "changed", "symlink", "hardlink", "mode", "parent"])
def test_private_input_retains_inode_and_directory_across_work(tmp_path, mutation):
    tmp_path.chmod(0o700)
    directory = tmp_path / "input"
    directory.mkdir(mode=0o700)
    path = directory / hosting.NAME
    path.write_bytes(encoded(configuration()))
    path.chmod(0o600)
    with hosting.HeldInput(path) as held:
        held.check()
        if mutation == "same-bytes":
            path.rename(directory / "old")
            path.write_bytes(held.raw)
            path.chmod(0o600)
        elif mutation == "changed": path.write_bytes(held.raw + b" ")
        elif mutation == "symlink":
            path.rename(directory / "old")
            path.symlink_to("old")
        elif mutation == "hardlink": os.link(path, directory / "alias")
        elif mutation == "mode": path.chmod(0o644)
        elif mutation == "parent":
            directory.rename(tmp_path / "old")
            directory.mkdir(mode=0o700)
        with pytest.raises((ValueError, OSError)): held.check()


def test_v1_rejects_both_fixed_hosting_files_even_as_symlinks(tmp_path):
    tmp_path.chmod(0o700)
    assert hosting.check_file({}, tmp_path) == {}
    for name in (hosting.NAME, hosting.ROOTS_NAME):
        path = tmp_path / name
        path.symlink_to("missing")
        with pytest.raises(ValueError): hosting.check_file({}, tmp_path)
        path.unlink()
