"""Refusal tests for existing Secret custody and untrusted bootstrap outputs."""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import zipfile

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import bootstrap_kubernetes_openbao as bootstrap


pytestmark = pytest.mark.skipif(os.name != "posix", reason="Linux bootstrap file contract")


class ExistingNamespace:
    namespace = "marty-test"

    def __init__(self, state: Path, secrets: set[str]):
        self.state = state
        self.secrets = secrets
        self.inspected_secrets: set[str] = set()
        self.mutations = []

    def kubectl(self, operation, *args, **kwargs):
        if operation == "namespace workload inspection":
            return b'{"items":[]}'
        if operation == "namespace Secret inspection":
            assert args[:2] == ("get", "secret")
            assert args[-3:] == ("--ignore-not-found", "-o", "name")
            self.inspected_secrets.update(args[2:-3])
            return "\n".join("secret/" + name for name in sorted(
                self.secrets & self.inspected_secrets)).encode()
        if operation in {"namespace inspection", "namespace identity"}:
            return b'{"metadata":{"uid":"namespace-fixture"}}'
        raise AssertionError("unexpected operation")

    def create(self, resource):
        self.mutations.append(resource)


@pytest.mark.parametrize("name", [
    "org-workload-tls", "issuance-server-kms", "notification-workload-tls",
    "notification-tls-kms", "marty-operator", "marty-openbao-seal",
])
def test_existing_destination_secret_refused_before_mutation(tmp_path, name):
    transport = ExistingNamespace(tmp_path, {name})
    with pytest.raises(bootstrap.BootstrapError, match="already contains Marty credentials"):
        bootstrap.prepare_namespace(transport, "fixture-bootstrap")
    assert name in transport.inspected_secrets
    assert transport.mutations == []
    assert list(tmp_path.iterdir()) == []


def test_existing_ingress_and_registry_secrets_are_preserved(tmp_path):
    transport = ExistingNamespace(tmp_path, {"marty-ingress-tls", "registry-pull"})
    bootstrap.prepare_namespace(transport, "fixture-bootstrap")
    assert transport.mutations == []
    assert transport.secrets == {"marty-ingress-tls", "registry-pull"}
    assert json.loads((tmp_path / "namespace.json").read_bytes())["uid"] == "namespace-fixture"


def archive_bytes(entries):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as archive:
        for name, kind in entries:
            entry = tarfile.TarInfo(name)
            if kind == "symlink":
                entry.type = tarfile.SYMTYPE
                entry.linkname = "/private/operator/root.token"
                archive.addfile(entry)
            else:
                contents = b"synthetic public certificate or scoped credential"
                entry.size = len(contents)
                archive.addfile(entry, io.BytesIO(contents))
    return raw.getvalue()


def valid_entries():
    return [("./" + name, "file") for name in sorted(
        set(bootstrap.SELFHOST_TLS_FILES) | {"selfhost-tls-kms-roles.json"})]


@pytest.mark.parametrize("invalid", ["unexpected", "duplicate", "symlink", "incomplete", "traversal"])
def test_tls_archive_invalid_inventory_is_rejected(tmp_path, invalid):
    entries = valid_entries()
    if invalid == "unexpected":
        entries.append(("./root.token", "file"))
    elif invalid == "duplicate":
        entries.append(entries[0])
    elif invalid == "symlink":
        entries[0] = (entries[0][0], "symlink")
    elif invalid == "incomplete":
        entries.pop()
    else:
        entries[0] = ("../escaped.token", "file")
    output = tmp_path / "staging"
    output.mkdir()
    with pytest.raises(bootstrap.BootstrapError, match="inventory differs|incomplete"):
        bootstrap.take_tls_outputs(archive_bytes(entries), output)
    assert not (tmp_path / "escaped.token").exists()
    assert not (tmp_path / "credentials").exists()


def test_complete_tls_archive_is_accepted_only_into_staging(tmp_path):
    bootstrap.take_tls_outputs(archive_bytes(valid_entries()), tmp_path)
    assert {path.name for path in tmp_path.iterdir()} == {
        name.removeprefix("./") for name, _ in valid_entries()}
    assert all(path.is_file() and not path.is_symlink() for path in tmp_path.iterdir())


def write_private(path, contents):
    path.write_bytes(contents)
    path.chmod(0o600)


@pytest.fixture
def authenticated_inputs(tmp_path):
    operator = b"synthetic signed operator; never executed by this test"
    script = b"#!/bin/sh\nexit 0\n"
    bundle = io.BytesIO()
    with zipfile.ZipFile(bundle, "w") as archive:
        archive.writestr("selfhost-prepared/docker/openbao-init.sh", script)
    bundle = bundle.getvalue()
    inventory = {"artifacts": [
        {"name": "marty-deploy-linux-amd64", "sha256": hashlib.sha256(operator).hexdigest()},
        {"name": "prepared-selfhost-bundle.zip", "sha256": hashlib.sha256(bundle).hexdigest()},
    ]}
    raw = json.dumps(inventory).encode()
    write_private(tmp_path / "installer-inventory.json", raw)
    write_private(tmp_path / "marty-deploy-linux-amd64", operator)
    write_private(tmp_path / "prepared-selfhost-bundle.zip", bundle)
    identity = {"inventorySha256": hashlib.sha256(raw).hexdigest(),
                "operatorSha256": hashlib.sha256(operator).hexdigest()}
    return tmp_path, identity, operator, script


@pytest.mark.parametrize("changed", ["inventory", "operator", "bundle"])
def test_staged_artifact_changes_cannot_replace_authenticated_bytes(authenticated_inputs, changed):
    assets, identity, _, _ = authenticated_inputs
    if changed == "inventory":
        # A replacement payload and matching replacement inventory are still
        # outside the original in-process authentication result.
        replacement = b"replacement operator"
        write_private(assets / "marty-deploy-linux-amd64", replacement)
        inventory = json.loads((assets / "installer-inventory.json").read_bytes())
        inventory["artifacts"][0]["sha256"] = hashlib.sha256(replacement).hexdigest()
        write_private(assets / "installer-inventory.json", json.dumps(inventory).encode())
    else:
        name = "marty-deploy-linux-amd64" if changed == "operator" else "prepared-selfhost-bundle.zip"
        write_private(assets / name, b"changed after authentication")
    with pytest.raises(bootstrap.BootstrapError, match="authenticated installer .* changed"):
        bootstrap.authenticated_bootstrap_inputs(assets, identity)


def test_consumed_init_script_is_retained_from_authenticated_bundle(authenticated_inputs):
    assets, identity, operator, script = authenticated_inputs
    captured_operator, captured_script = bootstrap.authenticated_bootstrap_inputs(assets, identity)
    write_private(assets / "prepared-selfhost-bundle.zip", b"changed during later cluster operations")
    assert captured_operator == operator
    assert captured_script == script
