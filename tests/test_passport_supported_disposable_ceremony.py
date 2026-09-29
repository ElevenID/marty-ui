"""Private certificate setup must stay scoped and cannot claim Gateway proof."""

from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Iterator
import uuid

import pytest

from scripts import passport_supported_disposable_ceremony as ceremony
from services.passport_disposable_identity import managed_key_reference
from scripts.passport_supported_provisioning_producer import PARTIAL_ONLY_SERVICES


NOW = datetime(2026, 9, 28, 12, tzinfo=timezone.utc)


def test_port_bound_key_references_match_signing_keys_rust_contract() -> None:
    assert managed_key_reference(29876, "csca") == (
        "cred-dsc-12003bce3b8a5d59814b-es256")
    assert managed_key_reference(29876, "x509_doc_signer") == (
        "cred-dsc-22f8cf60394c5f1f88a0-es256")
    assert managed_key_reference(29877, "csca") != managed_key_reference(
        29876, "csca")


@contextmanager
def staged(surface: str = "selfhost") -> Iterator[tuple[dict, Path]]:
    project = f"marty-passport-acceptance-{surface}-" + uuid.uuid4().hex[:12]
    root = Path(tempfile.gettempdir()) / project
    root.mkdir(mode=0o700)
    try:
        secrets = root / "secrets"
        secrets.mkdir(mode=0o700)
        for name, value in (
            ("csca_issue_gateway_key", "a" * 64),
            ("dsc_issue_gateway_key", "b" * 64),
            ("signing_keys_internal_api_key", "c" * 64),
        ):
            (secrets / name).write_text(value, encoding="ascii")
        source = "d" * 40
        services = "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "e" * 64
        plan = {
            "schema": "marty.passport-supported-provisioning-plan/v1",
            "status": "blocked", "surface": surface, "project": project,
            "run_id": "123456", "source_commit": source,
            "services_reference": services,
            "migrations_reference": (
                "ghcr.io/elevenid/marty-ui-oss/migrations@sha256:" + "f" * 64
            ),
            "owner_labels": {
                "com.marty.passport.acceptance.owner": "supported-consumer",
                "com.marty.passport.acceptance.run-id": "123456",
                "com.marty.passport.acceptance.source-commit": source,
                "com.marty.passport.acceptance.services-image": services,
            },
            "expires_at": (NOW + timedelta(minutes=45)).isoformat(),
        }
        (root / "acceptance.env").write_text(
            "PASSPORT_ACCEPTANCE_GATEWAY_PORT=29876\n", encoding="ascii",
        )
        yield plan, root
    finally:
        assert root.parent == Path(tempfile.gettempdir())
        assert root.name == project
        shutil.rmtree(root)


def fake_inspector(plan, *, foreign_network: bool = False):
    signer_id, network_id = "1" * 64, "2" * 64
    project = plan["project"]
    labels = {"com.docker.compose.project": project,
              "com.docker.compose.service": "signing-keys",
              **plan["owner_labels"]}
    container = {"Id": signer_id,
                 "Config": {"Image": plan["services_reference"], "Labels": labels,
                            "Env": ["ENVIRONMENT=beta",
                                    "SIGNING_KEYS_BETA_CSCA_ISSUANCE_ENABLED=true",
                                    "SIGNING_KEYS_DSC_ISSUE_GATEWAY_KEY_FILE=/run/secrets/dsc_issue_gateway_key",
                                    "SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY_FILE=/run/secrets/csca_issue_gateway_key"]},
                 "State": {"Running": True, "Health": {"Status": "healthy"}},
                 "NetworkSettings": {"Networks": {project + "_private": {
                     "NetworkID": network_id}}}}
    network = {"Id": network_id, "Name": project + "_private", "Internal": True,
               "Driver": "bridge", "Labels": {
                   **labels, "com.docker.compose.project": (
                       "foreign" if foreign_network else project)}}

    def inspect(args):
        if args[0] == "ps":
            return signer_id + "\n"
        if args[:2] == ["container", "inspect"]:
            assert args[2] == signer_id
            return json.dumps([container])
        if args[:2] == ["network", "inspect"]:
            assert args[2] == network_id
            return json.dumps([network])
        pytest.fail(f"unexpected Docker inspection: {args}")

    return inspect


@pytest.mark.parametrize("surface", ["base", "selfhost"])
def test_fixture_chain_is_port_bound_and_setup_only(monkeypatch, surface: str) -> None:
    with staged(surface) as (plan, root):
        calls = []

        def fake_exercise(chain, csca_authority, dsc_authority, *, request):
            calls.append((chain, csca_authority, dsc_authority, request))
            return {"evidence": {"chain_verified_by": "openssl-x509-strict"}}

        monkeypatch.setattr(ceremony, "exercise_with_authorities", fake_exercise)
        profiles = []

        def request(selected, path, body, authority, signer_id):
            profiles.append((path, body, authority, signer_id))
            return 200, {"identity": {**body, "status": "active"}}

        result = ceremony.bootstrap_certificate_chain(
            plan, root, 29876, now=NOW, inspect=fake_inspector(plan), request=request,
        )
        chain, csca_authority, dsc_authority, _ = calls[0]
        did = "did:web:localhost%3A29876:orgs:marty"
        assert chain["organization_id"] == ceremony.ORGANIZATION_ID
        assert chain["csca"]["issuer_did"] == did
        assert chain["dsc"]["dsc_issuer_did"] == did
        assert chain["dsc"]["csca_issuer_did"] == did
        assert csca_authority == "a" * 64 and dsc_authority == "b" * 64
        assert [item[1]["key_purpose"] for item in profiles] == [
            "csca", "x509_doc_signer"]
        assert all(item[0] == ceremony.IDENTITY_ROUTE and item[2] == ""
                   and item[3] == "1" * 64 for item in profiles)
        assert result["status"] == "setup_only"
        assert result["gateway_operator_authorization_verified"] is False
        assert "a" * 64 not in str(result) and "b" * 64 not in str(result)


def test_private_request_uses_only_project_network_and_stdin_authority() -> None:
    with staged() as (plan, _):
        calls = []

        def run(command, **kwargs):
            calls.append((command, kwargs))
            return subprocess.CompletedProcess(
                command, 0, stdout=json.dumps({"status": 200, "body": {"status": "issued"}}),
                stderr="",
            )

        path = "/v1/signing-keys/issuer-identities/csca-self-signed-certificate"
        assert ceremony._private_post(
            plan, path, {"organization_id": ceremony.ORGANIZATION_ID}, "a" * 64,
            "1" * 64, run=run,
        ) == (200, {"status": "issued"})
        command, kwargs = calls[0]
        assert command[0:3] == ["docker", "run", "--rm"]
        assert command[command.index("--name") + 1] == (
            f"{plan['project']}-passport-certificate-bootstrap-1")
        assert command[command.index("--network") + 1] == "container:" + "1" * 64
        assert command[command.index("--entrypoint") + 1] == "python3"
        assert plan["migrations_reference"] in command
        assert "a" * 64 not in " ".join(command)
        assert json.loads(kwargs["input"])["authority"] == "a" * 64
        assert kwargs["capture_output"] is True and kwargs["timeout"] == 45
        assert "passport-certificate-bootstrap" in PARTIAL_ONLY_SERVICES


@pytest.mark.parametrize("mutation", [
    lambda plan, root: plan.update(surface="base"),
    lambda plan, root: plan.update(expires_at=(NOW - timedelta(seconds=1)).isoformat()),
    lambda plan, root: plan.update(migrations_reference="python:latest"),
    lambda plan, root: plan["owner_labels"].update(
        {"com.marty.passport.acceptance.run-id": "other"}),
    lambda plan, root: (root / "secrets" / "dsc_issue_gateway_key").write_text(
        "a" * 64, encoding="ascii"),
    lambda plan, root: (root / "secrets" / "csca_issue_gateway_key").write_text(
        "bad\n", encoding="ascii"),
])
def test_invalid_scope_fails_before_any_certificate_request(mutation) -> None:
    with staged() as (plan, root):
        plan = deepcopy(plan)
        mutation(plan, root)
        with pytest.raises(ceremony.DisposableCeremonyError):
            ceremony.bootstrap_certificate_chain(
                plan, root, 29876, now=NOW,
                inspect=lambda *args: pytest.fail("Docker must not be inspected"),
                request=lambda *args: pytest.fail("request must not start"),
            )


def test_private_request_rejects_external_route_and_redacts_failure() -> None:
    with staged() as (plan, _):
        with pytest.raises(ceremony.DisposableCeremonyError, match="project scope"):
            ceremony._private_post(plan, "https://outside.example", {
                "organization_id": ceremony.ORGANIZATION_ID,
            }, "a" * 64, "1" * 64,
                run=lambda *args, **kwargs: pytest.fail("Docker must not start"))
        def fail(command, **kwargs):
            return subprocess.CompletedProcess(command, 1, stdout="", stderr="secret-on-stderr")
        with pytest.raises(ceremony.DisposableCeremonyError) as error:
            ceremony._private_post(plan,
                "/v1/signing-keys/issuer-identities/dsc-certificate",
                {"organization_id": ceremony.ORGANIZATION_ID}, "b" * 64,
                "1" * 64, run=fail)
        assert "secret-on-stderr" not in str(error.value)


def test_foreign_network_cannot_receive_operator_authority() -> None:
    with staged() as (plan, root):
        with pytest.raises(ValueError, match="ownership"):
            ceremony.bootstrap_certificate_chain(
                plan, root, 29876, now=NOW,
                inspect=fake_inspector(plan, foreign_network=True),
                request=lambda *args: pytest.fail("request must not start"),
            )


def test_staged_port_mismatch_blocks_profile_and_certificate_setup() -> None:
    with staged() as (plan, root):
        with pytest.raises(ceremony.DisposableCeremonyError, match="port differs"):
            ceremony.bootstrap_certificate_chain(
                plan, root, 29877, now=NOW,
                inspect=lambda *args: pytest.fail("Docker must not be inspected"),
                request=lambda *args: pytest.fail("request must not start"),
            )
