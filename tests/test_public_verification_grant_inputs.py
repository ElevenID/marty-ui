"""Closed grant-authority inputs and pre-fixture discovery refusal controls."""

import json
from pathlib import Path
import re
import subprocess

import pytest

from scripts import probe_signing_keys_openbao_policy as controller
from scripts import public_demo_grant_probe as probe

ROOT = Path(__file__).resolve().parents[1]


def test_demo_verifier_adds_only_its_origin_to_the_unchanged_bootstrap_inventory():
    initializer = (ROOT / "docker/openbao-init.sh").read_text(encoding="utf-8")
    legacy = (
        re.search(r"^grant_origins='([^']+)'$", initializer, re.MULTILINE)
        .group(1)
        .split()
    )
    assert len(legacy) == 7 and "flow-demo-holder" not in legacy
    assert probe.ORIGINS == (*legacy, "flow-demo-holder")
    lines = (probe.INPUTS / "verify-with-demo-holder.hcl").read_text().splitlines()
    rule = re.compile(
        r'path "transit/verify/marty-sign-grant-([a-z-]+)-v1/sha2-256" \{ capabilities = \["update"\] }'
    )
    assert all(rule.fullmatch(line) for line in lines)
    assert [rule.fullmatch(line).group(1) for line in lines] == list(probe.ORIGINS)
    mint = (probe.INPUTS / "mint-flow-demo-holder.hcl").read_text()
    assert re.fullmatch(
        r'path "transit/hmac/marty-sign-grant-flow-demo-holder-v1/sha2-256" \{\s+capabilities = \["update"\]\s+}\s*',
        mint,
    )
    assert json.loads((probe.INPUTS / "demo-holder-key.json").read_text()) == {
        "type": "hmac",
        "key_size": 32,
        "exportable": False,
        "allow_plaintext_backup": False,
    }


@pytest.mark.parametrize(
    "stdout,code,expected",
    [
        (f"{probe.CASE}: test\n\n1 test, 0 benchmarks\n", 0, True),
        ("0 tests, 0 benchmarks\n", 0, False),
        ("other_case: test\n", 0, False),
        (f"{probe.CASE}: test\nother_case: test\n", 0, False),
        (f"{probe.CASE}: test\n", 1, False),
    ],
)
def test_selected_native_case_must_exist_before_any_backend(stdout, code, expected):
    assert (
        probe.discovered(subprocess.CompletedProcess([], code, stdout, "")) is expected
    )
    command = probe.command(discovery=True)
    assert "--list" in command and "--ignored" in command and "--exact" in command
    assert "--offline" in command and "--locked" in command


def test_missing_native_case_and_mixed_modes_refuse_before_docker(monkeypatch):
    monkeypatch.setattr(
        controller,
        "pull_pinned_openbao",
        lambda: pytest.fail("backend creation reached"),
    )

    def no_tests(*args, **kwargs):
        return subprocess.CompletedProcess(args, 0, "0 tests\n", "")

    with pytest.raises(RuntimeError, match="discovery before backend"):
        controller.qualify(public_demo_grant=True, grant_runner=no_tests)
    with pytest.raises(RuntimeError, match="select one"):
        controller.qualify(
            public_demo_grant=True, grant_verifier=True, grant_runner=no_tests
        )


@pytest.mark.parametrize(
    "stdout,code,expected",
    [
        ("test result: ok. 1 passed; 0 failed; 0 ignored;", 0, True),
        ("test result: ok. 0 passed; 0 failed;", 0, False),
        ("test result: ok. 1 passed; 0 failed;", 1, False),
        ("test result: FAILED. 0 passed; 1 failed;", 1, False),
    ],
)
def test_native_execution_must_really_pass_one_case(stdout, code, expected):
    assert (
        probe.native_succeeded(subprocess.CompletedProcess([], code, stdout, ""))
        is expected
    )


def test_unexpected_verifier_authority_is_preserved_before_any_write():
    calls = []

    def call(method, path, token, body=None):
        calls.append((method, path))
        return 200, {"data": {"policy": 'path "*" { capabilities = ["sudo"] }'}}

    with pytest.raises(RuntimeError, match="preserve unexpected verifier policy"):
        probe.qualify(
            call,
            "synthetic-fixture-root",
            {"MARTY_TEST_OPENBAO_ROOT_TOKEN": "synthetic-fixture-root"},
        )
    assert calls == [("GET", "sys/policies/acl/sign-grant-verify")]


def test_missing_native_custody_case_refuses_before_docker(monkeypatch):
    monkeypatch.setattr(
        controller, "pull_pinned_openbao", lambda: pytest.fail("backend reached")
    )
    selections = []

    def discovery(command, **kwargs):
        selections.append(command)
        stdout = f"{probe.CASE}: test\n" if probe.CASE in command else "0 tests\n"
        return subprocess.CompletedProcess(command, 0, stdout, "")

    with pytest.raises(RuntimeError, match="discovery before backend"):
        controller.qualify(public_demo_grant=True, grant_runner=discovery)
    assert len(selections) == 2
    assert probe.CUSTODY_CASE in selections[1]
    assert "public_service_sign_live_kms" in selections[1]


def test_custody_case_discovery_is_independent_of_grant_case():
    assert probe.discovered(
        subprocess.CompletedProcess([], 0, f"{probe.CUSTODY_CASE}: test\n", ""),
        custody=True,
    )
    assert not probe.discovered(
        subprocess.CompletedProcess([], 0, f"{probe.CASE}: test\n", ""), custody=True
    )


def test_missing_native_admission_case_refuses_before_docker(monkeypatch):
    monkeypatch.setattr(
        controller, "pull_pinned_openbao", lambda: pytest.fail("backend reached")
    )
    selections = []

    def discovery(command, **kwargs):
        selections.append(command)
        case = (
            probe.CASE
            if probe.CASE in command
            else probe.CUSTODY_CASE
            if probe.CUSTODY_CASE in command
            else None
        )
        return subprocess.CompletedProcess(
            command, 0, f"{case}: test\n" if case else "0 tests\n", ""
        )

    with pytest.raises(RuntimeError, match="discovery before backend"):
        controller.qualify(public_demo_grant=True, grant_runner=discovery)
    assert len(selections) == 3
    assert probe.ADMISSION_CASE in selections[2]
    assert "marty-flow-acceptance" in selections[2]


def test_admission_case_discovery_is_exact():
    assert probe.discovered(
        subprocess.CompletedProcess([], 0, f"{probe.ADMISSION_CASE}: test\n", ""),
        admission=True,
    )
    assert not probe.discovered(
        subprocess.CompletedProcess([], 0, f"{probe.CUSTODY_CASE}: test\n", ""),
        admission=True,
    )


def test_owned_postgres_never_uses_an_inherited_database_and_cleans_failed_consumer(
    monkeypatch,
):
    calls = []
    removed = []

    def docker(*args, **kwargs):
        calls.append(args)
        if args[0] == "run":
            return "a" * 64
        if args[0] == "port":
            return "127.0.0.1:54321"
        return ""

    monkeypatch.setattr(controller, "require_docker", docker)
    monkeypatch.setattr(
        controller,
        "docker",
        lambda *args: subprocess.CompletedProcess([], 0, "ready", ""),
    )
    monkeypatch.setattr(
        controller,
        "remove_owned_demo_grant_backend",
        lambda name, identity: removed.append((name, identity)),
    )
    with pytest.raises(RuntimeError, match="consumer failed"):
        with controller.public_demo_postgres(
            {"FLOW_PUBLIC_VERIFICATION_TEST_URL": "postgres://shared/production"}
        ) as (environment, receipt):
            assert (
                "@127.0.0.1:54321/marty_public_verification_test"
                in environment["FLOW_PUBLIC_VERIFICATION_TEST_URL"]
            )
            assert len(environment["MARTY_TEST_POSTGRES_DISPOSABLE_NONCE"]) == 32
            assert receipt["postgresRemoved"] is False
            raise RuntimeError("consumer failed")
    assert removed[0][1] == "a" * 64
    assert receipt["postgresRemoved"] is True
    assert "/var/lib/postgresql/data:rw,mode=700" in calls[0]
    assert "127.0.0.1::5432" in calls[0]


def test_owned_postgres_readiness_failure_still_removes_the_exact_fixture(monkeypatch):
    removed = []
    monkeypatch.setattr(controller, "require_docker", lambda *args, **kwargs: "b" * 64)
    monkeypatch.setattr(
        controller,
        "docker",
        lambda *args: subprocess.CompletedProcess([], 1, "", "not ready"),
    )
    monkeypatch.setattr(controller.time, "sleep", lambda _: None)
    monkeypatch.setattr(
        controller,
        "remove_owned_demo_grant_backend",
        lambda name, identity: removed.append(identity),
    )
    with pytest.raises(RuntimeError, match="PostgreSQL not ready"):
        with controller.public_demo_postgres({}):
            pytest.fail("unready database yielded")
    assert removed == ["b" * 64]
