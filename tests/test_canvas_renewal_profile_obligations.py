"""Bounded source ownership for Canvas renewal profiles, not runtime evidence."""

from copy import deepcopy
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

import pytest

from scripts.check_gateway_public_protocol_contract import _without_rust_comments


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "contracts/canvas-renewal-profile-obligations.json"
SOURCE = (
    ROOT / "rust/crates/canvas-acceptance/tests/canvas_published_schema_contract.rs"
)
FIXTURE = ROOT / "rust/crates/canvas-acceptance/tests/support/renewal_fresh_main.rs"
RENDERED_CONFIG = (
    ROOT / "rust/crates/canvas-acceptance/tests/support/rendered_base_process.rs"
)
FAST = (
    ROOT
    / "rust/services/issuance/src/initiation_didcomm/tests/initiation_didcomm_renewal_tests.rs"
)
FAST_PARENT = ROOT / "rust/services/issuance/src/initiation_didcomm.rs"
RUNNER = ROOT / "scripts/ci/run-published-canvas-contracts.sh"
CONTAINER = (
    ROOT / "rust/crates/canvas-acceptance/tests/support/base_runtime_container.rs"
)
REFERENCE = ROOT / "rust/services/issuance/tests/support/renewal_reference_fixture.rs"
REFUSAL_AND_ALLOW = (
    "anoncrypt:private-refused",
    "authcrypt:private-refused",
    "anoncrypt:private-allowed",
    "authcrypt:private-allowed",
)
ALLOW = ("anoncrypt:private-allowed", "authcrypt:private-allowed")
EXPECTED = (
    (
        "gateway",
        "base_profile_gateway_composition_isolated",
        "base_profile_gateway_composition_child",
        "run_gateway",
        None,
        REFUSAL_AND_ALLOW,
    ),
    (
        "envoy",
        "base_profile_envoy_composition_isolated",
        "base_profile_envoy_composition_child",
        "run_envoy",
        None,
        REFUSAL_AND_ALLOW,
    ),
    (
        "kubernetes-gateway",
        "kubernetes_profile_gateway_composition_isolated",
        "kubernetes_profile_gateway_composition_child",
        "run_kubernetes",
        True,
        REFUSAL_AND_ALLOW,
    ),
    (
        "kubernetes-direct",
        "kubernetes_resolved_native_profile_delivers_both_encryption_modes",
        None,
        "run_kubernetes",
        False,
        ALLOW,
    ),
    (
        "rendered-direct",
        "base_profile_native_renewal_uses_actual_rendered_configuration",
        None,
        "run_rendered",
        None,
        ALLOW,
    ),
    (
        "packaged-direct",
        "renewal_fresh_packaged_main_delivers_both_encryption_modes",
        None,
        "run",
        None,
        ALLOW,
    ),
)
CONTAINER_CALLS = {
    "gateway": "base_runtime_container::run(",
    "envoy": "base_runtime_container::run_envoy(",
    "kubernetes-gateway": "base_runtime_container::run_kubernetes(",
}


def _compact(text: str) -> str:
    return re.sub(r"\s+", "", text)


def _body(source: str, name: str, *, test: bool) -> str:
    prefix = r"#\[tokio::test\]\s*async fn " if test else r"pub\(super\) async fn "
    matches = re.findall(
        rf"(?m)^{prefix}{re.escape(name)}\([^)]*\)\s*\{{(.*?)^\}}",
        source,
        re.DOTALL,
    )
    assert len(matches) == 1, f"Missing/duplicate active owner: {name}"
    return matches[0]


def _inputs() -> dict[str, str]:
    return {
        "source": SOURCE.read_text(encoding="utf-8"),
        "fixture": FIXTURE.read_text(encoding="utf-8"),
        "fast": FAST.read_text(encoding="utf-8"),
        "fast_parent": FAST_PARENT.read_text(encoding="utf-8"),
        "runner": RUNNER.read_text(encoding="utf-8"),
        "container": CONTAINER.read_text(encoding="utf-8"),
        "reference": REFERENCE.read_text(encoding="utf-8"),
    }


def _validate(manifest: dict, inputs: dict[str, str]) -> None:
    assert manifest["schema"] == "marty.canvas-renewal-profile-obligations/v1"
    assert (manifest["package"], manifest["target"]) == (
        "marty-canvas-acceptance",
        "canvas_published_schema_contract",
    )
    assert manifest["source"] == SOURCE.relative_to(ROOT).as_posix()
    assert manifest["fixture"] == FIXTURE.relative_to(ROOT).as_posix()
    assert (
        manifest["frozen_source"]
        == "contracts/credential-renewal-python-reference.json"
    )
    assert (ROOT / manifest["frozen_source"]).is_file()
    assert manifest["fast_owner"]["source"] == FAST.relative_to(ROOT).as_posix()
    assert manifest["fast_owner"]["test"] == (
        "initiation_didcomm::tests::renewal_graph::"
        "renewal_private_ip_matrix_composes_real_didcomm_policy_and_crypto"
    )
    assert "Real PostgreSQL" in manifest["fast_owner"]["does_not_prove"]
    assert "actual HTTPS" in manifest["fast_owner"]["does_not_prove"]
    assert "authority to skip" in manifest["scope"]

    source = _without_rust_comments(inputs["source"])
    fixture = _without_rust_comments(inputs["fixture"])
    fast = _without_rust_comments(inputs["fast"])
    fast_parent = _without_rust_comments(inputs["fast_parent"])
    reference = _without_rust_comments(inputs["reference"])
    container = _without_rust_comments(inputs["container"])
    runner = inputs["runner"]
    assert (
        '#[path = "support/renewal_fresh_main.rs"]\nmod renewal_fresh_main;' in source
    )
    assert (
        '#[path = "../../../services/issuance/tests/support/renewal_reference_fixture.rs"]'
        in source
    )
    assert "contracts/credential-renewal-python-reference.json" in reference
    assert "let corpus = reference::corpus();" in fixture
    assert (
        fast_parent.count(
            '#[cfg(test)]\n    #[path = "initiation_didcomm_renewal_tests.rs"]\n    mod renewal_graph;'
        )
        == 1
    )
    assert fast_parent.index("#[cfg(test)]\nmod tests {") < fast_parent.index(
        "mod renewal_graph;"
    )
    fast_body = _body(
        fast,
        "renewal_private_ip_matrix_composes_real_didcomm_policy_and_crypto",
        test=True,
    )
    assert "for authenticated in [false, true]" in fast_body
    assert "for allow_private_ips in [false, true]" in fast_body
    assert "NativeDidcommEnvelope::new(" in fast_body
    assert "DidcommEndpointValidator::new(allow_private_ips)" in fast_body
    assert "CredentialRenewalService::new(" in fast_body

    assert len(manifest["profiles"]) == len(EXPECTED)
    observed = tuple(
        (
            item["profile"],
            item["outer"],
            item["child"],
            item["entrypoint"],
            item.get("gateway"),
            tuple(item["cases"]),
        )
        for item in manifest["profiles"]
    )
    assert observed == EXPECTED, "Renewal profile owner or case matrix drift"
    assert all(item["retained"].strip() for item in manifest["profiles"])
    assert 'export MARTY_CANVAS_PUBLISHED_SCHEMA_TEST="1"' in runner
    assert (
        '"$composition_executable" --skip "$serial_composition_test" --nocapture --test-threads=4'
        in runner
    )
    assert "--skip renewal_" not in runner

    for profile, outer, child, entrypoint, gateway, _cases in EXPECTED:
        outer_body = _body(source, outer, test=True)
        assert 'std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST")' in outer_body
        assert "PublishedDatabase::start()" in outer_body
        assert runner.count(f"'{outer}: test'") == 1
        if child:
            assert CONTAINER_CALLS[profile] in outer_body
            child_body = _body(source, child, test=True)
            assert 'std::env::var("MARTY_BASE_RUNTIME_CHILD")' in child_body or (
                profile == "kubernetes-gateway"
                and 'std::env::var("MARTY_KUBERNETES_RUNTIME_CHILD")' in child_body
            )
            assert "MARTY_BASE_COMPOSITION_COMPLETE_V1" in child_body
            assert runner.count(f"'{child}: test'") == 1
            assert (
                f'const {"KUBERNETES_" if profile == "kubernetes-gateway" else "ENVOY_" if profile == "envoy" else ""}CHILD: &str = "{child}";'
                in container
            )
            call_owner = child_body
        else:
            call_owner = outer_body
        compact = _compact(call_owner)
        if gateway is None:
            assert f"renewal_fresh_main::{entrypoint}(" in call_owner
        else:
            assert "renewal_fresh_main::run_kubernetes(" in call_owner
            assert re.search(rf",{str(gateway).lower()},?\)", compact)

    case_owner = re.findall(
        r"(?ms)^async fn run_with_profile\([^)]*\)\s*\{(.*?)^\}", fixture
    )
    assert len(case_owner) == 1
    case_code = _compact(case_owner[0])
    assert "Ingress::Gateway|Ingress::Envoy|Ingress::KubernetesGateway" in case_code
    assert "&[(false,false),(true,false),(false,true),(true,true)]" in case_code
    assert "&[(false,true),(true,true)]" in case_code
    for wrapper, ingress in (
        ("run", "Ingress::Direct"),
        ("run_rendered", "Ingress::Direct"),
        ("run_gateway", "Ingress::Gateway"),
        ("run_envoy", "Ingress::Envoy"),
    ):
        assert ingress in _body(fixture, wrapper, test=False)
    assert "Ingress::KubernetesGateway" in _body(fixture, "run_kubernetes", test=False)
    assert "Ingress::KubernetesDirect" in _body(fixture, "run_kubernetes", test=False)


def test_six_renewal_profiles_retain_distinct_runtime_obligations() -> None:
    _validate(json.loads(MANIFEST.read_text(encoding="utf-8")), _inputs())


def _validate_rendered_config_owner(source: str, config: str, runner: str) -> None:
    assert (
        source.count(
            '#[path = "support/rendered_base_process.rs"]\nmod rendered_base_process;'
        )
        == 1
    )
    name = "rendered_base_renewal_config_crosses_encryption_and_private_address_policy"
    bodies = re.findall(
        rf'(?ms)^#\[cfg\(target_os = "linux"\)\]\s*#\[test\]\s*fn {name}\(\) \{{(.*?)^\}}',
        _without_rust_comments(config),
    )
    assert len(bodies) == 1
    body = _compact(bodies[0])
    for case in (
        '(false,false,"false")',
        '(true,false,"false")',
        '(false,true,"true")',
        '(true,true,"true")',
    ):
        assert case in body
    assert "RenderedBase::render(&spec)" in body
    assert (
        'std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref()!=Ok("1")'
        in body
    )
    assert 'println!("\\nRENDERED_BASE_RENEWAL_CONFIG_2X2_COMPLETE_V1")' in body
    assert body.index(
        'println!("\\nRENDERED_BASE_RENEWAL_CONFIG_2X2_COMPLETE_V1")'
    ) > body.index('gateway.get("REDIS_URL")')
    for field in (
        "DIDCOMM_ALLOW_PRIVATE_IPS",
        "DIDCOMM_TLS_CA_FILE",
        "DIDCOMM_ENCRYPTION_POLICY_FILE",
        "DIDCOMM_DID_WEB_INTERNAL_BASE_URL",
        "ISSUANCE_SERVICE_URL",
        "ISSUANCE_NATIVE_SERVICE_URL",
    ):
        assert field in body
    expected_row = f"rendered_base_process::{name}: test"
    assert (
        runner.count(
            f"printf '%s\\n' \"$composition_tests\" | grep -Fx '{expected_row}'"
        )
        == 1
    )
    assert '"$composition_executable" --skip "$serial_composition_test"' in runner
    assert f"--skip {name}" not in runner
    assert f"--skip rendered_base_process::{name}" not in runner
    assert (
        runner.count(
            f"grep -Fxc 'test {expected_row.removesuffix(': test')} ... ok' \"$composition_log\""
        )
        == 1
    )
    assert (
        runner.count(
            "grep -Fxc 'RENDERED_BASE_RENEWAL_CONFIG_2X2_COMPLETE_V1' \"$composition_log\""
        )
        == 1
    )


def test_rendered_config_matrix_has_one_registered_composition_owner() -> None:
    _validate_rendered_config_owner(
        SOURCE.read_text(encoding="utf-8"),
        RENDERED_CONFIG.read_text(encoding="utf-8"),
        RUNNER.read_text(encoding="utf-8"),
    )


@pytest.mark.parametrize(
    "fault",
    ["missing", "case", "renderer", "runner", "platform", "gate", "marker", "proof"],
)
def test_rendered_config_owner_rejects_drift(fault: str) -> None:
    source = SOURCE.read_text(encoding="utf-8")
    config = RENDERED_CONFIG.read_text(encoding="utf-8")
    runner = RUNNER.read_text(encoding="utf-8")
    if fault == "missing":
        source = source.replace("mod rendered_base_process;", "mod absent_renderer;")
    elif fault == "case":
        config = config.replace('(true, false, "false")', '(true, true, "true")')
    elif fault == "renderer":
        config = config.replace("RenderedBase::render(&spec)", "fixture_stub(&spec)")
    elif fault == "platform":
        config = config.replace(
            '#[cfg(target_os = "linux")]', '#[cfg(target_os = "windows")]'
        )
    elif fault == "gate":
        config = config.replace(
            'std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST")',
            'std::env::var("UNRELATED_FLAG")',
        )
    elif fault == "marker":
        config = config.replace(
            "RENDERED_BASE_RENEWAL_CONFIG_2X2_COMPLETE_V1", "EARLY_NOOP_COMPLETE"
        )
    elif fault == "proof":
        runner = runner.replace(
            "grep -Fxc 'RENDERED_BASE_RENEWAL_CONFIG_2X2_COMPLETE_V1'",
            "grep -Fxc 'NOOP_SUCCESS'",
        )
    else:
        runner += (
            "\n--skip rendered_base_renewal_config_crosses_encryption_"
            "and_private_address_policy\n"
        )
    with pytest.raises(AssertionError):
        _validate_rendered_config_owner(source, config, runner)


def test_rendered_config_execution_guard_rejects_early_return_and_duplicate_rows(
    tmp_path: Path,
) -> None:
    bash = shutil.which("bash")
    if os.name == "nt":
        git = shutil.which("git")
        assert git is not None
        bash = str(Path(git).parent.parent / "bin/bash.exe")
    assert bash is not None
    runner = RUNNER.read_text(encoding="utf-8")
    guard = re.search(
        r"(?ms)^\[\[ \$\(grep -Fxc 'test rendered_base_process::rendered_base_renewal_config.*?^\}",
        runner,
    )
    assert guard is not None
    test_row = (
        "test rendered_base_process::"
        "rendered_base_renewal_config_crosses_encryption_and_private_address_policy ... ok"
    )
    marker = "RENDERED_BASE_RENEWAL_CONFIG_2X2_COMPLETE_V1"
    log = tmp_path / "composition.log"
    for lines, expected in (
        ([test_row, marker], 0),
        ([test_row], 1),
        ([marker], 1),
        ([test_row.replace("ok", "ignored"), marker], 1),
        ([test_row, marker, marker], 1),
        ([test_row, test_row, marker], 1),
    ):
        log.write_text("\n".join(lines) + "\n", encoding="utf-8")
        result = subprocess.run(
            [
                bash,
                "-c",
                f'composition_log="$1"\n{guard.group()}',
                "_",
                log.as_posix(),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == expected, result.stderr


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "same_count_substitution",
        "case",
        "frozen_input",
        "child",
        "container",
        "source",
        "fast",
        "fast_module",
        "runner",
        "fixture",
    ],
)
def test_renewal_inventory_rejects_owner_and_matrix_drift(fault: str) -> None:
    manifest = deepcopy(json.loads(MANIFEST.read_text(encoding="utf-8")))
    inputs = _inputs()
    if fault == "missing":
        manifest["profiles"].pop()
    elif fault == "same_count_substitution":
        manifest["profiles"][0]["outer"] = "another_test"
    elif fault == "case":
        manifest["profiles"][0]["cases"][0] = "anoncrypt:private-allowed"
    elif fault == "frozen_input":
        manifest["frozen_source"] = "contracts/another-source.json"
    elif fault == "child":
        manifest["profiles"][0]["child"] = "another_child"
    elif fault == "container":
        inputs["container"] = inputs["container"].replace(
            'const ENVOY_CHILD: &str = "base_profile_envoy_composition_child";',
            'const ENVOY_CHILD: &str = "another_child";',
        )
    elif fault == "source":
        inputs["source"] = inputs["source"].replace(
            "renewal_fresh_main::run_rendered", "renewal_fresh_main::run_gateway"
        )
    elif fault == "fast":
        inputs["fast"] = inputs["fast"].replace(
            "for allow_private_ips in [false, true]", "for allow_private_ips in [true]"
        )
    elif fault == "fast_module":
        inputs["fast_parent"] = inputs["fast_parent"].replace(
            "mod renewal_graph;", "mod disconnected_renewal_graph;"
        )
    elif fault == "runner":
        inputs["runner"] = inputs["runner"].replace(
            'export MARTY_CANVAS_PUBLISHED_SCHEMA_TEST="1"',
            'export MARTY_CANVAS_PUBLISHED_SCHEMA_TEST="0"',
        )
    else:
        inputs["fixture"] = inputs["fixture"].replace(
            "&[(false, false), (true, false), (false, true), (true, true)]",
            "&[(false, true), (true, true)]",
        )
    with pytest.raises(AssertionError):
        _validate(manifest, inputs)
