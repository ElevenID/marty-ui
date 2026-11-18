import json
import textwrap
from pathlib import Path

import pytest

import scripts.check_gateway_public_protocol_contract as protocol_contract
from scripts.check_gateway_public_protocol_contract import (
    DTO_SHAPES,
    VECTOR_TEST_OWNERS,
    VectorTestOwner,
    _assert_full_workspace_ci_owner,
    _assert_issued_credential_extension_contract,
    _assert_protocol_version,
    _assert_rust_behavior_vector_test_owners,
)

CANONICAL_PROTOCOL_COMMIT = "76c37dc229b328afe002b911a26624543f814a64"


def test_gateway_public_dto_shape_manifest_is_unique_and_versioned() -> None:
    contract = json.loads(DTO_SHAPES.read_text(encoding="utf-8"))
    assert contract["schema_version"] == 1
    models = contract["models"]
    assert len(models) >= 40
    assert len({model["model"] for model in models}) == len(models)
    assert all(model["schema"].endswith(".json") for model in models)
    assert all(len(model["fields"]) == len(set(model["fields"])) for model in models)


def test_every_gateway_behavior_vector_has_a_declared_rust_test_owner() -> None:
    assert len(VECTOR_TEST_OWNERS) == 22
    _assert_rust_behavior_vector_test_owners()


def _vector_owner_fixture(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    contracts = tmp_path / "contracts"
    contracts.mkdir()
    names = (
        "gateway-example-behavior.json",
        "credential-metadata-behavior.json",
        "vc-api-adapter-behavior.json",
    )
    for name in names:
        (contracts / name).write_text("{}", encoding="utf-8")
    crate = tmp_path / "rust" / "services" / "example"
    services = crate / "src"
    services.mkdir(parents=True)
    (crate / "Cargo.toml").write_text(
        '[package]\nname = "example"\nversion = "0.1.0"\n', encoding="utf-8"
    )
    (services / "lib.rs").write_text("pub mod vector_tests;\n", encoding="utf-8")
    source = services / "vector_tests.rs"
    source.write_text(
        "#[cfg(test)]\nmod tests {\n    #[test]\n    fn vector_contract() {\n"
        + "".join(
            f'        let _ = include_str!("../../../../contracts/{name}");\n'
            for name in names
        )
        + "    }\n}\n",
        encoding="utf-8",
    )
    workflow = tmp_path / ".github" / "workflows"
    workflow.mkdir(parents=True)
    (workflow / "ci.yml").write_text(
        (Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml").read_text(
            encoding="utf-8"
        ),
        encoding="utf-8",
    )
    classifier = tmp_path / "scripts/ci/affected_components.sh"
    classifier.parent.mkdir(parents=True)
    classifier.write_text(
        (Path(__file__).resolve().parents[1] / "scripts/ci/affected_components.sh").read_text(
            encoding="utf-8"
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(protocol_contract, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(
        protocol_contract,
        "VECTOR_TEST_OWNERS",
        {
            name: VectorTestOwner(
                "rust/services/example/src/vector_tests.rs", "vector_contract"
            )
            for name in names
        },
    )
    return source


def _external_vector_owner_fixture(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> tuple[Path, Path]:
    source = _vector_owner_fixture(monkeypatch, tmp_path)
    original = source.read_text(encoding="utf-8")
    test_source = source.with_name("vector_tests_body.rs")
    test_source.write_text(
        textwrap.dedent(
            original.removeprefix("#[cfg(test)]\nmod tests {\n").removesuffix("}\n")
        ),
        encoding="utf-8",
    )
    source.write_text(
        '#[cfg(test)]\n#[path = "vector_tests_body.rs"]\nmod tests;\n',
        encoding="utf-8",
    )
    return source, test_source


@pytest.mark.parametrize("reverse_attributes", [False, True])
@pytest.mark.parametrize("separator", ["\n", "\n\n", "\n// test module\n"])
def test_vector_owner_guard_follows_registered_external_test_module(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    reverse_attributes: bool,
    separator: str,
) -> None:
    source, _ = _external_vector_owner_fixture(monkeypatch, tmp_path)
    attributes = ["#[cfg(test)]", '#[path = "vector_tests_body.rs"]']
    if reverse_attributes:
        attributes.reverse()
    source.write_text(separator.join(attributes) + "\nmod tests;\n", encoding="utf-8")
    _assert_rust_behavior_vector_test_owners()


@pytest.mark.parametrize(
    "old,new,error",
    [
        ("mod tests;", "// mod tests;", "not annotated"),
        ("mod tests;", 'const UNUSED: &str = r#"\nmod tests;\n"#;', "not annotated"),
        ("#[cfg(test)]\n", "", "requires only cfg\\(test\\)"),
        ("#[cfg(test)]", "#[cfg(any())]", "requires only cfg\\(test\\)"),
        ("#[cfg(test)]", "#[cfg(test)]\n#[cfg(any())]", "requires only cfg\\(test\\)"),
        ("#[cfg(test)]", "#[cfg(any())]\n\n#[cfg(test)]", "requires only cfg\\(test\\)"),
        (
            "#[cfg(test)]",
            "#[cfg(any())]\n// condition still applies\n#[cfg(test)]",
            "requires only cfg\\(test\\)",
        ),
        (
            "#[cfg(test)]",
            "#[cfg_attr(\n    test,\n    cfg(any())\n)]\n#[cfg(test)]",
            "requires only cfg\\(test\\)",
        ),
        (
            "#[cfg(test)]",
            '#[cfg_attr(test, cfg(any()), doc = r#"[ignored]"#)]\n#[cfg(test)]',
            "requires only cfg\\(test\\)",
        ),
        ("#[cfg(test)]", "# [cfg(any())]\n#[cfg(test)]", "malformed outer attributes"),
        (
            "#[cfg(test)]",
            "#[cfg(test)]\n#[cfg_attr(test, ignore)]",
            "requires only cfg\\(test\\)",
        ),
        ('#[path = "vector_tests_body.rs"]\n', "", "requires only cfg\\(test\\)"),
        ("vector_tests_body.rs", "../vector_tests_body.rs", "sibling path"),
        ("vector_tests_body.rs", "missing.rs", "not a sibling source"),
        ("vector_tests_body.rs", "vector_tests.rs", "not a sibling source"),
        ("mod tests;", "mod tests;\nmod tests;", "ambiguous registration"),
    ],
)
def test_vector_owner_guard_rejects_inactive_or_unbound_external_modules(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    old: str,
    new: str,
    error: str,
) -> None:
    source, _ = _external_vector_owner_fixture(monkeypatch, tmp_path)
    original = source.read_text(encoding="utf-8")
    assert old in original
    source.write_text(original.replace(old, new), encoding="utf-8")
    with pytest.raises(AssertionError, match=error):
        _assert_rust_behavior_vector_test_owners()


@pytest.mark.parametrize(
    "old,new,error",
    [
        ("#[test]\n", "", "not annotated"),
        ("#[test]", "#[ignore]\n#[test]", "ignored"),
        ("#[test]", '#[ignore = "service"]\n#[test]', "ignored"),
        ("#[test]", "#[cfg(any())]\n#[test]", "conditionally compiled"),
        ("#[test]", "#[cfg_attr(test, ignore)]\n#[test]", "conditionally compiled"),
        ("#[test]", "#![cfg(any())]\n#[test]", "conditionally compiled"),
        ("#[test]", "#![cfg_attr(test, cfg(any()))]\n#[test]", "conditionally compiled"),
        ("#[test]", "#! [cfg(any())]\n#[test]", "conditionally compiled"),
        ("#[test]", "#! /* gap */ [cfg(any())]\n#[test]", "conditionally compiled"),
        ("#[test]", "#![r#cfg(any())]\n#[test]", "conditionally compiled"),
        (
            "#[test]",
            "#![r#cfg_attr(all(), cfg(any()))]\n#[test]",
            "conditionally compiled",
        ),
        (
            "#[test]",
            "#![allow(dead_code)] #![cfg(any())]\n#[test]",
            "conditionally compiled",
        ),
        (
            "#[test]",
            "# /* gap */ ! [cfg_attr(test, cfg(any()))]\n#[test]",
            "conditionally compiled",
        ),
        (
            'include_str!("../../../../contracts/gateway-example-behavior.json")',
            '"gateway-example-behavior.json"',
            "not loaded by its Rust test",
        ),
    ],
)
def test_external_vector_tests_retain_annotation_and_fixture_guards(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    old: str,
    new: str,
    error: str,
) -> None:
    _, test_source = _external_vector_owner_fixture(monkeypatch, tmp_path)
    original = test_source.read_text(encoding="utf-8")
    assert old in original
    test_source.write_text(original.replace(old, new), encoding="utf-8")
    with pytest.raises(AssertionError, match=error):
        _assert_rust_behavior_vector_test_owners()


def test_vector_owner_guard_rejects_external_module_symlinks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _, test_source = _external_vector_owner_fixture(monkeypatch, tmp_path)
    outside_source = tmp_path / "outside.rs"
    test_source.rename(outside_source)
    test_source.symlink_to(outside_source)
    with pytest.raises(AssertionError, match="not a sibling source"):
        _assert_rust_behavior_vector_test_owners()


def test_vector_owner_guard_rejects_dead_or_nonexecuting_owners(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = _vector_owner_fixture(monkeypatch, tmp_path)
    original = source.read_text(encoding="utf-8")
    _assert_rust_behavior_vector_test_owners()

    source.write_text(original.replace("    #[test]\n", ""), encoding="utf-8")
    with pytest.raises(AssertionError, match="not annotated"):
        _assert_rust_behavior_vector_test_owners()

    source.write_text(
        original.replace("    #[test]\n", "    #[ignore]\n    #[test]\n"),
        encoding="utf-8",
    )
    with pytest.raises(AssertionError, match="ignored"):
        _assert_rust_behavior_vector_test_owners()

    source.write_text(
        original.replace(
            "    #[test]\n", '    #[ignore = "needs a service"]\n    #[test]\n'
        ),
        encoding="utf-8",
    )
    with pytest.raises(AssertionError, match="ignored"):
        _assert_rust_behavior_vector_test_owners()

    source.write_text(
        original.replace(
            "    #[test]\n", '    #[cfg(feature = "hidden")]\n    #[test]\n'
        ),
        encoding="utf-8",
    )
    with pytest.raises(AssertionError, match="conditionally compiled"):
        _assert_rust_behavior_vector_test_owners()

    source.write_text(
        original.replace(
            '        let _ = include_str!("../../../../contracts/gateway-example-behavior.json");',
            "        // gateway-example-behavior.json",
        ),
        encoding="utf-8",
    )
    with pytest.raises(AssertionError, match="not loaded by its Rust test"):
        _assert_rust_behavior_vector_test_owners()

    source.write_text(
        original.replace(
            '        let _ = include_str!("../../../../contracts/gateway-example-behavior.json");',
            '        let _ = r#"include_str!("../../../../contracts/gateway-example-behavior.json")"#;',
        ),
        encoding="utf-8",
    )
    with pytest.raises(AssertionError, match="not loaded by its Rust test"):
        _assert_rust_behavior_vector_test_owners()

    source.write_text(
        original.replace(
            '        let _ = include_str!("../../../../contracts/gateway-example-behavior.json");',
            '        let url = "https://example.test"; // include_str!("../../../../contracts/gateway-example-behavior.json")',
        ),
        encoding="utf-8",
    )
    with pytest.raises(AssertionError, match="not loaded by its Rust test"):
        _assert_rust_behavior_vector_test_owners()

    source.write_text(original, encoding="utf-8")
    lib_source = source.parent / "lib.rs"
    lib_source.write_text("// pub mod vector_tests;\n", encoding="utf-8")
    with pytest.raises(AssertionError, match="module is not registered"):
        _assert_rust_behavior_vector_test_owners()

    lib_source.write_text(
        '#[cfg(feature = "hidden")]\npub mod vector_tests;\n', encoding="utf-8"
    )
    with pytest.raises(AssertionError, match="conditionally registered"):
        _assert_rust_behavior_vector_test_owners()


def test_vector_owner_guard_rejects_unowned_vectors_and_missing_workspace_gate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _vector_owner_fixture(monkeypatch, tmp_path)
    (tmp_path / "contracts/gateway-new-behavior.json").write_text(
        "{}", encoding="utf-8"
    )
    with pytest.raises(AssertionError, match="unowned=.*gateway-new-behavior"):
        _assert_rust_behavior_vector_test_owners()

    (tmp_path / "contracts/gateway-new-behavior.json").unlink()
    (tmp_path / "contracts/vc-api-adapter-behavior.json").unlink()
    with pytest.raises(AssertionError, match="public vectors are missing"):
        _assert_rust_behavior_vector_test_owners()

    (tmp_path / "contracts/vc-api-adapter-behavior.json").write_text(
        "{}", encoding="utf-8"
    )
    workflow = tmp_path / ".github/workflows/ci.yml"
    workflow.write_text("test-rust-services:\n", encoding="utf-8")
    with pytest.raises(AssertionError, match="workspace test owner"):
        _assert_rust_behavior_vector_test_owners()


@pytest.mark.parametrize(
    "old,new",
    [
        ("lane: >-\n          ${{ fromJSON(github.event_name == 'pull_request' &&", 'lane: [flow]'),
        ("github.event_name == 'pull_request' &&", "github.event_name == 'merge_group' &&"),
        ("contains(github.event.pull_request.labels.*.name, 'ci-selfhost-diagnostic') &&", 'true &&'),
        ("contains(github.event.pull_request.labels.*.name, 'ci-renewal-unit-diagnostic') &&", 'true &&'),
        ('\'["contracts","flow","selfhost","renewal-unit"]\' ||', '\'["renewal-unit"]\' ||'),
        ("needs.changes.outputs.rust_runtime == 'true' &&", 'true &&'),
        ('\'["contracts","flow","selfhost"]\' || needs.changes.outputs.rust_matrix) }}', '\'["selfhost"]\' || needs.changes.outputs.rust_matrix) }}'),
        ('needs: [changes, release-preflight]', 'needs: changes'),
        ('needs: [changes, release-preflight]', 'needs: release-preflight'),
        ('source scripts/ci/affected_components.sh', 'true'),
        ('rust_matrix: ${{ steps.classify.outputs.rust_matrix }}', 'rust_matrix: \'["flow"]\''),
        ('plan: ${{ steps.classify.outputs.plan }}', "plan: '{}'"),
        ('cargo test --locked --workspace --exclude marty-selfhost-acceptance --exclude marty-flow-acceptance', 'cargo test --locked -p marty-flow-acceptance'),
        ('python3 -m scripts.ci.check_public_vector_execution', 'python3 -m scripts.ci.missing_vector_execution_check'),
        ("      - name: Require public protocol vector test execution\n        if: matrix.lane == 'contracts'", "      - name: Require public protocol vector test execution\n        if: matrix.lane == 'flow'"),
        ('\'true:true:["contracts","flow","selfhost"]\'', '\'true:true:["contracts"]\''),
        ('"$RUST_MATRIX" == \'["contracts","flow","selfhost"]\' ]]', '"$RUST_MATRIX" == \'["contracts"]\' ]]'),
        ('if [[ "${{ github.event_name }}" == merge_group && "$WEBSITE_ONLY" != true ]]; then', 'if false; then'),
        ('CI_PLAN: ${{ needs.changes.outputs.plan }}', "CI_PLAN: '{}'"),
        ('CI_NEEDS_JSON: ${{ toJSON(needs) }}', "CI_NEEDS_JSON: '{}'"),
        ('run: python3 scripts/ci/affected_components.py gate', 'run: true'),
    ],
)
def test_vector_workspace_owner_rejects_missing_contracts_or_protected_runtime(
    old: str, new: str
) -> None:
    workflow = (
        Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml"
    ).read_text(encoding="utf-8")
    _assert_full_workspace_ci_owner(workflow)
    assert workflow.count(old) >= 1
    with pytest.raises(AssertionError, match="workspace test owner"):
        _assert_full_workspace_ci_owner(workflow.replace(old, new))


@pytest.mark.parametrize(
    "old,new",
    [
        ('rust_matrix=\'["contracts","flow","selfhost"]\'', "rust_matrix='[\"flow\"]'"),
        ("rust_matrix='[\"contracts\"]'", "rust_matrix='[\"flow\"]'"),
        ('elif [[ "$EVENT_NAME" != pull_request ]]; then\n  all=true',
         'elif [[ "$EVENT_NAME" == pull_request ]]; then\n  all=true'),
        ('elif [[ "$EVENT_NAME" != pull_request ]]; then\n  all=true',
         'elif [[ "$EVENT_NAME" != pull_request ]]; then\n  all=false'),
        ('if [[ "$all" == true ]]; then\n  ui=true\n  python=true\n  rust=true',
         'if [[ "$all" == true ]]; then\n  ui=true\n  python=true\n  rust=false'),
        ("python3 scripts/ci/affected_components.py emit", "true"),
    ],
)
def test_vector_workspace_owner_checks_the_extracted_classifier(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, old: str, new: str
) -> None:
    _vector_owner_fixture(monkeypatch, tmp_path)
    workflow = (tmp_path / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    classifier = tmp_path / "scripts/ci/affected_components.sh"
    source = classifier.read_text(encoding="utf-8")
    _assert_full_workspace_ci_owner(workflow)
    assert source.count(old) >= 1
    classifier.write_text(source.replace(old, new), encoding="utf-8")
    with pytest.raises(AssertionError, match="workspace test owner"):
        _assert_full_workspace_ci_owner(workflow)


def test_vector_workspace_owner_rejects_missing_extracted_classifier(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _vector_owner_fixture(monkeypatch, tmp_path)
    workflow = (tmp_path / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    (tmp_path / "scripts/ci/affected_components.sh").unlink()
    with pytest.raises(AssertionError, match="workspace test owner.*classifier is missing"):
        _assert_full_workspace_ci_owner(workflow)


def test_vector_workspace_owner_ignores_stale_matrix_copy_outside_strategy() -> None:
    workflow = (
        Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml"
    ).read_text(encoding="utf-8")
    service_start = workflow.index("  test-rust-services:\n")
    matrix_start = workflow.index("        lane: >-\n", service_start)
    matrix_end = workflow.index("    permissions:\n", matrix_start)
    selector = workflow[matrix_start:matrix_end]
    weakened = (
        workflow[:matrix_start]
        + "        lane: ${{ fromJSON(needs.changes.outputs.rust_matrix) }}\n"
        + "    env:\n"
        + selector
        + workflow[matrix_end:]
    )
    assert selector in weakened
    with pytest.raises(AssertionError, match="workspace test owner"):
        _assert_full_workspace_ci_owner(weakened)


def test_vector_execution_guard_must_follow_workspace_run() -> None:
    workflow = (
        Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml"
    ).read_text(encoding="utf-8")
    workspace_step = "      - name: Run safe Rust contract groups concurrently\n"
    vector_step = (
        "      - name: Require public protocol vector test execution\n"
        "        if: matrix.lane == 'contracts'\n"
        "        shell: bash\n"
        "        run: python3 -m scripts.ci.check_public_vector_execution "
        '"$RUNNER_TEMP/rust-workspace.log"\n'
    )
    assert workflow.count(vector_step) == workflow.count(workspace_step) == 1
    premature = workflow.replace(vector_step, "").replace(
        workspace_step, vector_step + workspace_step
    )
    with pytest.raises(AssertionError, match="workspace test owner"):
        _assert_full_workspace_ci_owner(premature)


def test_vector_owner_guard_rejects_uncalled_loader_and_production_only_reference(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = _vector_owner_fixture(monkeypatch, tmp_path)
    original = source.read_text(encoding="utf-8")
    vector = "gateway-example-behavior.json"
    loader_source = original.replace(
        '        let _ = include_str!("../../../../contracts/gateway-example-behavior.json");\n',
        "        let _ = contract();\n",
    ).replace(
        "    #[test]\n",
        "    fn contract() -> &'static str {\n"
        f'        include_str!("../../../../contracts/{vector}")\n'
        "    }\n    #[test]\n",
    )
    source.write_text(loader_source, encoding="utf-8")
    monkeypatch.setitem(
        protocol_contract.VECTOR_TEST_OWNERS,
        vector,
        VectorTestOwner(
            "rust/services/example/src/vector_tests.rs", "vector_contract", "contract"
        ),
    )
    _assert_rust_behavior_vector_test_owners()

    source.write_text(
        loader_source.replace(
            "let _ = contract();", 'let _ = r#"https://example.test"#; // contract()'
        ),
        encoding="utf-8",
    )
    with pytest.raises(AssertionError, match="not loaded by its Rust test"):
        _assert_rust_behavior_vector_test_owners()

    source.write_text(
        loader_source.replace(
            "let _ = contract();", 'let _ = r#"contract() at https://example.test"#;'
        ),
        encoding="utf-8",
    )
    with pytest.raises(AssertionError, match="not loaded by its Rust test"):
        _assert_rust_behavior_vector_test_owners()

    source.write_text(
        original.replace(
            '        let _ = include_str!("../../../../contracts/gateway-example-behavior.json");\n',
            "",
        )
        + f'const UNUSED: &str = include_str!("../../../../contracts/{vector}");\n',
        encoding="utf-8",
    )
    monkeypatch.setitem(
        protocol_contract.VECTOR_TEST_OWNERS,
        vector,
        VectorTestOwner("rust/services/example/src/vector_tests.rs", "vector_contract"),
    )
    with pytest.raises(AssertionError, match="not loaded by its Rust test"):
        _assert_rust_behavior_vector_test_owners()


def test_ci_pins_the_public_protocol_once_without_repository_secrets() -> None:
    workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert f"MARTY_PROTOCOL_REF: {CANONICAL_PROTOCOL_COMMIT}" in workflow
    assert "repository: Marty-Protocol/Marty-Protocol" in workflow
    assert "repository: ElevenID/marty-protocol" not in workflow
    assert "ELEVENID_MARTY_PROTOCOL_REF" not in workflow
    assert "--issued-credential-extension-only" not in workflow
    assert workflow.count("repository: Marty-Protocol/Marty-Protocol") == 1
    public_checkout = """\
          persist-credentials: false
          repository: Marty-Protocol/Marty-Protocol
          ref: ${{ env.MARTY_PROTOCOL_REF }}
          path: marty-protocol
"""
    assert public_checkout in workflow


def test_legacy_protocol_version_gate_remains_exact(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "marty-protocol"\nversion = "0.5.0"\n',
        encoding="utf-8",
    )
    conformance = tmp_path / "conformance" / "valid"
    conformance.mkdir(parents=True)
    (conformance / "mip-configuration.json").write_text(
        json.dumps({"mip_version": "0.5.0", "supported_versions": ["0.5.0"]}),
        encoding="utf-8",
    )
    _assert_protocol_version(tmp_path)

    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "marty-protocol"\nversion = "0.5.1"\n',
        encoding="utf-8",
    )
    with pytest.raises(AssertionError, match="MIP version drifted"):
        _assert_protocol_version(tmp_path)


def test_issued_credential_protocol_extensions_are_closed_and_canonical(
    tmp_path: Path,
) -> None:
    schemas = tmp_path / "schemas"
    enums = tmp_path / "enums"
    schemas.mkdir()
    enums.mkdir()
    lifecycle = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "reason": {"type": ["string", "null"], "maxLength": 2000},
        },
    }
    formats = {
        "type": "string",
        "enum": ["SD_JWT_VC", "VDS_NC"],
        "$defs": {
            "wire_format_mapping": {"VDS_NC": "vds_nc"},
            "values": {"VDS_NC": {"standards": ["ICAO Doc 9303, Part 13"]}},
        },
    }
    (schemas / "issued-credential-lifecycle-request.json").write_text(
        json.dumps(lifecycle), encoding="utf-8"
    )
    (enums / "credential-formats.json").write_text(
        json.dumps(formats), encoding="utf-8"
    )
    adapter_contract = {
        "lifecycle_request": {
            "extra_fields": "forbidden",
            "reason": {"nullable": True, "max_unicode_scalars": 2000},
            "comments": {
                "nullable": True,
                "max_unicode_scalars": 4000,
                "blank_normalized_to_null": True,
            },
        }
    }
    adapter_contract_path = tmp_path / "issuance-issued-credential-adapters.json"
    adapter_contract_path.write_text(json.dumps(adapter_contract), encoding="utf-8")
    _assert_issued_credential_extension_contract(tmp_path, adapter_contract_path)

    adapter_contract["lifecycle_request"]["comments"]["max_unicode_scalars"] = 3999
    adapter_contract_path.write_text(json.dumps(adapter_contract), encoding="utf-8")
    with pytest.raises(AssertionError, match="comments extension drifted"):
        _assert_issued_credential_extension_contract(tmp_path, adapter_contract_path)
