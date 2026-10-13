"""Guard current operations-input capture inputs without changing its CI tier."""

import ast
import json
from pathlib import Path

import pytest

from scripts.ci.canvas_oracle_current_inputs import (
    assert_current_inputs,
    flat_local_script_imports,
    launched_scripts,
    normalized_sha256,
)

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "contracts/canvas-operations-input-current-inputs.json"
PRODUCER = "run_canvas_operations_input_oracle.py"
SCENARIO = "canvas-operations-input-scenarios.json"
ADDITIONAL = frozenset(
    {
        "contracts/canvas-operations-input-oracle.json",
        "contracts/canvas-worker-consumer-range-oracle.json",
        "rust/services/issuance/tests/support/canvas_operations_input_http.rs",
        "rust/services/issuance/tests/support/canvas_published_database.rs",
        "scripts/prepare_canvas_published_schema.py",
    }
)


def _producer_graph(root: Path) -> dict:
    source = root / "scripts" / PRODUCER
    assert flat_local_script_imports(source, root / "scripts") == set(), (
        "Review new operations-input producer helper imports"
    )
    assert launched_scripts(source, root / "scripts") == [], (
        "Review new operations-input producer child scripts"
    )
    tree = ast.parse(source.read_text(encoding="utf-8"))
    scenarios = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value.endswith("-scenarios.json")
    }
    assert scenarios == {f"/verification/contracts/{SCENARIO}"}, (
        "Review operations-input scenario selection"
    )
    assert not any(
        isinstance(node, ast.JoinedStr)
        and "scenarios.json" in ast.unparse(node)
        for node in ast.walk(tree)
    ), "Review dynamic operations-input scenario selection"
    return {
        "direct_imports": {PRODUCER: []},
        "launched_scripts": {},
        "scenario_literals": {PRODUCER: [SCENARIO]},
        "scenario_templates": {},
    }


def _assert_dispatch(root: Path, evidence: dict) -> None:
    preparer = (root / "scripts/prepare_canvas_published_schema.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(preparer)
    selector = (
        "MARTY_CANVAS_OPERATIONS_INPUT_ORACLE",
        "operations_input",
        "operations_inputs",
    )
    assert sum(
        isinstance(node, ast.Tuple)
        and tuple(
            item.value if isinstance(item, ast.Constant) else None
            for item in node.elts
        )
        == selector
        for node in ast.walk(tree)
    ) == 1, "Review operations-input preparer dispatch"
    assert 'report[key] = runpy.run_path(' in preparer
    assert 'f"/verification/scripts/run_canvas_{name}_oracle.py"' in preparer

    fixture = json.loads(
        (root / "contracts/canvas-worker-consumer-range-oracle.json").read_text(
            encoding="utf-8"
        )
    )
    assert fixture["schema_preparer_source_sha256"] == evidence["sha256"][
        "scripts/prepare_canvas_published_schema.py"
    ]
    assert fixture["observed_image"].startswith(
        "ghcr.io/elevenid/marty-credentials-issuance@sha256:"
    )
    assert fixture["observed_postgres_image"].startswith("postgres@sha256:")

    harness = (
        root / "rust/services/issuance/tests/support/canvas_published_database.rs"
    ).read_text(encoding="utf-8")
    constructor = harness.split("pub async fn start_with_operations_inputs()", 1)[
        1
    ].split("pub async fn start_with_enqueue_inputs()", 1)[0]
    for marker in (
        '"operations_input"',
        '"operations-input"',
        '"operations_inputs"',
        '"MARTY_CANVAS_OPERATIONS_INPUT_ORACLE=1"',
    ):
        assert marker in constructor
    assert "Self::start_probe(Some((" in constructor
    assert 'format!("scripts/run_canvas_{script}_oracle.py")' in harness
    assert 'format!("contracts/canvas-{scenario}-scenarios.json")' in harness


def _assert_replay_links(root: Path) -> None:
    fast = (root / "rust/services/issuance/src/canvas_operations.rs").read_text(
        encoding="utf-8"
    )
    fast_import = fast.split("mod input_http {", 1)[1].split("\n    }", 1)[0]
    assert '"/tests/support/canvas_operations_input_http.rs"' in fast_import, (
        "Review fast operations-input HTTP helper inclusion"
    )
    fast_cases = fast.split(
        "async fn frozen_operations_input_rejections_do_not_require_postgres()", 1
    )[1].split("async fn every_frozen_operation_is_mounted", 1)[0]
    assert "input_http::request_case(&router, case)" in fast_cases, (
        "Review fast operations-input HTTP helper callsite"
    )

    replay = (
        root / "rust/services/issuance/tests/support/canvas_operations_read_replay.rs"
    ).read_text(encoding="utf-8")
    replay_import = replay.split("/// Exercise the unchanged handlers", 1)[0]
    assert '#[path = "canvas_operations_input_http.rs"]' in replay_import, (
        "Review database operations-input HTTP helper inclusion"
    )
    assert (
        "pub(super) use input_http::{request_body, request_case};" in replay_import
    ), "Review database operations-input HTTP helper export"
    database_cases = replay.split("let mut real_database_cases = 0;", 1)[1].split(
        "assert_eq!(real_database_cases, 39);", 1
    )[0]
    assert "request_case(&router, case).await" in database_cases, (
        "Review database operations-input HTTP helper callsite"
    )


def check_inputs(evidence: dict, root: Path) -> None:
    assert_current_inputs(
        evidence,
        _producer_graph(root),
        root,
        entrypoint=PRODUCER,
        schema="marty.canvas-operations-input-current-inputs/v1",
        label="operations-input",
        disclaimer="do not attest the original historical capture",
        additional_inputs=ADDITIONAL,
    )
    _assert_dispatch(root, evidence)
    _assert_replay_links(root)


def test_operations_input_current_capture_inputs() -> None:
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    check_inputs(evidence, ROOT)
    assert len(evidence["sha256"]) == 7


def test_operations_input_http_helper_drift_fails(tmp_path: Path) -> None:
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    for name in evidence["sha256"]:
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / name).read_bytes())
    helper = (
        tmp_path
        / "rust/services/issuance/tests/support/canvas_operations_input_http.rs"
    )
    helper.write_bytes(helper.read_bytes() + b"\n// drift\n")
    with pytest.raises(AssertionError, match="operations-input input drift"):
        check_inputs(evidence, tmp_path)


@pytest.mark.parametrize(
    ("source", "original", "message"),
    [
        (
            "rust/services/issuance/src/canvas_operations.rs",
            '"/tests/support/canvas_operations_input_http.rs"',
            "fast operations-input HTTP helper inclusion",
        ),
        (
            "rust/services/issuance/src/canvas_operations.rs",
            "input_http::request_case(&router, case)",
            "fast operations-input HTTP helper callsite",
        ),
        (
            "rust/services/issuance/tests/support/canvas_operations_read_replay.rs",
            '#[path = "canvas_operations_input_http.rs"]',
            "database operations-input HTTP helper inclusion",
        ),
        (
            "rust/services/issuance/tests/support/canvas_operations_read_replay.rs",
            "pub(super) use input_http::{request_body, request_case};",
            "database operations-input HTTP helper export",
        ),
        (
            "rust/services/issuance/tests/support/canvas_operations_read_replay.rs",
            "request_case(&router, case).await",
            "database operations-input HTTP helper callsite",
        ),
    ],
)
def test_operations_input_http_helper_links_fail_closed(
    tmp_path: Path, source: str, original: str, message: str
) -> None:
    for name in (
        "rust/services/issuance/src/canvas_operations.rs",
        "rust/services/issuance/tests/support/canvas_operations_read_replay.rs",
    ):
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / name).read_bytes())
    target = tmp_path / source
    text = target.read_text(encoding="utf-8")
    assert original in text
    target.write_text(
        text.replace(original, "removed-helper-link", 1), encoding="utf-8"
    )
    with pytest.raises(AssertionError, match=message):
        _assert_replay_links(tmp_path)


def test_operations_input_producer_drift_fails(tmp_path: Path) -> None:
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    for name in evidence["sha256"]:
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / name).read_bytes())
    producer = tmp_path / "scripts" / PRODUCER
    producer.write_bytes(producer.read_bytes() + b"\n# drift\n")
    with pytest.raises(AssertionError, match="operations-input input drift"):
        check_inputs(evidence, tmp_path)


@pytest.mark.parametrize(
    "addition",
    [
        "import canvas_multibyte_codec_oracle",
        "__import__('new_helper')",
        "from importlib import import_module as loader\nloader('new_helper')",
    ],
)
def test_operations_input_new_import_needs_review(tmp_path: Path, addition: str) -> None:
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    for name in evidence["sha256"]:
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / name).read_bytes())
    helper = tmp_path / "scripts/canvas_multibyte_codec_oracle.py"
    helper.write_text("VALUE = 1\n", encoding="utf-8")
    producer = tmp_path / "scripts" / PRODUCER
    producer.write_text(
        producer.read_text(encoding="utf-8") + "\n" + addition + "\n",
        encoding="utf-8",
    )
    evidence["sha256"][f"scripts/{PRODUCER}"] = normalized_sha256(producer)
    with pytest.raises(AssertionError, match="Review .*import"):
        check_inputs(evidence, tmp_path)


def test_operations_input_new_scenario_needs_review(tmp_path: Path) -> None:
    producer = tmp_path / "scripts" / PRODUCER
    producer.parent.mkdir(parents=True)
    producer.write_text(
        (ROOT / "scripts" / PRODUCER).read_text(encoding="utf-8")
        + '\nADDITIONAL = "/verification/contracts/canvas-other-scenarios.json"\n',
        encoding="utf-8",
    )
    with pytest.raises(AssertionError, match="scenario selection"):
        _producer_graph(tmp_path)


def test_operations_input_new_child_script_needs_review(tmp_path: Path) -> None:
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    producer = scripts / PRODUCER
    producer.write_text(
        (ROOT / "scripts" / PRODUCER).read_text(encoding="utf-8")
        + '\nCHILD = "/verification/scripts/new_helper.py"\n',
        encoding="utf-8",
    )
    (scripts / "new_helper.py").write_text("VALUE = 1\n", encoding="utf-8")
    with pytest.raises(AssertionError, match="child scripts"):
        _producer_graph(tmp_path)


def test_operations_input_dispatch_change_needs_review(tmp_path: Path) -> None:
    preparer = tmp_path / "scripts/prepare_canvas_published_schema.py"
    preparer.parent.mkdir(parents=True)
    source = (ROOT / "scripts/prepare_canvas_published_schema.py").read_text(
        encoding="utf-8"
    )
    assert source.count('"MARTY_CANVAS_OPERATIONS_INPUT_ORACLE"') == 1
    preparer.write_text(
        source.replace(
            '"MARTY_CANVAS_OPERATIONS_INPUT_ORACLE"',
            '"MARTY_CANVAS_OPERATIONS_INPUT_DISABLED"',
            1,
        ),
        encoding="utf-8",
    )
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    fixture = json.loads(
        (ROOT / "contracts/canvas-worker-consumer-range-oracle.json").read_text(
            encoding="utf-8"
        )
    )
    fixture["schema_preparer_source_sha256"] = normalized_sha256(preparer)
    target = tmp_path / "contracts/canvas-worker-consumer-range-oracle.json"
    target.parent.mkdir(parents=True)
    target.write_text(json.dumps(fixture), encoding="utf-8")
    harness = tmp_path / "rust/services/issuance/tests/support/canvas_published_database.rs"
    harness.parent.mkdir(parents=True)
    harness.write_bytes(
        (ROOT / "rust/services/issuance/tests/support/canvas_published_database.rs").read_bytes()
    )
    with pytest.raises(AssertionError, match="preparer dispatch"):
        _assert_dispatch(tmp_path, evidence)
