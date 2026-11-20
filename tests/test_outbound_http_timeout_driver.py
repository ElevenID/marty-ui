from __future__ import annotations
import ast
import json
from pathlib import Path
from contextlib import nullcontext
from types import SimpleNamespace
import pytest
ROOT = Path(__file__).resolve().parents[1]

def test_outbound_native_oracle_decodes_artifacts_and_child_output_as_utf8() -> None:
    source = (ROOT / "scripts/run_outbound_http_timeout_oracle.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(source)
    native = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "run_native"
    )
    reads = [
        node
        for node in ast.walk(native)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "read_text"
    ]
    children = [
        node
        for node in ast.walk(native)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "run"
    ]
    assert len(reads) == 2 and len(children) == 1
    for call in reads + children:
        assert any(
            keyword.arg == "encoding"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value == "utf-8"
            for keyword in call.keywords
        )


def test_outbound_native_oracle_preserves_unicode_line_separators(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = (ROOT / "scripts/run_outbound_http_timeout_oracle.py").read_text(
        encoding="utf-8"
    )
    native = next(
        node
        for node in ast.parse(source).body
        if isinstance(node, ast.FunctionDef) and node.name == "run_native"
    )
    contracts = tmp_path / "contracts"
    contracts.mkdir()
    case = {"name": "synthetic_unicode_record"}
    observation = {
        "name": case["name"],
        "status": 403,
        "body": {"body_excerpt": "NEL\u0085LINE\u2028PARA\u2029"},
    }
    (contracts / "outbound-http-timeout-scenarios.json").write_text(
        json.dumps({"cases": [case]}), encoding="utf-8"
    )
    (contracts / "outbound-http-timeout-oracle.json").write_text(
        json.dumps({"cases": [observation]}, ensure_ascii=False), encoding="utf-8"
    )
    child = SimpleNamespace(
        returncode=0,
        stderr="",
        stdout="OUTBOUND_TIMEOUT_NATIVE="
        + json.dumps(observation, ensure_ascii=False)
        + "\n",
    )
    namespace = {
        "__file__": str(tmp_path / "scripts" / "oracle.py"),
        "Path": Path,
        "json": json,
        "os": SimpleNamespace(environ={}),
        "FROZEN_NATIVE_CASE_COUNT": 1,
        "ROUTINE_NATIVE_CASES": frozenset({case["name"]}),
        "subprocess": SimpleNamespace(run=lambda *args, **kwargs: child),
        "loopback_tls": lambda: nullcontext(
            ("https://127.0.0.1:1", None, tmp_path / "synthetic.pem")
        ),
    }
    exec(
        compile(
            ast.Module(body=[native], type_ignores=[]), "<owned-native-oracle>", "exec"
        ),
        namespace,
    )
    namespace["run_native"](tmp_path / "never-executed")
    assert json.loads(capsys.readouterr().out) == {
        "native_timeout_cases": 1,
        "status": "passed",
    }


@pytest.mark.parametrize("qualification,expected_count", [("0", 2), ("1", 104)])
def test_outbound_native_timeout_tiers_preserve_exact_frozen_observations(
    qualification: str,
    expected_count: int,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = (ROOT / "scripts/run_outbound_http_timeout_oracle.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(source)
    native = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "run_native"
    )
    routine_assignment = next(
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "ROUTINE_NATIVE_CASES"
            for target in node.targets
        )
    )
    assert isinstance(routine_assignment.value, ast.Call)
    routine_names = frozenset(ast.literal_eval(routine_assignment.value.args[0]))
    assert routine_names == {"body_timeout", "untrusted_certificate"}
    cases = json.loads(
        (ROOT / "contracts/outbound-http-timeout-scenarios.json").read_text(
            encoding="utf-8"
        )
    )["cases"]
    expected = json.loads(
        (ROOT / "contracts/outbound-http-timeout-oracle.json").read_text(
            encoding="utf-8"
        )
    )["cases"]
    by_name = dict(zip((case["name"] for case in cases), expected, strict=True))
    seen: list[str] = []

    def child(*_args, env, **_kwargs):
        assert _args[0][1:4] == [
            "outbound_http::tests::native_socket_case",
            "--exact",
            "--ignored",
        ]
        name = json.loads(env["MARTY_OUTBOUND_TIMEOUT_NATIVE_CASE"])["name"]
        seen.append(name)
        return SimpleNamespace(
            returncode=0,
            stderr="",
            stdout="OUTBOUND_TIMEOUT_NATIVE=" + json.dumps(by_name[name]) + "\n",
        )

    namespace = {
        "__file__": str(ROOT / "scripts/run_outbound_http_timeout_oracle.py"),
        "Path": Path,
        "json": json,
        "os": SimpleNamespace(environ={}),
        "subprocess": SimpleNamespace(run=child),
        "loopback_tls": lambda: nullcontext(
            ("https://127.0.0.1:1", None, Path("synthetic.pem"))
        ),
        "ROUTINE_NATIVE_CASES": routine_names,
        "FROZEN_NATIVE_CASE_COUNT": 104,
    }
    exec(
        compile(ast.Module(body=[native], type_ignores=[]), "<native-tier>", "exec"),
        namespace,
    )
    namespace["run_native"](Path("unused"), qualification)
    assert len(seen) == expected_count
    assert seen == (
        [case["name"] for case in cases]
        if qualification == "1"
        else ["body_timeout", "untrusted_certificate"]
    )
    assert json.loads(capsys.readouterr().out) == {
        "native_timeout_cases": expected_count,
        "status": "passed",
    }
