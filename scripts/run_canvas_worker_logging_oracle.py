"""Observe the exact immutable worker's logging setup, without importing it."""

import ast
import hashlib
import importlib.util
import json
import logging
import os
from pathlib import Path
import sys


def run():
    source = Path(importlib.util.find_spec("issuance.canvas_worker").origin).read_text(
        encoding="utf-8"
    )
    calls = [
        node
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Call)
        and ast.unparse(node.func) == "logging.basicConfig"
    ]
    assert len(calls) == 1
    expression = ast.unparse(calls[0])
    assert (
        expression == "logging.basicConfig(level=os.environ.get('LOG_LEVEL', 'INFO'))"
    )
    executable = compile(
        ast.Expression(calls[0]), "published-logging-expression", "eval"
    )
    spec = json.loads(
        Path("/verification/contracts/canvas-worker-logging-scenarios.json").read_text()
    )
    cases = []
    for value in spec["levels"]:
        root = logging.getLogger()
        for handler in list(root.handlers):
            root.removeHandler(handler)
            handler.close()
        root.setLevel(logging.WARNING)
        if value is None:
            os.environ.pop("LOG_LEVEL", None)
        else:
            os.environ["LOG_LEVEL"] = value
        try:
            eval(executable, {"logging": logging, "os": os})
        except ValueError:
            observed = {"error_class": "ValueError"}
        else:
            observed = {
                "enabled": [
                    name
                    for name, level in [
                        ("debug", logging.DEBUG),
                        ("info", logging.INFO),
                        ("warn", logging.WARNING),
                        ("error", logging.ERROR),
                    ]
                    if root.isEnabledFor(level)
                ]
            }
        cases.append({"input": value, "observed": observed})
    return {
        "schema": "marty.canvas-worker-logging-oracle/v1",
        "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "expression": expression,
        "cases": cases,
    }


if __name__ == "__main__":
    result = run()
    if sys.argv[1:] == ["--check"]:
        reference = json.loads(
            Path(
                "/verification/contracts/canvas-worker-logging-oracle.json"
            ).read_text()
        )
        assert result == reference
        print(
            f"Published worker logging reference passed ({len(result['cases'])} cases)"
        )
    else:
        assert not sys.argv[1:]
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
