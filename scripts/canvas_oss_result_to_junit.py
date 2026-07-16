#!/usr/bin/env python3
"""Convert the fixed portability result to a compact JUnit report."""

from __future__ import annotations

import argparse
import json
import xml.etree.ElementTree as ET
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = json.loads(args.result.read_text(encoding="utf-8"))
    cases = result["cases"]
    failures = sum(case["status"] in {"failed", "not_run"} and case["classification"] == "oss_required" for case in cases)
    suite = ET.Element("testsuite", name="canvas_oss_portability", tests=str(len(cases)), failures=str(failures))
    for case in cases:
        node = ET.SubElement(suite, "testcase", classname=case["classification"], name=case["id"])
        if case["classification"] == "oss_required" and case["status"] in {"failed", "not_run"}:
            failure = ET.SubElement(node, "failure", message=case["status"])
            failure.text = case["evidence"]
        elif case["classification"] != "oss_required":
            skipped = ET.SubElement(node, "skipped", message=case["status"])
            skipped.text = case["evidence"]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    ET.ElementTree(suite).write(args.output, encoding="utf-8", xml_declaration=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
