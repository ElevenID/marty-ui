"""Keep Marty services on MMF's focused security feature set."""

import json
import sys


def main() -> None:
    metadata = json.load(sys.stdin)
    packages = [package for package in metadata["packages"] if package["name"] == "mmf-security"]
    if len(packages) != 1:
        raise SystemExit("Expected exactly one MMF security package")

    package_id = packages[0]["id"]
    nodes = [node for node in metadata["resolve"]["nodes"] if node["id"] == package_id]
    if len(nodes) != 1:
        raise SystemExit("Expected exactly one resolved MMF security node")

    features = set(nodes[0]["features"])
    expected = {"cedar", "redis"}
    if features != expected:
        raise SystemExit(
            f"MMF security features changed: {sorted(features)}; expected {sorted(expected)}"
        )


if __name__ == "__main__":
    main()
