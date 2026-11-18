"""Render the opt-in passport provider K8s pair with one immutable image."""

import argparse
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "k8s/oracle/07c-passport-provider-supported.yaml"
PLACEHOLDER = "${MARTY_SERVICES_IMAGE}"
IMMUTABLE_IMAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[0-9a-f]{64}\Z")


def render(image: str) -> str:
    if IMMUTABLE_IMAGE.fullmatch(image) is None:
        raise ValueError("MARTY_SERVICES_IMAGE must be an immutable image digest")
    source = MANIFEST.read_text(encoding="utf-8")
    if source.count(PLACEHOLDER) != 2:
        raise ValueError("passport provider manifest must contain exactly two image bindings")
    rendered = source.replace(PLACEHOLDER, image)
    if "${" in rendered:
        raise ValueError("passport provider manifest has an unresolved variable")
    return rendered


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="immutable services image with @sha256 digest")
    args = parser.parse_args()
    try:
        sys.stdout.write(render(args.image))
    except ValueError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
