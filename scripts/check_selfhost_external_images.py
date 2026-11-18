#!/usr/bin/env python3
"""Fail early when opt-in self-host image inputs cannot form the source lock."""

from __future__ import annotations

import argparse
from pathlib import Path

from build_selfhost_image_lock import _json_object, preflight_external_images


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compose-model", required=True, type=Path)
    parser.add_argument("--external-services", required=True, type=Path)
    parser.add_argument("--base-compose", required=True, type=Path)
    parser.add_argument("--override-compose", required=True, type=Path)
    args = parser.parse_args()
    preflight_external_images(
        _json_object(args.compose_model), _json_object(args.external_services),
        args.base_compose, args.override_compose,
    )


if __name__ == "__main__":
    main()
