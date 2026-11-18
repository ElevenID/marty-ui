#!/usr/bin/env python3
"""Prepare a reviewable beta fence target approval from read-only evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from typing import Any, Callable

try:
    from .check_passport_beta_fence_authority import (
        file_sha256, manifest_source, merged_deletion_pr,
    )
    from .probe_passport_beta_fence_target import observe
    from .probe_passport_beta_host import HostProbeError, run
except ImportError:
    from check_passport_beta_fence_authority import (
        file_sha256, manifest_source, merged_deletion_pr,
    )
    from probe_passport_beta_fence_target import observe
    from probe_passport_beta_host import HostProbeError, run


def require(condition: bool, message: str) -> None:
    if not condition:
        raise HostProbeError(message)


def prepare(
    baseline_path: Path, *,
    observer: Callable[[], dict[str, Any]] = observe,
    runner: Callable[[list[str]], str] = run,
    source: Callable[[Path, str], dict[str, Any]] = manifest_source,
) -> dict[str, Any]:
    try:
        baseline_json = json.loads(baseline_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise HostProbeError("Signed beta baseline manifest is unavailable") from exc
    require(isinstance(baseline_json, dict)
            and isinstance(baseline_json.get("components"), list),
            "Signed beta baseline manifest is invalid")
    ui = [item for item in baseline_json["components"]
          if isinstance(item, dict) and item.get("name") == "marty-ui"
          and item.get("repository") == "ElevenID/marty-ui"]
    require(len(ui) == 1 and isinstance(ui[0].get("commit"), str),
            "Signed beta baseline source is ambiguous")
    baseline = source(baseline_path, ui[0]["commit"])
    deletion_head, _ = merged_deletion_pr(runner)
    target = observer()
    require(isinstance(target, dict), "Live beta target is invalid")
    docker = target.get("docker")
    require(isinstance(docker, dict) and docker.get("context") == "default",
            "Live beta target must use the protected passport runner Docker context")
    beta = target.get("beta")
    require(isinstance(beta, dict), "Live beta target is invalid")
    services = beta.get("services")
    require(isinstance(services, dict), "Live beta target is invalid")
    require(target.get("schema") == "marty.passport-beta-fence-target/v1"
            and target.get("authority")
                == "discovery_only_requires_protected_baseline"
            and isinstance(services.get("issuance"), dict)
            and services["issuance"].get("configured_image")
                == baseline["issuance_image"]
            and all(isinstance(services.get(name), dict)
                    and services[name].get("configured_image")
                    == baseline["services_image"] for name in
                    ("gateway", "flow", "issuance-native", "signing-keys"))
            and beta.get("ui_project") == "elevenid-beta-ui"
            and isinstance(beta.get("ui_service"), dict)
            and beta["ui_service"].get("configured_image")
                == baseline["ui_image"],
            "Live beta target differs from signed deployed baseline")
    require(re.fullmatch(r"[0-9a-f]{64}",
                         str(target.get("observation_sha256"))) is not None
            and re.fullmatch(r"[0-9a-f]{64}",
                             str(target.get("production_attachments_sha256")))
                is not None
            and re.fullmatch(r"[0-9]+",
                             str(beta.get("postgres_system_identifier"))) is not None
            and re.fullmatch(r"[0-9]+", str(beta.get("database_oid"))) is not None,
            "Live beta target identity is invalid")
    return {
        "schema": "marty.passport-beta-fence-approved-target/v1",
        "observation_sha256": target["observation_sha256"],
        "production_attachments_sha256":
            target["production_attachments_sha256"],
        "postgres_system_identifier": beta["postgres_system_identifier"],
        "database_oid": beta["database_oid"],
        "credentials_deletion_head": deletion_head,
        "beta_baseline_source_commit": baseline["source_commit"],
        "beta_baseline_manifest_sha256": file_sha256(baseline_path),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--beta-baseline-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = prepare(args.beta_baseline_manifest)
        with args.output.open("x", encoding="utf-8") as target:
            json.dump(result, target, sort_keys=True, indent=2)
            target.write("\n")
    except (HostProbeError, OSError, ValueError) as exc:
        raise SystemExit(f"Beta fence target approval is unavailable: {exc}") from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
