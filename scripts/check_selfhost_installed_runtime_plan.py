#!/usr/bin/env python3
"""Fail-closed, unqualified plan for the exact extracted self-host Compose DAG.

This does not start services or qualify an installation. The existing prepared
consumer verifies ZIP, receipt, descriptor, image and mount identity first.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from check_prepared_selfhost_consumer import check, verify_descriptor


EXPECTED_SERVICES = frozenset({
    "applicant", "auth", "canvas-sync-worker", "cloudflared", "cloudflared-beta",
    "compliance-profile", "credential-template", "db-migrate",
    "deployment-profile", "device-registration", "edge", "event-stream", "flow",
    "gateway", "issuance", "issuance-migrations", "issuance-native", "keycloak",
    "keycloak-configurator", "notification", "organization", "postgres",
    "presentation-policy", "redis", "revocation-profile",
    "revocation-profile-migrate", "signing-keys", "trust-profile",
    "tunnel-nginx-proxy", "ui", "verification",
})
BETA_SERVICES = frozenset({"cloudflared-beta", "tunnel-nginx-proxy"})
CONDITIONS = frozenset({"service_healthy", "service_completed_successfully"})
H, C = "service_healthy", "service_completed_successfully"
# Reviewed all-profile Compose edge set. An intentional source dependency change
# must update this contract and its source-render test in the same review.
EXPECTED_DEPENDENCIES = {
    "applicant": {"db-migrate": C},
    "auth": {"db-migrate": C, "flow": H, "keycloak-configurator": C, "redis": H},
    "canvas-sync-worker": {"db-migrate": C, "issuance-migrations": C},
    "cloudflared": {"edge": H},
    "cloudflared-beta": {"tunnel-nginx-proxy": H},
    "compliance-profile": {"db-migrate": C},
    "credential-template": {"db-migrate": C},
    "db-migrate": {"postgres": H, "redis": H, "revocation-profile-migrate": C},
    "deployment-profile": {"db-migrate": C},
    "device-registration": {"db-migrate": C, "redis": H},
    "edge": {"flow": H, "gateway": H, "keycloak": H, "ui": H},
    "flow": {"credential-template": H, "db-migrate": C, "organization": H,
             "presentation-policy": H, "redis": H},
    "gateway": {"applicant": H, "auth": H, "compliance-profile": H,
                "credential-template": H, "deployment-profile": H,
                "event-stream": H, "flow": H, "issuance": H, "issuance-native": H,
                "notification": H, "organization": H, "presentation-policy": H,
                "revocation-profile": H, "trust-profile": H, "verification": H},
    "issuance": {"db-migrate": C, "issuance-migrations": C},
    "issuance-migrations": {"credential-template": H, "db-migrate": C,
                            "organization": H},
    "issuance-native": {"db-migrate": C, "issuance-migrations": C,
                        "postgres": H, "revocation-profile": H, "signing-keys": H},
    "keycloak": {"postgres": H},
    "keycloak-configurator": {"keycloak": H},
    "notification": {"db-migrate": C},
    "organization": {"db-migrate": C, "redis": H},
    "presentation-policy": {"db-migrate": C},
    "revocation-profile": {"db-migrate": C, "redis": H},
    "revocation-profile-migrate": {"postgres": H},
    "signing-keys": {"db-migrate": C, "redis": H},
    "trust-profile": {"db-migrate": C},
    "tunnel-nginx-proxy": {"edge": H},
    "verification": {"credential-template": H, "presentation-policy": H, "redis": H},
}


def plan(model: dict, preflight: dict) -> dict:
    """Validate every rendered role and edge, then emit non-secret identity/counts."""
    services = model.get("services")
    if not isinstance(services, dict) or set(services) != EXPECTED_SERVICES:
        raise ValueError("installed runtime service set differs from reviewed DAG")
    if (preflight.get("schema") != "marty.selfhost-consumer-preflight/v1"
            or preflight.get("qualification") != "unqualified"
            or preflight.get("service_count") != len(services)):
        raise ValueError("runtime DAG is not bound to full prepared preflight")
    for digest_name in ("archive_sha256", "image_lock_sha256", "transaction_sha256"):
        if re.fullmatch(r"[0-9a-f]{64}", str(preflight.get(digest_name, ""))) is None:
            raise ValueError("runtime DAG lacks exact artifact identity")

    secrets = model.get("secrets", {})
    configs = model.get("configs", {})
    if not isinstance(secrets, dict) or not isinstance(configs, dict):
        raise ValueError("installed runtime secret/config declarations are invalid")
    edges: dict[str, set[str]] = {}
    profile_members: dict[str, set[str]] = {"default": set(), "beta-tunnel": set()}
    for name, service in services.items():
        if not isinstance(service, dict):
            raise ValueError(f"installed runtime service {name} is invalid")
        profiles = service.get("profiles", [])
        if not isinstance(profiles, list) or any(not isinstance(p, str) for p in profiles):
            raise ValueError(f"installed runtime service {name} has invalid profiles")
        expected_profiles = ["beta-tunnel"] if name in BETA_SERVICES else []
        if profiles != expected_profiles:
            raise ValueError(f"installed runtime service {name} changed profile")
        if profiles:
            profile_members["beta-tunnel"].add(name)
        else:
            profile_members["default"].add(name)
        for kind, declared in (("secrets", secrets), ("configs", configs)):
            references = service.get(kind, [])
            if not isinstance(references, list):
                raise ValueError(f"installed runtime service {name} has invalid {kind}")
            for reference in references:
                if (not isinstance(reference, dict)
                        or not isinstance(reference.get("source"), str)
                        or reference["source"] not in declared):
                    raise ValueError(f"installed runtime service {name} has undeclared {kind}")
        dependencies = service.get("depends_on", {})
        if not isinstance(dependencies, dict):
            raise ValueError(f"installed runtime service {name} has invalid dependencies")
        if {peer: item.get("condition") if isinstance(item, dict) else None
            for peer, item in dependencies.items()} != EXPECTED_DEPENDENCIES.get(name, {}):
            raise ValueError(f"installed runtime service {name} changed dependency edges")
        edges[name] = set()
        for peer, dependency in dependencies.items():
            if (peer not in services or peer == name or not isinstance(dependency, dict)
                    or dependency.get("condition") not in CONDITIONS
                    or dependency.get("required") is not True):
                raise ValueError(f"installed runtime service {name} has invalid dependency")
            if peer in BETA_SERVICES and name not in BETA_SERVICES:
                raise ValueError("default runtime depends on beta-tunnel service")
            healthcheck = services[peer].get("healthcheck")
            if dependency["condition"] == "service_healthy" and (
                    not isinstance(healthcheck, dict) or healthcheck.get("disable") is True):
                raise ValueError(f"installed runtime dependency {peer} has no healthcheck")
            if dependency["condition"] == "service_completed_successfully" and str(
                    services[peer].get("restart")) != "no":
                raise ValueError(f"installed runtime dependency {peer} is not one-shot")
            edges[name].add(peer)

    # Kahn traversal is deterministic and rejects cycles, including optional roles.
    pending = {name: set(peers) for name, peers in edges.items()}
    layers: list[list[str]] = []
    while pending:
        ready = sorted(name for name, peers in pending.items() if not peers)
        if not ready:
            raise ValueError("installed runtime dependency DAG has a cycle")
        layers.append(ready)
        for name in ready:
            del pending[name]
        for peers in pending.values():
            peers.difference_update(ready)
    return {
        "schema": "marty.selfhost-installed-runtime-plan/v1",
        "qualification": "unqualified",
        "archive_sha256": preflight["archive_sha256"],
        "image_lock_sha256": preflight["image_lock_sha256"],
        "transaction_sha256": preflight["transaction_sha256"],
        "release": preflight["release"],
        "source_sha": preflight["source_sha"],
        "run_id": preflight["run_id"],
        "service_count": len(services),
        "default_service_count": len(profile_members["default"]),
        "beta_tunnel_service_count": len(profile_members["beta-tunnel"]),
        "dependency_count": sum(map(len, edges.values())),
        "startup_layers": layers,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("archive", "image-lock", "transaction", "receipt", "descriptor",
                 "compose-model", "source-checkout", "install-root", "state-root",
                 "secret-root", "expected-source-sha", "expected-run-id", "output"):
        parser.add_argument(f"--{name}", required=True)
    args = parser.parse_args()
    archive, lock, transaction, receipt = (Path(args.archive), Path(args.image_lock),
                                            Path(args.transaction), Path(args.receipt))
    verify_descriptor(archive, lock, transaction, receipt, Path(args.descriptor))
    preflight = check(archive, lock, transaction, receipt, Path(args.compose_model),
                      Path(args.source_checkout), args.expected_source_sha,
                      args.expected_run_id, Path(args.install_root), Path(args.state_root),
                      Path(args.secret_root))
    # check() has just recomputed and compared this complete receipt.
    verified_receipt = json.loads(receipt.read_text(encoding="utf-8"))
    preflight.update({name: verified_receipt[name] for name in
                      ("image_lock_sha256", "transaction_sha256", "release")})
    result = plan(json.loads(Path(args.compose_model).read_text(encoding="utf-8")), preflight)
    Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                                 encoding="utf-8")


if __name__ == "__main__":
    main()
