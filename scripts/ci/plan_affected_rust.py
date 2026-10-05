"""Report conservative Rust package impact without changing CI execution."""

from __future__ import annotations

import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
from collections import defaultdict, deque


ROOT = Path(__file__).resolve().parents[2]
RUST = ROOT / "rust"

# These are observed HTTP/deployment consumers, not a complete runtime graph.
# Keep the service fallback below until every service and its transitive inputs
# have an obligation owner. The paths document the source of each observation.
OBSERVED_NON_CARGO_CONSUMERS = {
    # Auth connects to these services at runtime. Their package changes can
    # affect Auth even though Cargo has no reverse dependency on them.
    "marty-flow": [
        {
            "package": "marty-auth",
            "evidence": "rust/services/auth/src/config.rs",
            "binding": "FLOW_GRPC_TARGET",
            "runtime_evidence": "rust/services/auth/src/connections.rs",
            "runtime_marker": "&config.flow_grpc_target",
        },
        {
            "package": "marty-gateway",
            "evidence": "rust/services/gateway/src/config.rs",
            "binding": "FLOW_SERVICE_URL",
            "runtime_evidence": "rust/services/gateway/src/contract.rs",
            "runtime_marker": '("/v1/flows", "flows")',
        },
    ],
    "marty-organization": [
        {
            "package": "marty-auth",
            "evidence": "rust/services/auth/src/config.rs",
            "binding": "ORG_GRPC_TARGET",
            "runtime_evidence": "rust/services/auth/src/connections.rs",
            "runtime_marker": "&config.organization_grpc_target",
        },
        {
            "package": "marty-trust-profile",
            "evidence": "rust/services/trust-profile/src/config.rs",
            "binding": "ORG_GRPC_TARGET",
            "runtime_evidence": "rust/services/trust-profile/src/main.rs",
            "runtime_marker": "&config.organization_grpc_target",
        },
    ],
    "marty-applicant": [
        {
            "package": "marty-auth",
            "evidence": "rust/services/auth/src/config.rs",
            "binding": "APPLICANT_SERVICE_URL",
            "runtime_evidence": "rust/services/auth/src/main.rs",
            "runtime_marker": "config.applicant_service_url.clone()",
        },
    ],
    "marty-issuance-service": [
        {
            "package": "marty-auth",
            "evidence": "rust/services/auth/src/config.rs",
            "binding": "ISSUANCE_NATIVE_SERVICE_URL",
            "runtime_evidence": "rust/services/auth/src/main.rs",
            "runtime_marker": "&config.issuance_native_service_url",
        },
    ],
    "marty-notification": [
        {
            "package": "marty-applicant",
            "evidence": "rust/services/applicant/src/main.rs",
            "binding": "NOTIFICATION_EVENT_INGEST_URL",
            "runtime_evidence": "rust/services/applicant/src/providers.rs",
            "runtime_marker": ".post(url)",
        },
        {
            "package": "marty-gateway",
            "evidence": "rust/services/gateway/src/config.rs",
            "binding": "NOTIFICATION_SERVICE_URL",
            "runtime_evidence": "rust/services/gateway/src/contract.rs",
            "runtime_marker": '("/v1/notifications", "notifications")',
        },
        {
            "package": "marty-selfhost-bundle",
            "evidence": "rust/crates/selfhost-bundle/tests/support/resolved_selfhost_runtime.rs",
            "binding": "NOTIFICATION_SERVICE_URL",
        },
    ],
}


def changed_paths(base: str, head: str) -> list[str]:
    # Both move endpoints matter, including a deleted package that metadata no
    # longer describes. NUL delimiters preserve whitespace and Unicode names.
    result = subprocess.run(
        ["git", "diff", "--name-only", "-z", "--no-renames", base, head, "--"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return [path.decode("utf-8") for path in result.stdout.split(b"\0") if path]


def cargo_metadata() -> dict:
    result = subprocess.run(
        [
            "cargo",
            "metadata",
            "--locked",
            "--offline",
            "--no-deps",
            "--format-version",
            "1",
            "--manifest-path",
            str(RUST / "Cargo.toml"),
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return json.loads(result.stdout)


def plan(paths: list[str], metadata: dict, root: Path = ROOT) -> dict:
    members = set(metadata["workspace_members"])
    packages = [package for package in metadata["packages"] if package["id"] in members]
    if not packages:
        raise ValueError("Cargo metadata contains no workspace packages")
    names = {package["name"] for package in packages}
    roots = {
        package["name"]: PurePosixPath(
            Path(package["manifest_path"]).parent.relative_to(root).as_posix()
        )
        for package in packages
    }

    def full(reason: str, *, observed_consumers: list[dict] | None = None) -> dict:
        result = {"all": True, "packages": sorted(names), "reason": reason}
        if observed_consumers:
            result["observed_non_cargo_consumers"] = observed_consumers
        return result

    direct: set[str] = set()
    for raw in paths:
        path = PurePosixPath(raw.replace("\\", "/"))
        if path == PurePosixPath("rust/Cargo.toml") or path == PurePosixPath(
            "rust/Cargo.lock"
        ):
            return full(f"workspace manifest or lock: {path}")
        if not path.parts or path.parts[0] != "rust":
            # Protocol corpora, workflows, Dockerfiles, scripts, release inputs,
            # and undeclared consumers are not represented by Cargo metadata.
            return full(f"external or unknown input: {path}")
        owners = [
            (len(owner.parts), name)
            for name, owner in roots.items()
            if path.is_relative_to(owner)
        ]
        if not owners:
            # Includes third_party, toolchain, .cargo, deleted packages, and
            # workspace-level inputs. The current graph cannot prove isolation.
            return full(f"unowned Rust input: {path}")
        direct.add(max(owners)[1])

    reverse: dict[str, set[str]] = defaultdict(set)
    for package in packages:
        for dependency in package["dependencies"]:
            name = dependency["name"]  # Canonical name, even with a local alias.
            if name in names:
                reverse[name].add(package["name"])

    affected = set(direct)
    queue = deque(direct)
    while queue:
        for consumer in reverse[queue.popleft()]:
            if consumer not in affected:
                affected.add(consumer)
                queue.append(consumer)
    # Services consume one another over HTTP/gRPC and deployment wiring, not
    # only Cargo dependencies. For example, Applicant/Gateway consume
    # Notification and Presentation Policy consumes Trust Profile. Until that
    # runtime graph is proven, no affected service package is narrow evidence.
    services = {
        name
        for name, owner in roots.items()
        if owner.is_relative_to(PurePosixPath("rust/services"))
    }
    if affected & services:
        observed = [
            {"producer": producer, **edge}
            for producer in sorted(affected & services)
            for edge in OBSERVED_NON_CARGO_CONSUMERS.get(producer, [])
            if edge["package"] in names
        ]
        return full(
            "unmapped non-Cargo runtime consumers of service packages",
            observed_consumers=observed,
        )
    return {
        "all": False,
        "packages": sorted(affected),
        "direct": sorted(direct),
        "reason": "workspace package inputs and reverse Cargo consumers",
    }


def main() -> int:
    base = os.environ.get("BASE_SHA", "")
    head = os.environ.get("HEAD_SHA", "")
    if not base or not head:
        result = {"all": True, "packages": ["*"], "reason": "missing base or head SHA"}
    else:
        try:
            subprocess.run(
                ["git", "fetch", "--no-tags", "--depth=1", "origin", base],
                cwd=ROOT,
                check=True,
                capture_output=True,
            )
            result = plan(changed_paths(base, head), cargo_metadata())
        except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
            result = {
                "all": True,
                "packages": ["*"],
                "reason": f"unable to prove affected packages: {type(error).__name__}",
            }
    print("affected-rust-shadow: " + json.dumps(result, sort_keys=True))
    # This remains observational. Existing full Rust lanes are authoritative.
    return 0


if __name__ == "__main__":
    sys.exit(main())
