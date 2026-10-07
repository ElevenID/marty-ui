"""The shadow planner must broaden when Cargo ownership is insufficient."""

from __future__ import annotations

import io
import json
import re
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "ci"))
import plan_affected_rust as planner  # noqa: E402 - sys.path selects the repo-owned CI script


class AffectedRustPlannerTests(unittest.TestCase):
    def test_credential_template_control_plane_consumers_are_shadow_only(self) -> None:
        metadata = planner.cargo_metadata()
        members = set(metadata["workspace_members"])
        packages = {p["name"]: p for p in metadata["packages"] if p["id"] in members}
        producers = (
            "marty-organization",
            "marty-revocation-profile",
            "marty-trust-profile",
        )
        for producer in producers:
            with self.subTest(producer=producer):
                result = planner.plan(
                    [f"rust/services/{producer.removeprefix('marty-')}/src/lib.rs"],
                    metadata,
                    ROOT,
                )
                self.assertTrue(result["all"])
                self.assertEqual(result["packages"], sorted(packages))
                self.assertIn("unmapped non-Cargo runtime consumers", result["reason"])
                edges = [
                    edge
                    for edge in result["observed_non_cargo_consumers"]
                    if edge["producer"] == producer
                    and edge["package"] == "marty-credential-template"
                ]
                self.assertEqual(len(edges), 1)
                edge = edges[0]
                for marker, source in (
                    ("binding", "evidence"),
                    ("runtime_marker", "runtime_evidence"),
                    ("startup_marker", "runtime_evidence"),
                    ("connection_marker", "request_evidence"),
                    ("request_marker", "request_evidence"),
                    ("membership_marker", "request_evidence"),
                    ("identity_marker", "request_evidence"),
                    ("status_marker", "request_evidence"),
                    ("response_marker", "request_evidence"),
                    ("provider_marker", "provider_evidence"),
                ):
                    if marker in edge:
                        self.assertIn(
                            edge[marker],
                            (ROOT / edge[source]).read_text(encoding="utf-8"),
                        )
                self.assertNotIn(
                    producer,
                    {
                        dep["name"]
                        for dep in packages["marty-credential-template"]["dependencies"]
                    },
                )

    def test_verification_runtime_consumers_are_shadow_only(self) -> None:
        metadata = planner.cargo_metadata()
        members = set(metadata["workspace_members"])
        packages = {p["name"]: p for p in metadata["packages"] if p["id"] in members}
        for producer in (
            "marty-organization",
            "marty-credential-template",
            "marty-presentation-policy",
        ):
            with self.subTest(producer=producer):
                result = planner.plan(
                    [f"rust/services/{producer.removeprefix('marty-')}/src/lib.rs"],
                    metadata,
                    ROOT,
                )
                self.assertTrue(result["all"])
                self.assertEqual(result["packages"], sorted(packages))
                self.assertIn("unmapped non-Cargo runtime consumers", result["reason"])
                edges = [
                    edge
                    for edge in result["observed_non_cargo_consumers"]
                    if edge["producer"] == producer
                    and edge["package"] == "marty-verification-service"
                ]
                self.assertEqual(len(edges), 1)
                edge = edges[0]
                for marker, source in (
                    ("binding", "evidence"),
                    ("runtime_marker", "runtime_evidence"),
                    ("connection_marker", "connection_evidence"),
                    ("registration_marker", "connection_evidence"),
                    ("evaluation_marker", "connection_evidence"),
                    ("identity_marker", "connection_evidence"),
                    ("request_marker", "request_evidence"),
                    ("provider_marker", "provider_evidence"),
                ):
                    if marker in edge:
                        self.assertIn(
                            edge[marker],
                            (ROOT / edge[source]).read_text(encoding="utf-8"),
                        )
                self.assertNotIn(
                    producer,
                    {
                        dep["name"]
                        for dep in packages["marty-verification-service"][
                            "dependencies"
                        ]
                    },
                )

    def metadata(self, root: Path) -> dict:
        def package(name: str, directory: str, dependencies: list[dict]) -> dict:
            return {
                "id": name,
                "name": name,
                "manifest_path": str(root / directory / "Cargo.toml"),
                "dependencies": dependencies,
            }

        packages = [
            package("core", "rust/crates/core", []),
            package("nested", "rust/crates/core/nested", []),
            package(
                "service",
                "rust/crates/service",
                [{"name": "core", "rename": "local_core", "kind": "dev"}],
            ),
            package(
                "acceptance",
                "rust/crates/acceptance",
                [{"name": "service", "kind": "build"}],
            ),
        ]
        return {"packages": packages, "workspace_members": [p["id"] for p in packages]}

    def test_package_inputs_select_alias_dev_and_build_consumers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = planner.plan(
                ["rust/crates/core/fixtures/ü spaced.json"], self.metadata(root), root
            )
            self.assertFalse(result["all"])
            self.assertEqual(result["direct"], ["core"])
            self.assertEqual(result["packages"], ["acceptance", "core", "service"])

    def test_longest_package_root_owns_nested_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = planner.plan(
                ["rust/crates/core/nested/src/lib.rs"], self.metadata(root), root
            )
            self.assertEqual(result["packages"], ["nested"])

    def test_service_runtime_consumers_fail_closed_beyond_cargo(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            metadata = self.metadata(root)
            notification = {
                "id": "marty-notification",
                "name": "marty-notification",
                "manifest_path": str(root / "rust/services/notification/Cargo.toml"),
                "dependencies": [{"name": "core", "kind": None}],
            }
            metadata["packages"].append(notification)
            metadata["workspace_members"].append(notification["id"])
            trust_profile = {
                "id": "marty-trust-profile",
                "name": "marty-trust-profile",
                "manifest_path": str(root / "rust/services/trust-profile/Cargo.toml"),
                "dependencies": [],
            }
            metadata["packages"].append(trust_profile)
            metadata["workspace_members"].append(trust_profile["id"])
            for path in (
                "rust/services/notification/src/main.rs",
                "rust/services/trust-profile/src/lib.rs",
                "rust/crates/core/src/lib.rs",
            ):
                with self.subTest(path=path):
                    result = planner.plan([path], metadata, root)
                    self.assertTrue(result["all"])
                    self.assertEqual(len(result["packages"]), 6)
                    self.assertIn("non-Cargo runtime consumers", result["reason"])

    def test_notification_runtime_edges_are_observed_without_narrowing(self) -> None:
        metadata = planner.cargo_metadata()
        members = set(metadata["workspace_members"])
        packages = {p["name"]: p for p in metadata["packages"] if p["id"] in members}
        result = planner.plan(
            ["rust/services/notification/src/main.rs"], metadata, ROOT
        )
        self.assertTrue(result["all"])
        self.assertEqual(result["packages"], sorted(packages))
        self.assertEqual(
            {edge["package"] for edge in result["observed_non_cargo_consumers"]},
            {"marty-applicant", "marty-gateway", "marty-selfhost-bundle"},
        )
        for edge in result["observed_non_cargo_consumers"]:
            with self.subTest(consumer=edge["package"]):
                self.assertEqual(edge["producer"], "marty-notification")
                self.assertIn(edge["package"], packages)
                self.assertIn(
                    edge["binding"],
                    (ROOT / edge["evidence"]).read_text(encoding="utf-8"),
                )
                if "runtime_evidence" in edge:
                    self.assertIn(
                        edge["runtime_marker"],
                        (ROOT / edge["runtime_evidence"]).read_text(encoding="utf-8"),
                    )
                self.assertNotIn(
                    "marty-notification",
                    {dep["name"] for dep in packages[edge["package"]]["dependencies"]},
                )

    def test_notification_edge_diagnostic_does_not_replace_unknown_service_fallback(
        self,
    ) -> None:
        metadata = planner.cargo_metadata()
        result = planner.plan(
            [
                "rust/services/notification/src/main.rs",
                "rust/services/gateway/src/config.rs",
            ],
            metadata,
            ROOT,
        )
        self.assertTrue(result["all"])
        self.assertIn("unmapped non-Cargo runtime consumers", result["reason"])
        self.assertEqual(len(result["packages"]), len(metadata["workspace_members"]))

    def test_event_stream_gateway_grpc_subscription_is_runtime_not_test_only(
        self,
    ) -> None:
        metadata = planner.cargo_metadata()
        members = set(metadata["workspace_members"])
        packages = {p["name"]: p for p in metadata["packages"] if p["id"] in members}
        result = planner.plan(
            ["rust/services/event-stream/src/grpc.rs"], metadata, ROOT
        )
        self.assertTrue(result["all"])
        self.assertEqual(result["packages"], sorted(packages))
        self.assertIn("unmapped non-Cargo runtime consumers", result["reason"])
        edges = [
            edge
            for edge in result["observed_non_cargo_consumers"]
            if edge["producer"] == "marty-event-stream"
            and edge["package"] == "marty-gateway"
        ]
        self.assertEqual(len(edges), 1)
        edge = edges[0]
        for marker, source in (
            ("binding", "evidence"),
            ("runtime_marker", "runtime_evidence"),
            ("request_marker", "request_evidence"),
            ("route_marker", "callsite_evidence"),
            ("callsite_marker", "callsite_evidence"),
            ("provider_marker", "provider_evidence"),
            ("server_marker", "server_evidence"),
            ("condition_marker", "condition_evidence"),
        ):
            self.assertIn(
                edge[marker], (ROOT / edge[source]).read_text(encoding="utf-8")
            )
        runtime = (ROOT / edge["callsite_evidence"]).read_text(encoding="utf-8")
        self.assertIn("return sse_events_handler(state, request).await", runtime)
        self.assertIn("let provider = Arc::clone(&state.event_streams);", runtime)
        main = (ROOT / edge["runtime_evidence"]).read_text(encoding="utf-8")
        self.assertIn("GrpcEventStreamProvider::new(", main)
        self.assertIn("event_streams,", main)
        self.assertNotIn(
            "marty-event-stream",
            {dep["name"] for dep in packages["marty-gateway"]["dependencies"]},
        )

    def test_event_stream_auth_and_organization_publishers_are_observed_only(
        self,
    ) -> None:
        metadata = planner.cargo_metadata()
        members = set(metadata["workspace_members"])
        packages = {p["name"]: p for p in metadata["packages"] if p["id"] in members}
        result = planner.plan(
            ["rust/services/event-stream/src/grpc.rs"], metadata, ROOT
        )
        self.assertTrue(result["all"])
        self.assertEqual(result["packages"], sorted(packages))
        self.assertIn("unmapped non-Cargo runtime consumers", result["reason"])
        observed = [
            edge
            for edge in result["observed_non_cargo_consumers"]
            if edge["producer"] == "marty-event-stream"
        ]
        edges = {edge["package"]: edge for edge in observed}
        self.assertEqual(len(observed), 3)
        self.assertEqual(
            set(edges), {"marty-auth", "marty-organization", "marty-gateway"}
        )
        self.assertEqual(
            {
                package
                for package, item in packages.items()
                if any(
                    dependency["name"] == "marty-event-stream"
                    for dependency in item["dependencies"]
                )
            },
            {"marty-applicant"},
        )
        self.assertEqual(
            set(edges) | {"marty-applicant", "marty-event-stream"},
            {
                "marty-auth",
                "marty-organization",
                "marty-gateway",
                "marty-applicant",
                "marty-event-stream",
            },
        )
        for consumer in ("marty-auth", "marty-organization"):
            edge = edges[consumer]
            self.assertNotIn(
                "marty-event-stream",
                {
                    dependency["name"]
                    for dependency in packages[consumer]["dependencies"]
                },
            )
            markers = (
                ("binding", "evidence"),
                ("runtime_marker", "runtime_evidence"),
                ("connection_marker", "runtime_evidence"),
                ("startup_marker", "startup_evidence"),
                ("request_marker", "request_evidence"),
                ("response_marker", "request_evidence"),
                ("provider_marker", "provider_evidence"),
                ("server_marker", "server_evidence"),
                ("condition_marker", "condition_evidence"),
            )
            sources = {
                path: (ROOT / path).read_text(encoding="utf-8")
                for path in {edge[source_field] for _, source_field in markers}
            }

            def assert_markers() -> None:
                for marker_field, source_field in markers:
                    self.assertIn(edge[marker_field], sources[edge[source_field]])

            assert_markers()
            for marker_field, source_field in (
                ("runtime_marker", "runtime_evidence"),
                ("request_marker", "request_evidence"),
                ("provider_marker", "provider_evidence"),
            ):
                path = edge[source_field]
                original = sources[path]
                for replacement in ("", "health_check(HealthCheckRequest {})"):
                    with self.subTest(
                        consumer=consumer,
                        marker=marker_field,
                        replacement=replacement,
                    ):
                        sources[path] = original.replace(
                            edge[marker_field], replacement
                        )
                        with self.assertRaises(AssertionError):
                            assert_markers()
                sources[path] = original
            assert_markers()

    def test_flow_gateway_route_is_observed_without_narrowing(self) -> None:
        metadata = planner.cargo_metadata()
        members = set(metadata["workspace_members"])
        packages = {p["name"]: p for p in metadata["packages"] if p["id"] in members}
        result = planner.plan(["rust/services/flow/src/lib.rs"], metadata, ROOT)
        self.assertTrue(result["all"])
        self.assertEqual(result["packages"], sorted(packages))
        edges = [
            edge
            for edge in result["observed_non_cargo_consumers"]
            if edge["producer"] == "marty-flow" and edge["package"] == "marty-gateway"
        ]
        self.assertEqual(len(edges), 1)
        edge = edges[0]
        self.assertIn(
            edge["binding"], (ROOT / edge["evidence"]).read_text(encoding="utf-8")
        )
        self.assertIn(
            edge["runtime_marker"],
            (ROOT / edge["runtime_evidence"]).read_text(encoding="utf-8"),
        )
        self.assertNotIn(
            "marty-flow",
            {dep["name"] for dep in packages["marty-gateway"]["dependencies"]},
        )

    def test_published_gateway_upstream_routes_are_observed_without_narrowing(
        self,
    ) -> None:
        metadata = planner.cargo_metadata()
        members = set(metadata["workspace_members"])
        packages = {p["name"]: p for p in metadata["packages"] if p["id"] in members}
        contract = json.loads(
            (ROOT / "contracts/gateway-routes.json").read_text(encoding="utf-8")
        )
        published_paths = {route["path"] for route in contract["routes"]}
        self.assertEqual(len(planner.GATEWAY_PUBLIC_ROUTE_CONSUMERS), 12)
        self.assertIn(
            "marty-deployment-profile",
            {dep["name"] for dep in packages["marty-gateway"]["dependencies"]},
        )
        self.assertIn("/v1/deployment-profiles", published_paths)
        bootstrap = (ROOT / "rust/services/gateway/src/main.rs").read_text(
            encoding="utf-8"
        )
        self.assertIn("GatewayProxy::new(", bootstrap)
        self.assertIn("contract.proxy_route_table_with_passport_selectors(", bootstrap)
        self.assertEqual(
            {
                edge["binding"]
                for edge in planner.OBSERVED_NON_CARGO_CONSUMERS["marty-flow"]
                if edge["package"] == "marty-gateway"
            },
            {"FLOW_SERVICE_URL"},
        )
        self.assertEqual(
            {
                edge["binding"]
                for edge in planner.OBSERVED_NON_CARGO_CONSUMERS["marty-notification"]
                if edge["package"] == "marty-gateway"
            },
            {"NOTIFICATION_SERVICE_URL"},
        )
        for producer in planner.GATEWAY_PUBLIC_ROUTE_CONSUMERS:
            with self.subTest(producer=producer):
                self.assertIn(producer, packages)
                changed = Path(packages[producer]["manifest_path"]).relative_to(ROOT)
                result = planner.plan([changed.as_posix()], metadata, ROOT)
                self.assertTrue(result["all"])
                self.assertEqual(result["packages"], sorted(packages))
                self.assertIn("unmapped non-Cargo runtime consumers", result["reason"])
                edges = [
                    edge
                    for edge in result["observed_non_cargo_consumers"]
                    if edge["producer"] == producer
                    and edge["package"] == "marty-gateway"
                ]
                self.assertEqual(len(edges), 1)
                edge = edges[0]
                self.assertIn(edge["route_path"], published_paths)
                owner = re.fullmatch(
                    r'\("([^\"]+)", "([^\"]+)"\)', edge["runtime_marker"]
                )
                self.assertIsNotNone(owner)
                self.assertTrue(edge["route_path"].startswith(owner.group(1)))
                configured = (ROOT / edge["evidence"]).read_text(encoding="utf-8")
                self.assertRegex(
                    configured,
                    r'\(\s*"'
                    + re.escape(owner.group(2))
                    + r'"\s*,\s*"'
                    + re.escape(edge["binding"])
                    + r'"',
                )
                for marker, source in (
                    ("binding", "evidence"),
                    ("runtime_marker", "runtime_evidence"),
                    ("dispatch_marker", "dispatch_evidence"),
                ):
                    self.assertIn(
                        edge[marker], (ROOT / edge[source]).read_text(encoding="utf-8")
                    )
                self.assertNotIn(
                    producer,
                    {dep["name"] for dep in packages["marty-gateway"]["dependencies"]},
                )

    def test_organization_trust_profile_control_plane_is_observed(self) -> None:
        metadata = planner.cargo_metadata()
        members = set(metadata["workspace_members"])
        packages = {p["name"]: p for p in metadata["packages"] if p["id"] in members}
        result = planner.plan(["rust/services/organization/src/lib.rs"], metadata, ROOT)
        self.assertTrue(result["all"])
        self.assertEqual(result["packages"], sorted(packages))
        edges = [
            edge
            for edge in result["observed_non_cargo_consumers"]
            if edge["producer"] == "marty-organization"
            and edge["package"] == "marty-trust-profile"
        ]
        self.assertEqual(len(edges), 1)
        edge = edges[0]
        self.assertIn(
            edge["binding"], (ROOT / edge["evidence"]).read_text(encoding="utf-8")
        )
        self.assertIn(
            edge["runtime_marker"],
            (ROOT / edge["runtime_evidence"]).read_text(encoding="utf-8"),
        )
        control_plane = (
            ROOT / "rust/services/trust-profile/src/control_plane.rs"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "OrganizationServiceClient::new(endpoint.connect_lazy())", control_plane
        )
        self.assertIn(".get_member(self.request(GetMemberRequest", control_plane)
        self.assertNotIn(
            "marty-organization",
            {dep["name"] for dep in packages["marty-trust-profile"]["dependencies"]},
        )

    def test_credential_template_flow_runtime_edge_is_observed_without_narrowing(
        self,
    ) -> None:
        metadata = planner.cargo_metadata()
        members = set(metadata["workspace_members"])
        packages = {p["name"]: p for p in metadata["packages"] if p["id"] in members}
        result = planner.plan(
            ["rust/services/credential-template/src/lib.rs"], metadata, ROOT
        )
        self.assertTrue(result["all"])
        self.assertEqual(result["packages"], sorted(packages))
        self.assertIn("unmapped non-Cargo runtime consumers", result["reason"])
        edges = [
            edge
            for edge in result["observed_non_cargo_consumers"]
            if edge["producer"] == "marty-credential-template"
            and edge["package"] == "marty-flow"
        ]
        self.assertEqual(len(edges), 1)
        edge = edges[0]
        for marker, source in (
            ("binding", "evidence"),
            ("runtime_marker", "runtime_evidence"),
            ("request_marker", "request_evidence"),
            ("callsite_marker", "callsite_evidence"),
            ("provider_marker", "provider_evidence"),
        ):
            self.assertIn(
                edge[marker], (ROOT / edge[source]).read_text(encoding="utf-8")
            )
        self.assertNotIn(
            "marty-credential-template",
            {dep["name"] for dep in packages["marty-flow"]["dependencies"]},
        )

    def test_issuance_initiation_control_plane_consumers_are_shadow_only(self) -> None:
        metadata = planner.cargo_metadata()
        members = set(metadata["workspace_members"])
        packages = {p["name"]: p for p in metadata["packages"] if p["id"] in members}
        expected_observed_closure = {
            "marty-organization": {
                "marty-organization",
                "marty-issuance-service",
                "marty-auth",
                "marty-trust-profile",
                "marty-presentation-policy",
                "marty-flow",
                "marty-gateway",
            },
            "marty-credential-template": {
                "marty-credential-template",
                "marty-issuance-service",
                "marty-flow",
                "marty-auth",
                "marty-gateway",
            },
            "marty-revocation-profile": {
                "marty-revocation-profile",
                "marty-issuance-service",
                "marty-flow",
                "marty-auth",
                "marty-gateway",
            },
        }
        for producer, expected in expected_observed_closure.items():
            with self.subTest(producer=producer):
                result = planner.plan(
                    [f"rust/services/{producer.removeprefix('marty-')}/src/lib.rs"],
                    metadata,
                    ROOT,
                )
                self.assertTrue(result["all"])
                self.assertEqual(result["packages"], sorted(packages))
                self.assertIn("unmapped non-Cargo runtime consumers", result["reason"])
                edges = [
                    edge
                    for edge in result["observed_non_cargo_consumers"]
                    if edge["producer"] == producer
                    and edge["package"] == "marty-issuance-service"
                ]
                self.assertEqual(len(edges), 1)
                edge = edges[0]
                for marker, source in (
                    ("binding", "evidence"),
                    ("runtime_marker", "runtime_evidence"),
                    ("startup_marker", "runtime_evidence"),
                    ("ports_marker", "runtime_evidence"),
                    ("connection_marker", "request_evidence"),
                    ("request_marker", "request_evidence"),
                    ("provider_marker", "provider_evidence"),
                ):
                    with self.subTest(marker=marker):
                        source_text = (ROOT / edge[source]).read_text(encoding="utf-8")
                        self.assertIn(edge[marker], source_text)
                for marker in (
                    "response_marker",
                    "fallback_marker",
                    "identity_marker",
                    "status_marker",
                ):
                    if marker in edge:
                        source_text = (ROOT / edge["request_evidence"]).read_text(
                            encoding="utf-8"
                        )
                        self.assertIn(edge[marker], source_text)
                self.assertNotIn(
                    producer,
                    {
                        dep["name"]
                        for dep in packages["marty-issuance-service"]["dependencies"]
                    },
                )
                # Hypothetical observed non-Cargo reachability is not an
                # active selector; every service input still selects all.
                reachable = {producer}
                frontier = [producer]
                while frontier:
                    for observed in planner.OBSERVED_NON_CARGO_CONSUMERS.get(
                        frontier.pop(), []
                    ):
                        consumer = observed["package"]
                        if consumer not in reachable:
                            reachable.add(consumer)
                            frontier.append(consumer)
                self.assertEqual(reachable, expected)

    def test_three_flow_grpc_runtime_consumers_are_observed_without_narrowing(
        self,
    ) -> None:
        metadata = planner.cargo_metadata()
        members = set(metadata["workspace_members"])
        packages = {p["name"]: p for p in metadata["packages"] if p["id"] in members}
        for producer, changed in (
            ("marty-organization", "rust/services/organization/src/lib.rs"),
            (
                "marty-presentation-policy",
                "rust/services/presentation-policy/src/lib.rs",
            ),
            ("marty-issuance-service", "rust/services/issuance/src/lib.rs"),
        ):
            with self.subTest(producer=producer):
                result = planner.plan([changed], metadata, ROOT)
                self.assertTrue(result["all"])
                self.assertEqual(result["packages"], sorted(packages))
                self.assertIn("unmapped non-Cargo runtime consumers", result["reason"])
                edges = [
                    edge
                    for edge in result["observed_non_cargo_consumers"]
                    if edge["producer"] == producer and edge["package"] == "marty-flow"
                ]
                self.assertEqual(len(edges), 1)
                edge = edges[0]
                for marker, source in (
                    ("binding", "evidence"),
                    ("runtime_marker", "runtime_evidence"),
                    ("connection_marker", "runtime_evidence"),
                    ("startup_marker", "startup_evidence"),
                    ("request_marker", "request_evidence"),
                    ("callsite_marker", "callsite_evidence"),
                    ("identity_marker", "runtime_evidence"),
                    ("provider_marker", "provider_evidence"),
                ):
                    self.assertIn(
                        edge[marker], (ROOT / edge[source]).read_text(encoding="utf-8")
                    )
                if producer == "marty-presentation-policy":
                    for marker in (
                        "evaluation_request_marker",
                        "evaluation_identity_marker",
                    ):
                        self.assertIn(
                            edge[marker],
                            (ROOT / edge["runtime_evidence"]).read_text(
                                encoding="utf-8"
                            ),
                        )
                self.assertNotIn(
                    producer,
                    {dep["name"] for dep in packages["marty-flow"]["dependencies"]},
                )

    def test_trust_profile_presentation_policy_runtime_edge_is_observed(self) -> None:
        metadata = planner.cargo_metadata()
        members = set(metadata["workspace_members"])
        packages = {p["name"]: p for p in metadata["packages"] if p["id"] in members}
        result = planner.plan(
            ["rust/services/trust-profile/src/lib.rs"], metadata, ROOT
        )
        self.assertTrue(result["all"])
        self.assertEqual(result["packages"], sorted(packages))
        edges = [
            edge
            for edge in result["observed_non_cargo_consumers"]
            if edge["producer"] == "marty-trust-profile"
            and edge["package"] == "marty-presentation-policy"
        ]
        self.assertEqual(len(edges), 1)
        edge = edges[0]
        self.assertIn(
            edge["binding"], (ROOT / edge["evidence"]).read_text(encoding="utf-8")
        )
        self.assertIn(
            edge["runtime_marker"],
            (ROOT / edge["runtime_evidence"]).read_text(encoding="utf-8"),
        )
        request = (ROOT / edge["request_evidence"]).read_text(encoding="utf-8")
        self.assertIn("self.http.get(url)", request)
        resolver = request.split("async fn load_profile(", 1)[1].split(
            "async fn evaluate_issuer(", 1
        )[0]
        self.assertIn(".http_request(format!", resolver)
        self.assertIn(edge["request_marker"], resolver)
        self.assertIn("self.trust_profile_url", resolver)
        self.assertIn(".send()", resolver)
        self.assertIn(edge["identity_marker"], resolver)
        self.assertNotIn(
            "marty-trust-profile",
            {
                dep["name"]
                for dep in packages["marty-presentation-policy"]["dependencies"]
            },
        )

    def test_signing_keys_flow_signer_and_envelope_edges_are_observed_only(
        self,
    ) -> None:
        metadata = planner.cargo_metadata()
        members = set(metadata["workspace_members"])
        packages = {p["name"]: p for p in metadata["packages"] if p["id"] in members}
        result = planner.plan(
            ["rust/services/signing-keys/src/http.rs"], metadata, ROOT
        )
        self.assertTrue(result["all"])
        self.assertEqual(result["packages"], sorted(packages))
        self.assertIn("unmapped non-Cargo runtime consumers", result["reason"])
        signing_edges = [
            edge
            for edge in result["observed_non_cargo_consumers"]
            if edge["producer"] == "marty-signing-keys"
        ]
        self.assertEqual(
            {edge["package"] for edge in signing_edges},
            {"marty-flow", "marty-gateway"},
        )
        edge = next(edge for edge in signing_edges if edge["package"] == "marty-flow")
        for marker, source in (
            ("binding", "evidence"),
            ("runtime_marker", "runtime_evidence"),
            ("startup_marker", "runtime_evidence"),
            ("signing_registration_marker", "runtime_evidence"),
            ("envelope_registration_marker", "runtime_evidence"),
            ("request_marker", "request_evidence"),
            ("sign_marker", "request_evidence"),
            ("response_marker", "request_evidence"),
            ("wrap_marker", "request_evidence"),
            ("unwrap_marker", "request_evidence"),
            ("callsite_marker", "callsite_evidence"),
            ("envelope_callsite_marker", "callsite_evidence"),
            ("callback_marker", "callback_evidence"),
            ("provider_marker", "provider_evidence"),
            ("provider_handler_marker", "provider_evidence"),
            ("provider_wrap_marker", "provider_evidence"),
            ("provider_wrap_handler_marker", "provider_evidence"),
            ("provider_unwrap_marker", "provider_evidence"),
            ("provider_unwrap_handler_marker", "provider_evidence"),
        ):
            with self.subTest(marker=marker):
                text = (ROOT / edge[source]).read_text(encoding="utf-8")
                self.assertIn(edge[marker], text)
                self.assertNotIn(edge[marker], text.replace(edge[marker], "removed"))
        self.assertNotIn(
            "marty-signing-keys",
            {dep["name"] for dep in packages["marty-flow"]["dependencies"]},
        )
        # This is a hypothetical observed reverse chain, not an active selector.
        flow_consumers = {
            item["package"]
            for item in planner.OBSERVED_NON_CARGO_CONSUMERS["marty-flow"]
        }
        self.assertEqual(
            {"marty-signing-keys"}
            | {item["package"] for item in signing_edges}
            | flow_consumers,
            {"marty-signing-keys", "marty-flow", "marty-gateway", "marty-auth"},
        )

    def test_auth_outbound_runtime_edges_are_observed_without_narrowing(self) -> None:
        metadata = planner.cargo_metadata()
        members = set(metadata["workspace_members"])
        packages = {p["name"]: p for p in metadata["packages"] if p["id"] in members}
        auth_dependencies = {
            dep["name"] for dep in packages["marty-auth"]["dependencies"]
        }
        providers = {
            "marty-flow": "rust/services/flow/src/lib.rs",
            "marty-organization": "rust/services/organization/src/lib.rs",
            "marty-applicant": "rust/services/applicant/src/lib.rs",
            "marty-issuance-service": "rust/services/issuance/src/lib.rs",
        }
        for provider, path in providers.items():
            with self.subTest(provider=provider):
                self.assertNotIn(provider, auth_dependencies)
                self.assertTrue((ROOT / path).is_file())
                result = planner.plan([path], metadata, ROOT)
                self.assertTrue(result["all"])
                self.assertEqual(result["packages"], sorted(packages))
                edges = [
                    edge
                    for edge in result["observed_non_cargo_consumers"]
                    if edge["producer"] == provider and edge["package"] == "marty-auth"
                ]
                self.assertEqual(len(edges), 1)
                edge = edges[0]
                self.assertIn(
                    edge["binding"],
                    (ROOT / edge["evidence"]).read_text(encoding="utf-8"),
                )
                self.assertIn(
                    edge["runtime_marker"],
                    (ROOT / edge["runtime_evidence"]).read_text(encoding="utf-8"),
                )

    def test_shared_and_unowned_inputs_request_full_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for path in (
                "rust/Cargo.lock",
                "rust/third_party/ssi-jwt/src/lib.rs",
                "rust/deleted-crate/fixture.json",
                "contracts/canvas-worker-oracle.json",
                "proto/candidate.proto",
                "services/Dockerfile",
                ".github/workflows/ci.yml",
            ):
                with self.subTest(path=path):
                    result = planner.plan([path], self.metadata(root), root)
                    self.assertTrue(result["all"])
                    self.assertEqual(len(result["packages"]), 4)

    def test_empty_diff_is_explicit_and_does_not_change_current_gates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = planner.plan([], self.metadata(Path(directory)), Path(directory))
            self.assertEqual(result["packages"], [])
            self.assertFalse(result["all"])

    def test_empty_metadata_does_not_prove_no_affected_packages(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            self.assertRaisesRegex(ValueError, "no workspace packages"),
        ):
            planner.plan(
                ["rust/crates/core/src/lib.rs"],
                {"packages": [], "workspace_members": []},
                Path(directory),
            )

    def test_missing_diff_revision_reports_full_selection(self) -> None:
        output = io.StringIO()
        with (
            patch.dict("os.environ", {"BASE_SHA": "", "HEAD_SHA": ""}),
            redirect_stdout(output),
        ):
            self.assertEqual(planner.main(), 0)
        result = json.loads(output.getvalue().removeprefix("affected-rust-shadow: "))
        self.assertTrue(result["all"])
        self.assertEqual(result["packages"], ["*"])

    def test_git_diff_keeps_deleted_and_moved_endpoints(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def git(*args: str) -> str:
                return subprocess.run(
                    ["git", *args],
                    cwd=root,
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout.strip()

            git("init", "-q")
            git("config", "user.name", "Test")
            git("config", "user.email", "test@example.invalid")
            (root / "rust" / "crates" / "core").mkdir(parents=True)
            old = root / "rust" / "crates" / "core" / "ü old.json"
            old.write_text("fixture", encoding="utf-8")
            deleted = root / "rust" / "crates" / "core" / "deleted.json"
            deleted.write_text("deleted", encoding="utf-8")
            git("add", ".")
            git("commit", "-qm", "before")
            base = git("rev-parse", "HEAD")
            old.rename(root / "rust" / "crates" / "core" / "new.json")
            deleted.unlink()
            git("add", "-A")
            git("commit", "-qm", "after")
            with patch.object(planner, "ROOT", root):
                paths = planner.changed_paths(base, "HEAD")
            self.assertEqual(
                set(paths),
                {
                    "rust/crates/core/ü old.json",
                    "rust/crates/core/new.json",
                    "rust/crates/core/deleted.json",
                },
            )


if __name__ == "__main__":
    unittest.main()
