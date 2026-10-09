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

    def test_selfhost_bundle_document_keeps_rust_consumers_in_shadow_plan(self) -> None:
        metadata = planner.cargo_metadata()
        result = planner.plan(
            ["SELFHOST_BUNDLE.md", "rust/crates/selfhost-bundle/src/lib.rs"],
            metadata,
            ROOT,
        )
        self.assertFalse(result["all"])
        self.assertEqual(result["direct"], ["marty-selfhost-bundle"])
        self.assertIn("marty-canvas-acceptance", result["packages"])
        self.assertNotIn("marty-canvas-worker-acceptance", result["packages"])
        self.assertIn("marty-selfhost-bundle", result["packages"])

    def test_selfhost_bundle_document_requires_existing_owned_asset(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            metadata = self.metadata(root)
            result = planner.plan(["SELFHOST_BUNDLE.md"], metadata, root)
            self.assertTrue(result["all"])
            self.assertIn("missing known package asset", result["reason"])

    def test_selfhost_document_owner_must_remain_in_bundle_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            metadata = self.metadata(root)
            bundle = {
                "id": "marty-selfhost-bundle",
                "name": "marty-selfhost-bundle",
                "manifest_path": str(root / "rust/crates/selfhost-bundle/Cargo.toml"),
                "dependencies": [],
            }
            metadata["packages"].append(bundle)
            metadata["workspace_members"].append(bundle["id"])
            (root / "SELFHOST_BUNDLE.md").write_text("test", encoding="utf-8")
            descriptor = root / "deploy-config/bundles/selfhost.json"
            descriptor.parent.mkdir(parents=True)

            descriptor.write_text(
                json.dumps({"assets": ["SELFHOST_BUNDLE.md"]}), encoding="utf-8"
            )
            owned = planner.plan(["SELFHOST_BUNDLE.md"], metadata, root)
            self.assertFalse(owned["all"])
            self.assertEqual(owned["direct"], ["marty-selfhost-bundle"])

            for content in (
                json.dumps({"assets": []}),
                json.dumps({"assets": ["SELFHOST_BUNDLE.md"] * 2}),
                json.dumps({"assets": "SELFHOST_BUNDLE.md"}),
                "not JSON",
            ):
                with self.subTest(content=content):
                    descriptor.write_text(content, encoding="utf-8")
                    result = planner.plan(["SELFHOST_BUNDLE.md"], metadata, root)
                    self.assertTrue(result["all"])
                    self.assertIn("missing known package asset", result["reason"])

            descriptor.unlink()
            missing = planner.plan(["SELFHOST_BUNDLE.md"], metadata, root)
            self.assertTrue(missing["all"])
            self.assertIn("missing known package asset", missing["reason"])

            target = root / "alternate-descriptor.json"
            target.write_text(
                json.dumps({"assets": ["SELFHOST_BUNDLE.md"]}), encoding="utf-8"
            )
            try:
                descriptor.symlink_to(target)
            except OSError:
                return  # File symlinks are unavailable on this Windows host.
            linked = planner.plan(["SELFHOST_BUNDLE.md"], metadata, root)
            self.assertTrue(linked["all"])
            self.assertIn("missing known package asset", linked["reason"])

    def test_unknown_root_document_still_selects_every_package(self) -> None:
        metadata = planner.cargo_metadata()
        result = planner.plan(["OTHER_SELFHOST_BUNDLE.md"], metadata, ROOT)
        self.assertTrue(result["all"])
        self.assertIn("external or unknown input", result["reason"])

    def test_known_document_does_not_mask_unknown_root_input(self) -> None:
        metadata = planner.cargo_metadata()
        result = planner.plan(
            ["SELFHOST_BUNDLE.md", "OTHER_SELFHOST_BUNDLE.md"], metadata, ROOT
        )
        self.assertTrue(result["all"])
        self.assertIn("external or unknown input", result["reason"])

    def test_symlinked_known_document_stays_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "source.md"
            target.write_text("test", encoding="utf-8")
            try:
                (root / "SELFHOST_BUNDLE.md").symlink_to(target)
            except OSError:
                self.skipTest("This host cannot create file symlinks")
            metadata = self.metadata(root)
            bundle = {
                "id": "marty-selfhost-bundle",
                "name": "marty-selfhost-bundle",
                "manifest_path": str(root / "rust/crates/selfhost-bundle/Cargo.toml"),
                "dependencies": [],
            }
            metadata["packages"].append(bundle)
            metadata["workspace_members"].append(bundle["id"])
            descriptor = root / "deploy-config/bundles/selfhost.json"
            descriptor.parent.mkdir(parents=True)
            descriptor.write_text(
                json.dumps({"assets": ["SELFHOST_BUNDLE.md"]}), encoding="utf-8"
            )
            result = planner.plan(["SELFHOST_BUNDLE.md"], metadata, root)
            self.assertTrue(result["all"])
            self.assertIn("missing known package asset", result["reason"])

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

    def test_flow_auth_credential_login_grpc_edge_is_source_backed_and_shadow_only(
        self,
    ) -> None:
        metadata = planner.cargo_metadata()
        members = set(metadata["workspace_members"])
        packages = {p["name"]: p for p in metadata["packages"] if p["id"] in members}
        result = planner.plan(
            ["rust/services/flow/src/grpc_service.rs"], metadata, ROOT
        )
        self.assertTrue(result["all"])
        self.assertEqual(result["packages"], sorted(packages))
        self.assertIn("unmapped non-Cargo runtime consumers", result["reason"])
        edges = [
            edge
            for edge in result["observed_non_cargo_consumers"]
            if edge["producer"] == "marty-flow" and edge["package"] == "marty-auth"
        ]
        self.assertEqual(len(edges), 1)
        edge = edges[0]
        markers = (
            ("binding", "evidence"),
            ("runtime_marker", "runtime_evidence"),
            ("client_marker", "client_evidence"),
            ("client_wiring_marker", "client_evidence"),
            ("request_marker", "client_evidence"),
            ("request_auth_marker", "client_evidence"),
            ("registration_marker", "registration_evidence"),
            ("callsite_marker", "callsite_evidence"),
            ("route_marker", "route_evidence"),
            ("route_handler_marker", "route_evidence"),
            ("provider_marker", "provider_evidence"),
            ("provider_auth_marker", "provider_evidence"),
            ("provider_start_marker", "provider_evidence"),
            ("provider_registration_marker", "provider_registration_evidence"),
            ("provider_serving_marker", "provider_registration_evidence"),
            ("deployment_marker", "deployment_evidence"),
        )
        sources = {
            path: (ROOT / path).read_text(encoding="utf-8")
            for _, source in markers
            if (path := edge[source])
        }

        def method_body(text: str, start: str, end: str) -> str:
            self.assertIn(start, text)
            body = text.split(start, 1)[1]
            self.assertIn(end, body)
            return body.split(end, 1)[0]

        def assert_markers(snapshot: dict[str, str]) -> None:
            for marker, source in markers:
                content = snapshot[edge[source]]
                if marker in {"request_marker", "request_auth_marker"}:
                    content = method_body(
                        content,
                        "impl CredentialVerificationStarter for GrpcCredentialVerificationStarter {",
                        "pub fn credential_verification_request(",
                    )
                if marker == "client_wiring_marker":
                    content = method_body(
                        content,
                        "    pub fn credential_verification(&self)",
                        "    pub fn organization_provisioning(",
                    )
                if marker == "route_handler_marker":
                    content = method_body(
                        content,
                        "async fn credential_login(State(state): State<AuthHttpState>)",
                        "async fn credential_login_status(",
                    )
                if marker in {"provider_auth_marker", "provider_start_marker"}:
                    content = method_body(
                        content,
                        "    async fn start_verification(",
                        "    async fn application_approved(",
                    )
                if marker == "provider_serving_marker":
                    content = method_body(
                        content, "let grpc = grpc_builder", "    runtime.activate()?"
                    )
                if marker == "deployment_marker":
                    content = method_body(content, "\n  auth:\n", "\n  organization:\n")
                self.assertIn(edge[marker], content)

        assert_markers(sources)
        for marker, source in markers:
            with self.subTest(marker=marker):
                path = edge[source]
                changed = dict(sources)
                changed[path] = sources[path].replace(edge[marker], "removed-edge")
                with self.assertRaises(AssertionError):
                    assert_markers(changed)
        self.assertNotIn(
            "marty-flow",
            {dep["name"] for dep in packages["marty-auth"]["dependencies"]},
        )

    def test_flow_applicant_webhook_is_observed_without_narrowing(self) -> None:
        self.assert_source_bound_service_edge(
            producer="marty-flow",
            consumer="marty-applicant",
            changed="rust/services/flow/src/http_application.rs",
            markers=(
                "binding",
                "runtime_marker",
                "request_marker",
                "callsite_marker",
                "provider_marker",
                "route_registration_marker",
                "server_marker",
            ),
        )

    def test_organization_device_registration_membership_is_observed_only(self) -> None:
        self.assert_source_bound_service_edge(
            producer="marty-organization",
            consumer="marty-device-registration",
            changed="rust/services/organization/src/grpc_service.rs",
            markers=(
                "binding",
                "runtime_marker",
                "registration_marker",
                "connection_marker",
                "request_marker",
                "response_marker",
                "condition_marker",
                "callsite_marker",
                "provider_handler_marker",
                "provider_marker",
                "provider_registration_marker",
            ),
        )

    def assert_source_bound_service_edge(
        self, *, producer: str, consumer: str, changed: str, markers: tuple[str, ...]
    ) -> None:
        metadata = planner.cargo_metadata()
        members = set(metadata["workspace_members"])
        packages = {p["name"]: p for p in metadata["packages"] if p["id"] in members}
        result = planner.plan([changed], metadata, ROOT)
        self.assertTrue(result["all"])
        self.assertEqual(result["packages"], sorted(packages))
        self.assertIn("unmapped non-Cargo runtime consumers", result["reason"])
        edges = [
            edge for edge in result["observed_non_cargo_consumers"]
            if edge["producer"] == producer and edge["package"] == consumer
        ]
        self.assertEqual(len(edges), 1)
        edge = edges[0]
        marker_sources = {
            "binding": "evidence",
            "runtime_marker": "evidence",
            "registration_marker": "evidence",
            "connection_marker": "request_evidence",
            "request_marker": "request_evidence",
            "response_marker": "request_evidence",
            "condition_marker": "callsite_evidence",
            "callsite_marker": "callsite_evidence",
            "provider_handler_marker": "provider_evidence",
            "provider_marker": "provider_evidence",
            "provider_registration_marker": "provider_registration_evidence",
            "route_registration_marker": "route_registration_evidence",
            "server_marker": "server_evidence",
        }
        for marker in markers:
            source = marker_sources[marker]
            with self.subTest(producer=producer, consumer=consumer, marker=marker):
                source_text = (ROOT / edge[source]).read_text(encoding="utf-8")
                self.assertIn(edge[marker], source_text)
        compose = (ROOT / edge["deployment_evidence"]).read_text(encoding="utf-8")
        service = compose.split(f"\n  {edge['deployment_service']}:\n", 1)[1]
        service = re.split(r"(?m)^  [a-z][a-z0-9_-]*:\s*$", service, maxsplit=1)[0]
        self.assertIn(edge["deployment_marker"], service)
        if "deployment_network_marker" in edge:
            self.assertIn(edge["deployment_network_marker"], service)
        if "deployment_consumer_service" in edge:
            consumer_service = compose.split(
                f"\n  {edge['deployment_consumer_service']}:\n", 1
            )[1]
            consumer_service = re.split(
                r"(?m)^  [a-z][a-z0-9_-]*:\s*$", consumer_service, maxsplit=1
            )[0]
            self.assertIn(edge["deployment_consumer_marker"], consumer_service)
            self.assertIn(edge["deployment_network_marker"], consumer_service)
            if "deployment_consumer_absent_marker" in edge:
                self.assertNotIn(
                    edge["deployment_consumer_absent_marker"], consumer_service
                )
        self.assertNotIn(
            producer, {dep["name"] for dep in packages[consumer]["dependencies"]}
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

    def test_auth_gateway_session_grpc_edge_is_source_backed_and_shadow_only(
        self,
    ) -> None:
        metadata = planner.cargo_metadata()
        members = set(metadata["workspace_members"])
        packages = {p["name"]: p for p in metadata["packages"] if p["id"] in members}
        changed = Path(packages["marty-auth"]["manifest_path"]).relative_to(ROOT)
        result = planner.plan([changed.as_posix()], metadata, ROOT)
        self.assertTrue(result["all"])
        self.assertEqual(result["packages"], sorted(packages))
        self.assertIn("unmapped non-Cargo runtime consumers", result["reason"])
        edges = [
            edge
            for edge in result["observed_non_cargo_consumers"]
            if edge["producer"] == "marty-auth" and edge["package"] == "marty-gateway"
        ]
        self.assertEqual(len(edges), 1)
        edge = edges[0]
        markers = (
            ("grpc_binding", "evidence"),
            ("grpc_runtime_marker", "grpc_runtime_evidence"),
            ("grpc_registration_marker", "grpc_runtime_evidence"),
            ("grpc_connection_marker", "grpc_request_evidence"),
            ("grpc_request_marker", "grpc_request_evidence"),
            ("grpc_identity_marker", "grpc_request_evidence"),
            ("grpc_provider_marker", "grpc_provider_evidence"),
            (
                "grpc_provider_registration_marker",
                "grpc_provider_registration_evidence",
            ),
            ("grpc_deployment_marker", "grpc_deployment_evidence"),
        )
        sources = {
            path: (ROOT / path).read_text(encoding="utf-8")
            for _, source in markers
            if (path := edge[source])
        }

        def auth_validate_session_body(source_text: str) -> str:
            owner = "impl AuthService for AuthGrpcService {"
            method = "    async fn validate_session("
            successor = "    async fn create_session("
            self.assertIn(owner, source_text)
            impl = source_text.split(owner, 1)[1]
            self.assertIn(method, impl)
            body = impl.split(method, 1)[1]
            self.assertIn(successor, body)
            return body.split(successor, 1)[0]

        def assert_markers(snapshot: dict[str, str]) -> None:
            for marker, source in markers:
                text = snapshot[edge[source]]
                if marker == "grpc_provider_marker":
                    text = auth_validate_session_body(text)
                self.assertIn(edge[marker], text)

        assert_markers(sources)
        for marker, source in markers:
            with self.subTest(marker=marker):
                path = edge[source]
                changed_source = dict(sources)
                if marker == "grpc_provider_marker":
                    # Leave get_auth_status's identical call intact: it must
                    # not mask removal from the validate_session RPC.
                    body = auth_validate_session_body(sources[path])
                    changed_source[path] = sources[path].replace(
                        body, body.replace(edge[marker], "removed-edge", 1), 1
                    )
                    self.assertIn(edge[marker], changed_source[path])
                else:
                    changed_source[path] = sources[path].replace(
                        edge[marker], "removed-edge"
                    )
                with self.assertRaises(AssertionError):
                    assert_markers(changed_source)
        self.assertNotIn(
            "marty-auth",
            {dep["name"] for dep in packages["marty-gateway"]["dependencies"]},
        )

    def test_flow_callback_to_auth_internal_route_is_observed_only(self) -> None:
        metadata = planner.cargo_metadata()
        members = set(metadata["workspace_members"])
        packages = {p["name"]: p for p in metadata["packages"] if p["id"] in members}
        result = planner.plan(["rust/services/auth/src/http_service.rs"], metadata, ROOT)
        self.assertTrue(result["all"])
        self.assertEqual(result["packages"], sorted(packages))
        self.assertIn("unmapped non-Cargo runtime consumers", result["reason"])
        edges = [
            edge
            for edge in result["observed_non_cargo_consumers"]
            if edge["producer"] == "marty-auth" and edge["package"] == "marty-flow"
        ]
        self.assertEqual(len(edges), 1)
        edge = edges[0]
        markers = (
            ("auth_url_marker", "auth_request_evidence"),
            ("auth_request_marker", "auth_request_evidence"),
            ("binding", "evidence"),
            ("grpc_marker", "grpc_evidence"),
            ("conditional_marker", "runtime_evidence"),
            ("runtime_marker", "runtime_evidence"),
            ("selection_marker", "selection_evidence"),
            ("submission_context_marker", "submission_evidence"),
            ("submission_secret_marker", "submission_evidence"),
            ("submission_event_marker", "submission_evidence"),
            ("submission_outbox_marker", "submission_evidence"),
            ("outbox_marker", "outbox_evidence"),
            ("delivery_marker", "delivery_evidence"),
            ("provider_marker", "provider_evidence"),
            ("provider_registration_marker", "provider_evidence"),
        )
        sources = {
            path: (ROOT / path).read_text(encoding="utf-8")
            for path in {edge[source] for _, source in markers}
        }

        def assert_markers() -> None:
            for marker, source in markers:
                self.assertIn(edge[marker], sources[edge[source]])

        assert_markers()
        for marker, source in markers:
            path = edge[source]
            original = sources[path]
            sources[path] = original.replace(edge[marker], "removed-runtime-edge")
            with self.subTest(marker=marker), self.assertRaises(AssertionError):
                assert_markers()
            sources[path] = original
        compose = (ROOT / edge["deployment_evidence"]).read_text(encoding="utf-8")
        flow = compose.split("\n  flow:\n", 1)[1].split("\n  issuance:\n", 1)[0]
        auth = compose.split("\n  auth:\n", 1)[1].split("\n  organization:\n", 1)[0]
        deployment_markers = (
            ("deployment_auth_base_marker", "auth"),
            ("deployment_secret_marker", "flow"),
            ("deployment_binding_marker", "flow"),
            ("deployment_marker", "flow"),
        )
        deployments = {"auth": auth, "flow": flow}

        def assert_deployment_markers() -> None:
            for marker, service in deployment_markers:
                self.assertIn(edge[marker], deployments[service])

        assert_deployment_markers()
        for marker, service in deployment_markers:
            original = deployments[service]
            deployments[service] = original.replace(edge[marker], "removed-runtime-edge")
            with self.subTest(marker=marker), self.assertRaises(AssertionError):
                assert_deployment_markers()
            deployments[service] = original
        self.assertNotIn(
            "marty-auth", {dep["name"] for dep in packages["marty-flow"]["dependencies"]}
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

    def test_organization_membership_consumers_are_observed_only(self) -> None:
        metadata = planner.cargo_metadata()
        members = set(metadata["workspace_members"])
        packages = {p["name"]: p for p in metadata["packages"] if p["id"] in members}
        result = planner.plan(["rust/services/organization/src/lib.rs"], metadata, ROOT)
        self.assertTrue(result["all"])
        self.assertEqual(result["packages"], sorted(packages))
        self.assertIn("unmapped non-Cargo runtime consumers", result["reason"])
        consumers = {
            "marty-compliance-profile",
            "marty-deployment-profile",
            "marty-revocation-profile",
            "marty-presentation-policy",
        }
        for consumer in consumers:
            with self.subTest(consumer=consumer):
                edges = [
                    edge
                    for edge in result["observed_non_cargo_consumers"]
                    if edge["producer"] == "marty-organization"
                    and edge["package"] == consumer
                ]
                self.assertEqual(len(edges), 1)
                edge = edges[0]
                request_source = (
                    "shared_request_evidence"
                    if "shared_request_evidence" in edge
                    else "request_evidence"
                )
                for marker, source in (
                    ("binding", "evidence"),
                    ("runtime_marker", "runtime_evidence"),
                    ("service_marker", "runtime_evidence"),
                    ("connection_marker", "request_evidence"),
                    ("request_marker", request_source),
                    ("provider_marker", "provider_evidence"),
                ):
                    with self.subTest(consumer=consumer, marker=marker):
                        self.assertIn(
                            edge[marker],
                            (ROOT / edge[source]).read_text(encoding="utf-8"),
                        )
                for marker in ("target_marker", "registration_marker"):
                    if marker in edge:
                        self.assertIn(
                            edge[marker],
                            (ROOT / edge["request_evidence"]).read_text(
                                encoding="utf-8"
                            ),
                        )
                self.assertNotIn(
                    "marty-organization",
                    {dep["name"] for dep in packages[consumer]["dependencies"]},
                )
        gateway_edges = [
            edge
            for edge in result["observed_non_cargo_consumers"]
            if edge["producer"] == "marty-organization"
            and edge["package"] == "marty-gateway"
        ]
        self.assertEqual(len(gateway_edges), 1)
        gateway = gateway_edges[0]
        for marker, source in (
            ("grpc_binding", "evidence"),
            ("grpc_runtime_marker", "grpc_runtime_evidence"),
            ("grpc_registration_marker", "grpc_runtime_evidence"),
            ("grpc_connection_marker", "grpc_request_evidence"),
            ("grpc_request_marker", "grpc_request_evidence"),
            ("grpc_provider_marker", "grpc_provider_evidence"),
        ):
            with self.subTest(consumer="marty-gateway", marker=marker):
                self.assertIn(
                    gateway[marker],
                    (ROOT / gateway[source]).read_text(encoding="utf-8"),
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
                "marty-credential-template",
                "marty-verification-service",
                "marty-issuance-service",
                "marty-auth",
                "marty-trust-profile",
                "marty-presentation-policy",
                "marty-flow",
                "marty-gateway",
                "marty-applicant",
                "marty-compliance-profile",
                "marty-deployment-profile",
                "marty-revocation-profile",
                "marty-device-registration",
            },
            "marty-credential-template": {
                "marty-credential-template",
                "marty-verification-service",
                "marty-issuance-service",
                "marty-presentation-policy",
                "marty-flow",
                "marty-auth",
                "marty-gateway",
                "marty-applicant",
            },
            "marty-revocation-profile": {
                "marty-revocation-profile",
                "marty-credential-template",
                "marty-verification-service",
                "marty-issuance-service",
                "marty-presentation-policy",
                "marty-flow",
                "marty-auth",
                "marty-gateway",
                "marty-applicant",
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
                if producer == "marty-credential-template":
                    source_text = (ROOT / edge["request_evidence"]).read_text(
                        encoding="utf-8"
                    )
                    self.assertNotIn("resolve_template_http", source_text)
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

    def test_issuance_applicant_template_http_consumer_is_observed_only(self) -> None:
        metadata = planner.cargo_metadata()
        members = set(metadata["workspace_members"])
        packages = {p["name"]: p for p in metadata["packages"] if p["id"] in members}
        result = planner.plan(["rust/services/issuance/src/application_template_http.rs"],
                              metadata, ROOT)
        self.assertTrue(result["all"])
        self.assertEqual(result["packages"], sorted(packages))
        self.assertIn("unmapped non-Cargo runtime consumers", result["reason"])
        edges = [edge for edge in result["observed_non_cargo_consumers"]
                 if edge["producer"] == "marty-issuance-service"
                 and edge["package"] == "marty-applicant"]
        self.assertEqual(len(edges), 1)
        edge = edges[0]
        markers = (
            ("binding", "evidence"),
            ("runtime_marker", "evidence"),
            ("request_call_marker", "request_evidence"),
            ("request_marker", "request_evidence"),
            ("provider_marker", "provider_evidence"),
            ("deployment_marker", "deployment_evidence"),
        )
        sources = {path: (ROOT / path).read_text(encoding="utf-8")
                   for path in {edge[source] for _, source in markers}}

        def assert_markers() -> None:
            for marker, source in markers:
                self.assertIn(edge[marker], sources[edge[source]])

        assert_markers()
        compose = sources[edge["deployment_evidence"]]
        applicant = compose.split("\n  applicant:\n", 1)[1].split(
            "\n  notification:\n", 1
        )[0]
        self.assertIn(edge["deployment_marker"], applicant)
        for marker, source in markers:
            path = edge[source]
            original = sources[path]
            sources[path] = original.replace(edge[marker], "removed-route-or-binding")
            with self.subTest(marker=marker), self.assertRaises(AssertionError):
                assert_markers()
            sources[path] = original
        assert_markers()
        self.assertNotIn("marty-issuance-service", {
            dep["name"] for dep in packages["marty-applicant"]["dependencies"]
        })

    def test_issuance_presentation_policy_status_http_consumer_is_observed_only(
        self,
    ) -> None:
        metadata = planner.cargo_metadata()
        members = set(metadata["workspace_members"])
        packages = {p["name"]: p for p in metadata["packages"] if p["id"] in members}
        result = planner.plan(["rust/services/issuance/src/http.rs"], metadata, ROOT)
        self.assertTrue(result["all"])
        self.assertEqual(result["packages"], sorted(packages))
        edges = [edge for edge in result["observed_non_cargo_consumers"]
                 if edge["producer"] == "marty-issuance-service"
                 and edge["package"] == "marty-presentation-policy"]
        self.assertEqual(len(edges), 1)
        edge = edges[0]
        markers = (
            ("binding", "evidence"),
            ("status_marker", "evidence"),
            ("runtime_marker", "runtime_evidence"),
            ("request_marker", "request_evidence"),
            ("provider_marker", "provider_evidence"),
        )
        sources = {path: (ROOT / path).read_text(encoding="utf-8")
                   for path in {edge[source] for _, source in markers}}

        def assert_markers() -> None:
            for marker, source in markers:
                self.assertIn(edge[marker], sources[edge[source]])

        assert_markers()
        for marker, source in markers:
            path = edge[source]
            original = sources[path]
            sources[path] = original.replace(edge[marker], "removed-route-or-binding")
            with self.subTest(marker=marker), self.assertRaises(AssertionError):
                assert_markers()
            sources[path] = original
        assert_markers()
        compose = (ROOT / edge["deployment_evidence"]).read_text(encoding="utf-8")
        presentation = compose.split("\n  presentation-policy:\n", 1)[1].split(
            "\n  deployment-profile:\n", 1
        )[0]
        self.assertIn(edge["deployment_marker"], presentation)
        with self.assertRaises(AssertionError):
            self.assertIn(
                edge["deployment_marker"],
                presentation.replace(edge["deployment_marker"], "removed-binding"),
            )
        self.assertNotIn("marty-issuance-service", {
            dep["name"] for dep in packages["marty-presentation-policy"]["dependencies"]
        })

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

    def test_flow_http_reference_consumers_are_observed_without_narrowing(self) -> None:
        metadata = planner.cargo_metadata()
        members = set(metadata["workspace_members"])
        packages = {p["name"]: p for p in metadata["packages"] if p["id"] in members}
        routes = {
            "marty-issuance-service": (
                "ApplicationTemplate",
                "self.application_templates",
                "v1/application-templates/{encoded}",
            ),
            "marty-credential-template": (
                "DeliveryDestination",
                "self.delivery_destinations",
                "v1/delivery-destinations/{encoded}",
            ),
            "marty-trust-profile": (
                "TrustProfile",
                "self.trust_profiles",
                "v1/trust-profiles/{encoded}",
            ),
            "marty-deployment-profile": (
                "DeploymentProfile",
                "self.deployment_profiles",
                "v1/deployment-profiles/{encoded}",
            ),
        }
        resolver = (
            (ROOT / "rust/services/flow/src/http_providers.rs")
            .read_text(encoding="utf-8")
            .split("let response: ReferenceResponse = match kind {", 1)[1]
            .split("if response.id != reference_id", 1)[0]
        )
        flow_dependencies = {
            dep["name"] for dep in packages["marty-flow"]["dependencies"]
        }
        for producer, (kind, client, route) in routes.items():
            with self.subTest(producer=producer):
                self.assertNotIn(producer, flow_dependencies)
                result = planner.plan(
                    [
                        Path(packages[producer]["manifest_path"])
                        .relative_to(ROOT)
                        .as_posix()
                    ],
                    metadata,
                    ROOT,
                )
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
                if producer in {"marty-issuance-service", "marty-credential-template"}:
                    marker_keys = (
                        ("http_binding", "evidence"),
                        ("http_startup_marker", "http_startup_evidence"),
                        ("http_request_marker", "http_request_evidence"),
                        ("http_response_marker", "http_request_evidence"),
                        ("http_callsite_marker", "http_callsite_evidence"),
                        ("http_provider_marker", "http_provider_evidence"),
                    )
                    request_marker = edge["http_request_marker"]
                else:
                    marker_keys = (
                        ("binding", "evidence"),
                        ("runtime_marker", "runtime_evidence"),
                        ("request_marker", "request_evidence"),
                        ("response_marker", "request_evidence"),
                        ("callsite_marker", "callsite_evidence"),
                        ("provider_marker", "provider_evidence"),
                    )
                    request_marker = edge["request_marker"]
                self.assertIn(route, request_marker)
                branch = resolver.split(f"FlowReferenceKind::{kind} => {{", 1)[1].split(
                    "FlowReferenceKind::", 1
                )[0]
                self.assertIn(client, branch)
                self.assertIn(request_marker, branch)
                for marker, source in marker_keys:
                    with self.subTest(producer=producer, marker=marker):
                        self.assertIn(
                            edge[marker],
                            (ROOT / edge[source]).read_text(encoding="utf-8"),
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
            {
                "marty-flow",
                "marty-gateway",
                "marty-issuance-service",
                "marty-credential-template",
                "marty-verification-service",
            },
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
            {
                "marty-signing-keys",
                "marty-flow",
                "marty-gateway",
                "marty-auth",
                "marty-issuance-service",
                "marty-credential-template",
                "marty-verification-service",
                "marty-applicant",
            },
        )

    def test_signing_keys_issuer_resolution_consumers_are_observed_only(self) -> None:
        metadata = planner.cargo_metadata()
        members = set(metadata["workspace_members"])
        packages = {p["name"]: p for p in metadata["packages"] if p["id"] in members}
        result = planner.plan(
            ["rust/services/signing-keys/src/http.rs"], metadata, ROOT
        )
        self.assertTrue(result["all"])
        self.assertEqual(result["packages"], sorted(packages))
        self.assertIn("unmapped non-Cargo runtime consumers", result["reason"])
        for consumer in (
            "marty-issuance-service",
            "marty-credential-template",
            "marty-verification-service",
        ):
            with self.subTest(consumer=consumer):
                edges = [
                    edge
                    for edge in result["observed_non_cargo_consumers"]
                    if edge["producer"] == "marty-signing-keys"
                    and edge["package"] == consumer
                ]
                self.assertEqual(len(edges), 1)
                edge = edges[0]
                for marker, source in (
                    ("binding", "evidence"),
                    ("default_marker", "evidence"),
                    ("runtime_marker", "runtime_evidence"),
                    ("request_marker", "request_evidence"),
                    ("gateway_route_marker", "gateway_evidence"),
                    (
                        "gateway_classification_marker",
                        "gateway_classification_evidence",
                    ),
                    ("gateway_dispatch_marker", "gateway_evidence"),
                    ("gateway_marker", "gateway_evidence"),
                    ("provider_marker", "provider_evidence"),
                    ("provider_handler_marker", "provider_evidence"),
                ):
                    with self.subTest(consumer=consumer, marker=marker):
                        self.assertIn(
                            edge[marker],
                            (ROOT / edge[source]).read_text(encoding="utf-8"),
                        )
                for marker, source in (
                    ("service_marker", "runtime_evidence"),
                    ("conditional_marker", "runtime_evidence"),
                    ("response_marker", "request_evidence"),
                    ("fallback_marker", "request_evidence"),
                ):
                    if marker in edge:
                        self.assertIn(
                            edge[marker],
                            (ROOT / edge[source]).read_text(encoding="utf-8"),
                        )
                self.assertNotIn(
                    "marty-signing-keys",
                    {dep["name"] for dep in packages[consumer]["dependencies"]},
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
                if provider == "marty-issuance-service":
                    markers = (
                        ("startup_marker", "runtime_evidence"),
                        ("request_marker", "request_evidence"),
                        ("request_method_marker", "request_evidence"),
                        ("request_auth_marker", "request_evidence"),
                        ("callsite_route_marker", "callsite_evidence"),
                        ("callsite_marker", "callsite_evidence"),
                        ("provider_condition_marker", "provider_evidence"),
                        ("provider_marker", "provider_evidence"),
                    )
                    sources = {
                        path: (ROOT / path).read_text(encoding="utf-8")
                        for path in {edge[source] for _, source in markers}
                    }

                    def assert_markers() -> None:
                        for marker, source in markers:
                            self.assertIn(edge[marker], sources[edge[source]])

                    assert_markers()
                    for marker, source in markers:
                        path = edge[source]
                        original = sources[path]
                        sources[path] = original.replace(
                            edge[marker], "removed-runtime-contract-marker"
                        )
                        with self.subTest(marker=marker), self.assertRaises(
                            AssertionError
                        ):
                            assert_markers()
                        sources[path] = original
                    assert_markers()
                    compose = (ROOT / edge["deployment_evidence"]).read_text(
                        encoding="utf-8"
                    )
                    auth_tail = compose.split("\n  auth:\n", 1)[1]
                    next_service = re.search(
                        r"(?m)^  [a-z][a-z0-9_-]*:\s*$", auth_tail
                    )
                    self.assertIsNotNone(next_service)
                    auth_service = auth_tail[: next_service.start()]
                    self.assertIn(edge["deployment_marker"], auth_service)
                    with self.assertRaises(AssertionError):
                        self.assertIn(
                            edge["deployment_marker"],
                            auth_service.replace(
                                edge["deployment_marker"], "removed-runtime-binding"
                            ),
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
