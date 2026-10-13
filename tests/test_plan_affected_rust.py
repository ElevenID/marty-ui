"""The shadow planner must broaden when Cargo ownership is insufficient."""

from __future__ import annotations

import io
import json
import re
import subprocess
import sys
import tempfile
import tomllib
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "ci"))
import plan_affected_rust as planner  # noqa: E402 - sys.path selects the repo-owned CI script

GATEWAY_UPSTREAM_TARGETS = {
    "AUTH_SERVICE_URL": "http://auth:8001",
    "ORGANIZATION_SERVICE_URL": "http://organization:8002",
    "CREDENTIAL_TEMPLATE_SERVICE_URL": "http://credential-template:8003",
    "TRUST_PROFILE_SERVICE_URL": "http://trust-profile:8004",
    "ISSUANCE_SERVICE_URL": "http://issuance:8005",
    "APPLICANT_SERVICE_URL": "http://applicant:8006",
    "NOTIFICATION_SERVICE_URL": "http://notification:8007",
    "COMPLIANCE_PROFILE_SERVICE_URL": "http://compliance-profile:8008",
    "PRESENTATION_POLICY_SERVICE_URL": "http://presentation-policy:8009",
    "DEPLOYMENT_PROFILE_SERVICE_URL": "http://deployment-profile:8010",
    "FLOW_SERVICE_URL": "http://flow:8011",
    "VERIFICATION_SERVICE_URL": "http://verification:8012",
    "REVOCATION_PROFILE_SERVICE_URL": "http://revocation-profile:8013",
    "DEVICE_REGISTRATION_SERVICE_URL": "http://device-registration:8014",
    "SIGNING_KEYS_SERVICE_URL": "http://signing-keys:8017",
}


class AffectedRustPlannerTests(unittest.TestCase):
    def test_known_grpc_constructor_spellings_have_cargo_or_shadow_owners(self) -> None:
        """Catch new source packages using these clients; not a full call graph."""
        metadata = planner.cargo_metadata()
        members = set(metadata["workspace_members"])
        packages = {p["name"]: p for p in metadata["packages"] if p["id"] in members}
        tracked = subprocess.run(
            ["git", "ls-files", "-z", "--", "rust/services"],
            cwd=ROOT,
            check=True,
            capture_output=True,
        ).stdout
        sources: dict[str, tuple[str, str]] = {}
        service_packages: dict[str, str] = {}
        for raw in tracked.split(b"\0"):
            if not raw:
                continue
            relative = Path(raw.decode("utf-8"))
            parts = relative.parts
            if len(parts) < 5 or parts[:2] != ("rust", "services"):
                continue
            if parts[3] != "src" or relative.suffix != ".rs":
                continue
            service = parts[2]
            if service not in service_packages:
                manifest = ROOT / "rust" / "services" / service / "Cargo.toml"
                service_packages[service] = tomllib.loads(
                    manifest.read_text(encoding="utf-8")
                )["package"]["name"]
            sources[relative.as_posix()] = (
                service_packages[service],
                (ROOT / relative).read_text(encoding="utf-8"),
            )
        expected_clients = (
            ("marty-auth", "AuthServiceClient::", 1),
            ("marty-credential-template", "CredentialTemplateServiceClient::", 3),
            ("marty-event-stream", "EventStreamServiceClient::", 4),
            ("marty-flow", "FlowServiceClient::", 1),
            ("marty-issuance-service", "IssuanceServiceClient::", 1),
            ("marty-organization", "OrganizationServiceClient::", 12),
            ("marty-presentation-policy", "PresentationPolicyServiceClient::", 2),
            ("marty-revocation-profile", "RevocationProfileServiceClient::", 2),
        )
        discovered_markers = {
            marker
            for _, source in sources.values()
            for marker in re.findall(r"\b[A-Za-z][A-Za-z0-9_]*ServiceClient::", source)
        }
        self.assertEqual(
            discovered_markers, {marker for _, marker, _ in expected_clients}
        )
        for producer, marker, expected_count in expected_clients:
            with self.subTest(producer=producer):
                client_packages = {
                    package for package, source in sources.values() if marker in source
                }
                cargo_consumers = {
                    name
                    for name, package in packages.items()
                    if any(dep["name"] == producer for dep in package["dependencies"])
                }
                observed = {
                    edge["package"]
                    for edge in planner.OBSERVED_NON_CARGO_CONSUMERS[producer]
                }
                self.assertEqual(len(client_packages), expected_count)
                self.assertEqual(client_packages - observed - cargo_consumers, set())

    def test_gateway_credential_template_issuer_resolution_is_shadow_only(self) -> None:
        metadata = planner.cargo_metadata()
        members = set(metadata["workspace_members"])
        packages = {p["name"]: p for p in metadata["packages"] if p["id"] in members}
        result = planner.plan(["rust/services/gateway/src/runtime.rs"], metadata, ROOT)
        self.assertTrue(result["all"])
        self.assertEqual(result["packages"], sorted(packages))
        self.assertIn("unmapped non-Cargo runtime consumers", result["reason"])
        edges = [
            edge
            for edge in result["observed_non_cargo_consumers"]
            if edge["producer"] == "marty-gateway"
            and edge["package"] == "marty-credential-template"
        ]
        self.assertEqual(len(edges), 1)
        edge = edges[0]
        self.assertNotIn(
            "marty-gateway",
            {
                dep["name"]
                for dep in packages["marty-credential-template"]["dependencies"]
            },
        )
        markers = (
            ("binding", "evidence"),
            ("auth_binding", "evidence"),
            ("runtime_marker", "runtime_evidence"),
            ("auth_runtime_marker", "runtime_evidence"),
            ("request_marker", "request_evidence"),
            ("request_base_marker", "request_evidence"),
            ("request_method_marker", "request_evidence"),
            ("request_auth_marker", "request_evidence"),
            ("send_marker", "request_evidence"),
            ("provider_route_marker", "provider_evidence"),
            ("provider_dispatch_marker", "provider_evidence"),
            ("provider_auth_marker", "provider_evidence"),
            ("provider_operation_marker", "provider_operation_evidence"),
        )
        sources = {
            path: (ROOT / path).read_text(encoding="utf-8")
            for path in {edge[source] for _, source in markers}
        }
        for marker, source in markers:
            with self.subTest(marker=marker):
                self.assertIn(edge[marker], sources[edge[source]])
        request = (
            sources[edge["request_evidence"]]
            .split("async fn resolve_issuer(", 1)[1]
            .split("\n    async fn ", 1)[0]
        )
        self.assertIn(edge["request_marker"], request)
        self.assertIn(edge["request_base_marker"], request)
        self.assertIn(edge["request_method_marker"], request)
        self.assertIn(edge["request_auth_marker"], request)
        self.assertIn(edge["send_marker"], request)
        provider = (
            sources[edge["provider_evidence"]]
            .split("async fn internal_signing_compatibility_handler(", 1)[1]
            .split("\nasync fn ", 1)[0]
        )
        self.assertIn(edge["provider_dispatch_marker"], provider)
        self.assertIn(edge["provider_auth_marker"], provider)
        compose = yaml.safe_load(
            (ROOT / edge["deployment_evidence"]).read_text(encoding="utf-8")
        )
        self.assertEqual(
            compose["services"][edge["deployment_service"]]["environment"][
                "SIGNING_KEYS_INTERNAL_URL"
            ],
            "http://gateway:8000/internal/signing-keys",
        )
        self.assertEqual(
            compose["services"][edge["deployment_service"]]["environment"][
                edge["deployment_auth_key"]
            ],
            compose["services"]["gateway"]["environment"][edge["deployment_auth_key"]],
        )
        self.assertIn(
            edge["deployment_marker"],
            (ROOT / edge["deployment_evidence"]).read_text(encoding="utf-8"),
        )

    def test_gateway_issuance_and_verification_issuer_resolution_is_shadow_only(
        self,
    ) -> None:
        metadata = planner.cargo_metadata()
        members = set(metadata["workspace_members"])
        packages = {p["name"]: p for p in metadata["packages"] if p["id"] in members}
        result = planner.plan(["rust/services/gateway/src/runtime.rs"], metadata, ROOT)
        self.assertTrue(result["all"])
        self.assertEqual(result["packages"], sorted(packages))
        self.assertIn("unmapped non-Cargo runtime consumers", result["reason"])
        edges = {
            edge["package"]: edge
            for edge in result["observed_non_cargo_consumers"]
            if edge["producer"] == "marty-gateway"
            and edge["package"]
            in {"marty-issuance-service", "marty-verification-service"}
            and edge.get("provider_operation_marker")
            == '(HttpMethod::Get, "resolve-issuer-did")'
        }
        self.assertEqual(
            set(edges), {"marty-issuance-service", "marty-verification-service"}
        )
        compose = yaml.safe_load((ROOT / "docker-compose.base.yml").read_text())
        for package, edge in edges.items():
            with self.subTest(package=package):
                self.assertNotIn(
                    "marty-gateway",
                    {dep["name"] for dep in packages[package]["dependencies"]},
                )
                for marker, evidence in (
                    ("binding", "evidence"),
                    ("auth_binding", "evidence"),
                    ("runtime_marker", "runtime_evidence"),
                    ("request_marker", "request_evidence"),
                    ("request_auth_marker", "request_evidence"),
                    ("send_marker", "request_evidence"),
                    ("provider_route_marker", "provider_evidence"),
                    ("provider_dispatch_marker", "provider_evidence"),
                    ("provider_auth_marker", "provider_evidence"),
                    ("provider_operation_marker", "provider_operation_evidence"),
                ):
                    self.assertIn(
                        edge[marker],
                        (ROOT / edge[evidence]).read_text(encoding="utf-8"),
                        marker,
                    )
                environment = compose["services"][edge["deployment_service"]][
                    "environment"
                ]
                self.assertEqual(
                    environment["SIGNING_KEYS_INTERNAL_URL"],
                    (
                        "http://signing-keys:8017/internal"
                        if edge["deployment_service"] == "issuance"
                        else "http://gateway:8000/internal/signing-keys"
                    ),
                )
                self.assertIn(
                    edge["deployment_marker"],
                    (ROOT / edge["deployment_evidence"]).read_text(encoding="utf-8"),
                )
                self.assertEqual(
                    environment[edge["deployment_auth_key"]],
                    compose["services"]["gateway"]["environment"][
                        edge["deployment_auth_key"]
                    ],
                )
        issuance = edges["marty-issuance-service"]
        issuance_main = (ROOT / issuance["runtime_evidence"]).read_text(
            encoding="utf-8"
        )
        resolver_call = issuance_main.split(issuance["runtime_marker"], 1)[1].split(
            ")?);", 1
        )[0]
        self.assertIn("config.signing_keys_internal_url.clone()", resolver_call)
        self.assertIn(issuance["auth_runtime_marker"], resolver_call)
        self.assertIn(
            issuance["request_method_marker"],
            (ROOT / issuance["request_evidence"]).read_text(encoding="utf-8"),
        )
        verification = edges["marty-verification-service"]
        main = (ROOT / verification["runtime_evidence"]).read_text(encoding="utf-8")
        conditional_start = (
            "let credentials_compat = " + verification["conditional_marker"]
        )
        conditional_end = "    } else {\n        None\n    };"

        def assert_conditional_resolver(source: str) -> None:
            self.assertEqual(source.count(conditional_start), 1)
            section = source.split(conditional_start, 1)[1].split(
                "let http_listener", 1
            )[0]
            self.assertEqual(section.count(conditional_end), 1)
            body = section.split(conditional_end, 1)[0]
            self.assertIn(verification["runtime_marker"], body)

        assert_conditional_resolver(main)
        call_start = main.index("        let issuer_resolver = ")
        call_end = main.index("        let service = ", call_start)
        call = main[call_start:call_end]
        moved = main[:call_start] + main[call_end:]
        moved = moved.replace(conditional_end, conditional_end + "\n" + call, 1)
        with self.assertRaises(AssertionError):
            assert_conditional_resolver(moved)
        self.assertEqual(
            compose["services"]["verification"]["environment"][
                verification["deployment_conditional_key"]
            ],
            "${VERIFICATION_CREDENTIALS_COMPAT_ENABLED:-false}",
        )
        self.assertIn(
            verification["fallback_marker"],
            (ROOT / verification["request_evidence"]).read_text(encoding="utf-8"),
        )

    def test_beta_passport_gateway_callback_is_an_observed_conditional_operation(
        self,
    ) -> None:
        """Inventory a conditional operation without narrowing selection."""
        metadata = planner.cargo_metadata()
        result = planner.plan(["rust/services/gateway/src/runtime.rs"], metadata, ROOT)
        self.assertTrue(result["all"])
        edges = [
            edge
            for edge in result["observed_non_cargo_consumers"]
            if edge["producer"] == "marty-gateway"
            and edge["package"] == "marty-issuance-service"
            and edge.get("conditional") == "beta passport Gateway callback profile only"
        ]
        self.assertEqual(len(edges), 1)
        witness = edges[0]
        for marker, evidence in (
            ("binding", "config_evidence"),
            ("selection_marker", "config_evidence"),
            ("handoff_marker", "handoff_evidence"),
            ("signature_marker", "handoff_evidence"),
            ("route_marker", "route_evidence"),
            ("forwarding_test_marker", "forwarding_test_evidence"),
        ):
            with self.subTest(marker=marker):
                self.assertIn(
                    witness[marker],
                    (ROOT / witness[evidence]).read_text(encoding="utf-8"),
                )
        compose = yaml.safe_load(
            (ROOT / witness["profile_evidence"]).read_text(encoding="utf-8")
        )
        environment = compose["services"][witness["profile_service"]]["environment"]
        self.assertEqual(environment["ENVIRONMENT"], "beta")
        self.assertEqual(environment["PASSPORT_BETA_BUREAU_ENABLED"], "true")
        self.assertEqual(
            environment["PASSPORT_BETA_BUREAU_GATEWAY_CALLBACK_ENABLED"], "true"
        )
        self.assertEqual(
            environment["PASSPORT_BUREAU_CALLBACK_URL"],
            witness["profile_callback_url"],
        )
        gateway = compose["services"][witness["profile_gateway_service"]]["environment"]
        self.assertEqual(gateway["PASSPORT_NATIVE_GATEWAY_ENABLED"], "true")
        self.assertEqual(gateway["PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED"], "false")

    def test_beta_passport_gateway_issuance_selectors_have_distinct_witnesses(
        self,
    ) -> None:
        """Inventory native and physical-provider routing without narrowing CI."""
        metadata = planner.cargo_metadata()
        result = planner.plan(["rust/services/issuance/src/main.rs"], metadata, ROOT)
        self.assertTrue(result["all"])
        edges = [
            edge
            for edge in result["observed_non_cargo_consumers"]
            if edge["producer"] == "marty-issuance-service"
            and edge["package"] == "marty-gateway"
            and edge.get("conditional")
            in {
                "beta passport native Gateway routes only",
                "physical-provider beta signed webhook only",
            }
        ]
        self.assertEqual(len(edges), 2)
        witnesses = {edge["conditional"]: edge for edge in edges}
        self.assertEqual(len(witnesses), 2)
        for name, witness in witnesses.items():
            with self.subTest(name=name):
                for marker, evidence in (
                    ("binding", "config_evidence"),
                    ("url_binding", "config_evidence"),
                    ("dispatch_marker", "dispatch_evidence"),
                    ("route_marker", "route_evidence"),
                    ("owner_marker", "route_evidence"),
                    ("route_test_marker", "route_evidence"),
                    ("provider_marker", "provider_evidence"),
                    ("provider_path_marker", "provider_evidence"),
                ):
                    self.assertIn(
                        witness[marker],
                        (ROOT / witness[evidence]).read_text(encoding="utf-8"),
                    )
                profile = yaml.safe_load(
                    (ROOT / witness["profile_evidence"]).read_text(encoding="utf-8")
                )
                gateway = profile["services"][witness["profile_gateway_service"]][
                    "environment"
                ]
                self.assertEqual(gateway["PASSPORT_NATIVE_GATEWAY_ENABLED"], "true")
                if name == "physical-provider beta signed webhook only":
                    self.assertEqual(
                        gateway["PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED"], "true"
                    )
                    self.assertEqual(
                        gateway["PASSPORT_PROVIDER_INGRESS_SERVICE_URL"],
                        "http://passport-provider-ingress:8021",
                    )
                    self.assertIn(
                        witness["profile_provider_service"], profile["services"]
                    )
                else:
                    self.assertEqual(
                        gateway["PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED"], "false"
                    )

    def test_physical_provider_ingress_has_a_callback_signer_witness(self) -> None:
        """Retain the isolated signer obligation without selecting fewer checks."""
        metadata = planner.cargo_metadata()
        result = planner.plan(
            ["rust/services/signing-keys/src/passport_callback_hmac.rs"], metadata, ROOT
        )
        self.assertTrue(result["all"])
        edges = [
            edge
            for edge in result["observed_non_cargo_consumers"]
            if edge["producer"] == "marty-signing-keys"
            and edge["package"] == "marty-issuance-service"
            and edge.get("conditional")
            == "physical-provider ingress callback signing only"
        ]
        self.assertEqual(len(edges), 1)
        witness = edges[0]
        for marker, evidence in (
            ("binding", "consumer_evidence"),
            ("callback_binding", "consumer_evidence"),
            ("handoff_marker", "handoff_evidence"),
            ("callback_marker", "handoff_evidence"),
            ("request_marker", "request_evidence"),
            ("auth_marker", "request_evidence"),
            ("body_marker", "request_evidence"),
            ("delivery_marker", "request_evidence"),
            ("provider_route_marker", "provider_evidence"),
            ("provider_handler_marker", "provider_evidence"),
            ("provider_registration_marker", "provider_registration_evidence"),
            ("provider_binary_marker", "provider_manifest_evidence"),
        ):
            with self.subTest(marker=marker):
                self.assertIn(
                    witness[marker],
                    (ROOT / witness[evidence]).read_text(encoding="utf-8"),
                )
        profile = yaml.safe_load(
            (ROOT / witness["profile_evidence"]).read_text(encoding="utf-8")
        )
        ingress = profile["services"][witness["profile_consumer_service"]]
        signer = profile["services"][witness["profile_provider_service"]]
        self.assertEqual(
            ingress["environment"]["PASSPORT_PROVIDER_INGRESS_ENABLED"], "true"
        )
        self.assertEqual(
            ingress["environment"]["PASSPORT_PROVIDER_SIGNER_URL"],
            witness["profile_signer_url"],
        )
        self.assertEqual(
            ingress["environment"]["PASSPORT_PROVIDER_NATIVE_CALLBACK_URL"],
            witness["profile_callback_url"],
        )
        self.assertEqual(
            signer["environment"]["SERVICE_NAME"], "passport_callback_signer_supported"
        )
        self.assertIn(witness["profile_provider_service"], ingress["depends_on"])

    def test_beta_bureau_has_a_distinct_callback_signer_witness(self) -> None:
        """Record the beta-only signer operation without narrowing CI."""
        metadata = planner.cargo_metadata()
        result = planner.plan(
            ["rust/services/signing-keys/src/passport_callback_hmac.rs"], metadata, ROOT
        )
        self.assertTrue(result["all"])
        edges = [
            edge
            for edge in result["observed_non_cargo_consumers"]
            if edge["producer"] == "marty-signing-keys"
            and edge["package"] == "marty-issuance-service"
            and edge.get("conditional") == "beta passport bureau callback signing only"
        ]
        self.assertEqual(len(edges), 1)
        witness = edges[0]
        for marker, evidence in (
            ("gate_marker", "consumer_evidence"),
            ("gate_logic_marker", "consumer_evidence"),
            ("enable_marker", "consumer_evidence"),
            ("binding", "consumer_evidence"),
            ("private_url_marker", "consumer_evidence"),
            ("callback_binding", "consumer_evidence"),
            ("callback_selection_marker", "consumer_evidence"),
            ("handoff_marker", "consumer_evidence"),
            ("test_marker", "consumer_evidence"),
            ("request_marker", "request_evidence"),
            ("auth_marker", "request_evidence"),
            ("body_marker", "request_evidence"),
            ("provider_route_marker", "provider_evidence"),
            ("provider_handler_marker", "provider_evidence"),
            ("provider_beta_gate_marker", "provider_registration_evidence"),
            ("provider_enable_gate_marker", "provider_registration_evidence"),
            ("provider_registration_marker", "provider_registration_evidence"),
            ("provider_binary_marker", "provider_manifest_evidence"),
        ):
            with self.subTest(marker=marker):
                self.assertIn(
                    witness[marker],
                    (ROOT / witness[evidence]).read_text(encoding="utf-8"),
                )
        profile = yaml.safe_load(
            (ROOT / witness["profile_evidence"]).read_text(encoding="utf-8")
        )
        bureau = profile["services"][witness["profile_consumer_service"]]
        signer = profile["services"][witness["profile_provider_service"]]
        self.assertEqual(bureau["environment"]["ENVIRONMENT"], "beta")
        self.assertEqual(bureau["environment"]["PASSPORT_BETA_BUREAU_ENABLED"], "true")
        self.assertEqual(
            bureau["environment"]["SIGNING_KEYS_INTERNAL_URL"],
            witness["profile_signer_url"],
        )
        self.assertEqual(
            bureau["environment"]["PASSPORT_BUREAU_CALLBACK_URL"],
            witness["profile_callback_url"],
        )
        self.assertEqual(
            bureau["environment"]["PASSPORT_BETA_BUREAU_GATEWAY_CALLBACK_ENABLED"],
            "true",
        )
        self.assertEqual(signer["environment"]["ENVIRONMENT"], "beta")
        self.assertEqual(
            signer["environment"]["PASSPORT_CALLBACK_SIGNER_ENABLED"], "true"
        )
        self.assertEqual(
            signer["environment"]["SERVICE_NAME"], "passport_callback_signer"
        )
        self.assertIn(witness["profile_provider_service"], bureau["depends_on"])
        self.assertIn("passport-callback-signing", bureau["networks"])
        self.assertIn("passport-callback-signing", signer["networks"])

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
        self.assertIn("marty-selfhost-acceptance", result["packages"])
        self.assertNotIn("marty-canvas-acceptance", result["packages"])
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

    def test_applicant_notification_ingest_witness_is_scoped_and_shadow_only(
        self,
    ) -> None:
        metadata = planner.cargo_metadata()
        members = set(metadata["workspace_members"])
        packages = {p["name"]: p for p in metadata["packages"] if p["id"] in members}
        result = planner.plan(
            ["rust/services/notification/src/http.rs"], metadata, ROOT
        )
        self.assertTrue(result["all"])
        self.assertEqual(result["packages"], sorted(packages))
        self.assertIn("unmapped non-Cargo runtime consumers", result["reason"])
        edges = [
            edge
            for edge in result["observed_non_cargo_consumers"]
            if edge["producer"] == "marty-notification"
            and edge["package"] == "marty-applicant"
        ]
        self.assertEqual(len(edges), 1)
        edge = edges[0]
        self.assertNotIn(
            "marty-notification",
            {dep["name"] for dep in packages["marty-applicant"]["dependencies"]},
        )
        main = (ROOT / edge["evidence"]).read_text(encoding="utf-8")
        request = (ROOT / edge["runtime_evidence"]).read_text(encoding="utf-8")
        provider = (ROOT / edge["provider_evidence"]).read_text(encoding="utf-8")
        compose = (ROOT / edge["deployment_evidence"]).read_text(encoding="utf-8")
        scopes = {
            "config": main.split("let notification_url =", 1)[1].split(
                "let persistence =", 1
            )[0],
            "startup": main.split("let service =", 1)[1].split(
                "let event_delivery_service =", 1
            )[0],
            "request": request.split("impl EventPublisher for GrpcEventPublisher", 1)[
                1
            ].split("let wire = event_stream_wire", 1)[0],
            "provider_identity": provider.split("const PRODUCER_HEADER", 1)[1].split(
                "#[derive(Clone)]", 1
            )[0],
            "route": provider.split("pub fn router", 1)[1].split(
                "pub fn validate_internal_auth_config", 1
            )[0],
            "handler": provider.split("async fn ingest_event", 1)[1].split(
                "async fn health", 1
            )[0],
            "applicant": compose.split("\n  applicant:\n", 1)[1].split(
                "\n  notification:\n", 1
            )[0],
            "notification": compose.split("\n  notification:\n", 1)[1].split(
                "\n  compliance-profile:\n", 1
            )[0],
        }
        witnesses = {
            "config": (
                "binding",
                "default_binding_marker",
                "default_path_marker",
                "token_marker",
            ),
            "startup": ("startup_marker", "startup_url_marker", "startup_token_marker"),
            "request": (
                "runtime_marker",
                "token_header_marker",
                "producer_header_marker",
                "payload_marker",
            ),
            "provider_identity": ("provider_identity_marker",),
            "route": ("provider_route_marker",),
            "handler": (
                "provider_producer_guard_marker",
                "provider_expected_token_marker",
                "provider_token_guard_marker",
                "provider_call_marker",
            ),
            "applicant": ("deployment_marker", "deployment_token_marker"),
            "notification": ("deployment_token_marker",),
        }

        def assert_witnesses(source_scopes: dict[str, str]) -> None:
            for scope, markers in witnesses.items():
                for marker in markers:
                    self.assertIn(edge[marker], source_scopes[scope])

        assert_witnesses(scopes)
        for scope, markers in witnesses.items():
            for marker in markers:
                modified = dict(scopes)
                modified[scope] = modified[scope].replace(
                    edge[marker], "removed-source-witness", 1
                )
                with self.subTest(scope=scope, marker=marker):
                    with self.assertRaises(AssertionError):
                        assert_witnesses(modified)

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
            edge
            for edge in result["observed_non_cargo_consumers"]
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

    def test_gateway_did_web_consumers_are_source_backed_and_shadow_only(self) -> None:
        metadata = planner.cargo_metadata()
        members = set(metadata["workspace_members"])
        packages = {p["name"]: p for p in metadata["packages"] if p["id"] in members}
        result = planner.plan(["rust/services/gateway/src/runtime.rs"], metadata, ROOT)
        self.assertTrue(result["all"])
        self.assertEqual(result["packages"], sorted(packages))
        self.assertIn("unmapped non-Cargo runtime consumers", result["reason"])
        gateway_edges = [
            edge
            for edge in result["observed_non_cargo_consumers"]
            if edge["producer"] == "marty-gateway"
        ]
        edges = {}
        for consumer, binding in (
            (
                "marty-trust-profile",
                'value(&values, "DID_RESOLUTION_BASE_URL").unwrap_or("http://gateway:8000")',
            ),
            ("marty-issuance-service", '"DIDCOMM_DID_WEB_INTERNAL_BASE_URL"'),
        ):
            matches = [
                edge
                for edge in gateway_edges
                if edge["package"] == consumer and edge["binding"] == binding
            ]
            self.assertEqual(len(matches), 1)
            edges[consumer] = matches[0]
        for consumer in edges:
            self.assertNotIn(
                "marty-gateway",
                {dep["name"] for dep in packages[consumer]["dependencies"]},
            )

        source_paths = {
            "rust/services/gateway/src/runtime.rs",
            "contracts/gateway-routes.json",
            "docker-compose.base.yml",
        }
        for edge in edges.values():
            source_paths.update((edge["evidence"], edge["runtime_evidence"]))
            source_paths.add(edge.get("request_evidence", edge.get("client_evidence")))
        sources = {
            path: (ROOT / path).read_text(encoding="utf-8") for path in source_paths
        }
        witnesses = [
            (
                "rust/services/gateway/src/runtime.rs",
                'request.uri().path() == "/.well-known/did.json"',
            ),
            ("rust/services/gateway/src/runtime.rs", '.strip_prefix("/orgs/")'),
            (
                "rust/services/gateway/src/runtime.rs",
                "did_web_root_handler(state).await",
            ),
            (
                "rust/services/gateway/src/runtime.rs",
                "did_web_slug_handler(state, slug).await",
            ),
        ]
        for edge in edges.values():
            client_source = (
                "request_evidence" if "request_evidence" in edge else "client_evidence"
            )
            for marker, source in (
                ("binding", "evidence"),
                ("runtime_marker", "runtime_evidence"),
                ("client_marker", client_source),
                ("request_marker", client_source),
                ("registration_marker", "runtime_evidence"),
            ):
                if marker in edge:
                    witnesses.append((edge[source], edge[marker]))

        def assert_witnesses() -> None:
            paths = {
                route["path"]
                for route in json.loads(sources["contracts/gateway-routes.json"])[
                    "routes"
                ]
            }
            self.assertIn("/.well-known/did.json", paths)
            self.assertIn("/orgs/{org_slug}/did.json", paths)
            compose = sources["docker-compose.base.yml"]

            def service(name: str) -> str:
                body = compose.split(f"\n  {name}:\n", 1)[1]
                return re.split(r"(?m)^  [a-z][a-z0-9_-]*:\s*$", body, maxsplit=1)[0]

            self.assertIn('GATEWAY_PORT: "8000"', service("gateway"))
            for edge in edges.values():
                self.assertIn(
                    edge["deployment_marker"], service(edge["deployment_service"])
                )
            for path, marker in witnesses:
                self.assertIn(marker, sources[path])

        assert_witnesses()
        for path, marker in witnesses:
            original = sources[path]
            sources[path] = original.replace(marker, "removed-runtime-witness")
            with (
                self.subTest(path=path, marker=marker),
                self.assertRaises(AssertionError),
            ):
                assert_witnesses()
            sources[path] = original
        for path, marker in (
            ("contracts/gateway-routes.json", "/.well-known/did.json"),
            ("contracts/gateway-routes.json", "/orgs/{org_slug}/did.json"),
            ("docker-compose.base.yml", 'GATEWAY_PORT: "8000"'),
            *(
                ("docker-compose.base.yml", edge["deployment_marker"])
                for edge in edges.values()
            ),
        ):
            original = sources[path]
            sources[path] = original.replace(marker, "removed-deployment-witness")
            with (
                self.subTest(path=path, marker=marker),
                self.assertRaises(AssertionError),
            ):
                assert_witnesses()
            sources[path] = original

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
                    and edge.get("route_contract") == "contracts/gateway-routes.json"
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
                direct_dependencies = {
                    dep["name"] for dep in packages["marty-gateway"]["dependencies"]
                }
                self.assertEqual(
                    producer == "marty-signing-keys", producer in direct_dependencies
                )

    def test_base_compose_wires_every_configured_gateway_upstream(self) -> None:
        # An in-container localhost default cannot reach a sibling service.
        config = (ROOT / "rust/services/gateway/src/config.rs").read_text(
            encoding="utf-8"
        )
        table = config.split("const SERVICE_URLS:", 1)[1].split("\n];", 1)[0]
        bindings = re.findall(r'"([A-Z_]+_SERVICE_URL)"', table)
        self.assertEqual(len(bindings), len(GATEWAY_UPSTREAM_TARGETS))
        self.assertEqual(set(bindings), set(GATEWAY_UPSTREAM_TARGETS))

        compose = (ROOT / "docker-compose.base.yml").read_text(encoding="utf-8")
        gateway = compose.split("\n  gateway:\n", 1)[1]
        gateway = re.split(r"(?m)^  [a-z][a-z0-9_-]*:\s*$", gateway, maxsplit=1)[0]
        for binding, url in GATEWAY_UPSTREAM_TARGETS.items():
            with self.subTest(binding=binding):
                self.assertEqual(
                    re.findall(
                        rf"(?m)^      {re.escape(binding)}: (https?://[^\s#]+)$",
                        gateway,
                    ),
                    [url],
                )
                service = url.split("://", 1)[1].split(":", 1)[0]
                self.assertIn(f"\n  {service}:\n", compose)

    def test_oracle_kubernetes_wires_every_configured_gateway_upstream(self) -> None:
        configmap = (ROOT / "k8s/oracle/01-configmap.yaml").read_text(encoding="utf-8")
        configmaps = [
            document
            for document in yaml.safe_load_all(configmap)
            if document
            and document.get("kind") == "ConfigMap"
            and document.get("metadata", {}).get("name") == "marty-config"
        ]
        self.assertEqual(len(configmaps), 1)
        deployment = (ROOT / "k8s/oracle/07-microservices.yaml").read_text(
            encoding="utf-8"
        )
        deployments = [
            document
            for document in yaml.safe_load_all(deployment)
            if document
            and document.get("kind") == "Deployment"
            and document.get("metadata", {}).get("name") == "gateway"
        ]
        self.assertEqual(len(deployments), 1)
        containers = deployments[0]["spec"]["template"]["spec"]["containers"]
        gateways = [
            container for container in containers if container.get("name") == "gateway"
        ]
        self.assertEqual(len(gateways), 1)
        gateway = gateways[0]
        self.assertEqual(
            gateway.get("envFrom"), [{"configMapRef": {"name": "marty-config"}}]
        )
        for binding, url in GATEWAY_UPSTREAM_TARGETS.items():
            with self.subTest(binding=binding):
                self.assertEqual(
                    re.findall(
                        rf'(?m)^  {re.escape(binding)}: "(https?://[^"\s]+)"$',
                        configmap,
                    ),
                    [url],
                )
                self.assertEqual(configmaps[0]["data"].get(binding), url)
                overrides = [
                    variable
                    for variable in gateway.get("env", [])
                    if variable.get("name") == binding
                ]
                self.assertLessEqual(len(overrides), 1)
                if overrides:
                    self.assertEqual(
                        overrides[0],
                        {
                            "name": binding,
                            "valueFrom": {
                                "configMapKeyRef": {
                                    "name": "marty-config",
                                    "key": binding,
                                }
                            },
                        },
                    )
        signing_services = [
            document
            for document in yaml.safe_load_all(
                (ROOT / "k8s/oracle/07b-signing-keys.yaml").read_text(encoding="utf-8")
            )
            if document
            and document.get("kind") == "Service"
            and document.get("metadata", {}).get("name") == "signing-keys"
        ]
        self.assertEqual(len(signing_services), 1)
        self.assertTrue(
            any(
                port.get("port") == 8017 and port.get("targetPort") == 8017
                for port in signing_services[0]["spec"]["ports"]
            )
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
        result = planner.plan(
            ["rust/services/auth/src/http_service.rs"], metadata, ROOT
        )
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
            deployments[service] = original.replace(
                edge[marker], "removed-runtime-edge"
            )
            with self.subTest(marker=marker), self.assertRaises(AssertionError):
                assert_deployment_markers()
            deployments[service] = original
        self.assertNotIn(
            "marty-auth",
            {dep["name"] for dep in packages["marty-flow"]["dependencies"]},
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

    def test_organization_auth_jit_grpc_edge_is_source_backed_and_shadow_only(
        self,
    ) -> None:
        metadata = planner.cargo_metadata()
        members = set(metadata["workspace_members"])
        packages = {p["name"]: p for p in metadata["packages"] if p["id"] in members}
        result = planner.plan(
            ["rust/services/organization/src/grpc_service.rs"], metadata, ROOT
        )
        self.assertTrue(result["all"])
        self.assertEqual(result["packages"], sorted(packages))
        self.assertIn("unmapped non-Cargo runtime consumers", result["reason"])
        edges = [
            edge
            for edge in result["observed_non_cargo_consumers"]
            if edge["producer"] == "marty-organization"
            and edge["package"] == "marty-auth"
        ]
        self.assertEqual(len(edges), 1)
        edge = edges[0]
        scopes = {
            "config": (
                "let organization_grpc_target = grpc_target(",
                "let event_stream_grpc_target",
            ),
            "connection": (
                "let organization = workload_channel_factory(",
                "let grpc_clients =",
            ),
            "clients": (
                "pub fn new(flow: Channel",
                "pub fn credential_verification(&self)",
            ),
            "wiring": (
                "pub fn organization_provisioning(",
                "pub struct GrpcCredentialVerificationStarter",
            ),
            "startup": ("let organizations = Arc::new(", "let user_provisioner:"),
            "jit": (
                "pub async fn provision_at(",
                "impl UserProvisioner for JitUserProvisioner",
            ),
            "callback": (
                "pub async fn handle_callback(",
                "async fn publish_login_events(",
            ),
            "add_request": (
                "async fn ensure_default_member(&self",
                "async fn resolve_default_context(",
            ),
            "lookup_requests": (
                "async fn resolve_default_context(",
                "pub struct MmfApplicantProfileProvisioner",
            ),
            "get_organization": (
                "async fn get_organization(",
                "async fn create_organization(",
            ),
            "get_member": ("async fn get_member(", "async fn add_member("),
            "add_member": ("async fn add_member(", "async fn update_member("),
            "server": ("let organization_server =", "runtime.activate()?"),
            "compose": ("\n  auth:\n", "\n  organization:\n"),
        }
        markers = (
            ("binding", "evidence", "config", 1),
            ("runtime_marker", "runtime_evidence", "connection", 1),
            ("client_marker", "client_evidence", "clients", 1),
            ("wiring_marker", "client_evidence", "wiring", 1),
            ("wiring_client_marker", "client_evidence", "wiring", 1),
            ("wiring_token_marker", "client_evidence", "wiring", 1),
            ("registration_marker", "registration_evidence", "startup", 1),
            ("jit_registration_marker", "registration_evidence", "startup", 1),
            ("jit_add_marker", "jit_evidence", "jit", 1),
            ("jit_context_marker", "jit_evidence", "jit", 1),
            ("callback_marker", "callback_evidence", "callback", 1),
            ("add_request_marker", "client_evidence", "add_request", 1),
            ("request_auth_marker", "client_evidence", "add_request", 1),
            ("member_request_marker", "client_evidence", "lookup_requests", 1),
            ("organization_request_marker", "client_evidence", "lookup_requests", 1),
            ("request_auth_marker", "client_evidence", "lookup_requests", 2),
            (
                "organization_provider_marker",
                "provider_evidence",
                "get_organization",
                1,
            ),
            ("provider_auth_marker", "provider_evidence", "get_organization", 1),
            ("member_provider_marker", "provider_evidence", "get_member", 1),
            ("provider_auth_marker", "provider_evidence", "get_member", 1),
            ("add_provider_marker", "provider_evidence", "add_member", 1),
            ("provider_auth_marker", "provider_evidence", "add_member", 1),
            (
                "provider_registration_marker",
                "provider_registration_evidence",
                "server",
                1,
            ),
            ("provider_serving_marker", "provider_registration_evidence", "server", 1),
            ("deployment_marker", "deployment_evidence", "compose", 1),
        )
        sources = {
            path: (ROOT / path).read_text(encoding="utf-8")
            for _, source, _, _ in markers
            if (path := edge[source])
        }

        def scoped_parts(content: str, scope: str) -> tuple[str, str, str]:
            start, end = scopes[scope]
            self.assertIn(start, content)
            before, tail = content.split(start, 1)
            self.assertIn(end, tail)
            body, after = tail.split(end, 1)
            return before + start, body, end + after

        def assert_markers(snapshot: dict[str, str]) -> None:
            for marker, source, scope, count in markers:
                _, body, _ = scoped_parts(snapshot[edge[source]], scope)
                self.assertEqual(body.count(edge[marker]), count, marker)

        assert_markers(sources)
        for marker, source, scope, _ in markers:
            with self.subTest(marker=marker, scope=scope):
                path = edge[source]
                before, body, after = scoped_parts(sources[path], scope)
                changed = dict(sources)
                changed[path] = (
                    before + body.replace(edge[marker], "removed-edge", 1) + after
                )
                with self.assertRaises(AssertionError):
                    assert_markers(changed)
        self.assertNotIn(
            "marty-organization",
            {dep["name"] for dep in packages["marty-auth"]["dependencies"]},
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

    def test_credential_template_issuance_canvas_readiness_http_is_shadow_only(
        self,
    ) -> None:
        metadata = planner.cargo_metadata()
        members = set(metadata["workspace_members"])
        packages = {p["name"]: p for p in metadata["packages"] if p["id"] in members}
        result = planner.plan(
            ["rust/services/credential-template/src/http_service.rs"], metadata, ROOT
        )
        self.assertTrue(result["all"])
        self.assertEqual(result["packages"], sorted(packages))
        self.assertIn("unmapped non-Cargo runtime consumers", result["reason"])
        edges = [
            edge
            for edge in result["observed_non_cargo_consumers"]
            if edge["producer"] == "marty-credential-template"
            and edge["package"] == "marty-issuance-service"
        ]
        self.assertEqual(len(edges), 1)
        edge = edges[0]
        scopes = {
            "config": (
                "let credential_template_service_url = validate_http_base_url(",
                "if settings.initiation.related_resource_max_bytes",
            ),
            "startup": (
                "let canvas_readiness = Arc::new(",
                "let canvas_management = CanvasPlatformManagementHttpService",
            ),
            "registration": (
                "let canvas_management = CanvasPlatformManagementHttpService",
                ".with_application_approval(",
            ),
            "inputs": (
                "impl CanvasReadinessInputProvider for CanvasReadinessRuntime {",
                "pub struct PostgresCanvasReadinessStateProvider",
            ),
            "request": (
                "impl CanvasReadinessDocumentProvider for HttpCanvasReadinessDocumentProvider {",
                "fn append_segments(",
            ),
            "get": (
                "async fn object(&self, endpoint: Option<Url>)",
                "impl CanvasReadinessDocumentProvider for HttpCanvasReadinessDocumentProvider {",
            ),
            "route": (
                "pub fn credential_template_router(",
                "async fn create_template(",
            ),
            "handler": (
                "async fn get_internal_issuance_context(",
                "async fn get_internal_credential_configurations(",
            ),
            "base_compose": ("\n  issuance:\n", "\n  issuance-native:\n"),
            "native_compose": ("\n  issuance-native:\n", None),
        }
        markers = (
            ("readiness_binding", "evidence", "config"),
            ("readiness_startup_marker", "readiness_startup_evidence", "startup"),
            ("readiness_url_marker", "readiness_startup_evidence", "startup"),
            (
                "readiness_registration_marker",
                "readiness_startup_evidence",
                "registration",
            ),
            ("readiness_callsite_marker", "readiness_request_evidence", "inputs"),
            ("readiness_object_marker", "readiness_request_evidence", "request"),
            ("readiness_base_marker", "readiness_request_evidence", "request"),
            ("readiness_endpoint_marker", "readiness_request_evidence", "request"),
            ("readiness_get_marker", "readiness_request_evidence", "get"),
            ("readiness_response_marker", "readiness_request_evidence", "get"),
            ("readiness_provider_route_marker", "readiness_provider_evidence", "route"),
            (
                "readiness_provider_method_marker",
                "readiness_provider_evidence",
                "route",
            ),
            (
                "readiness_provider_handler_marker",
                "readiness_provider_evidence",
                "handler",
            ),
            (
                "readiness_deployment_marker",
                "readiness_deployment_evidence",
                "base_compose",
            ),
            (
                "readiness_deployment_marker",
                "readiness_native_deployment_evidence",
                "native_compose",
            ),
        )
        sources = {
            path: (ROOT / path).read_text(encoding="utf-8")
            for _, source, _ in markers
            if (path := edge[source])
        }

        def scoped_parts(content: str, scope: str) -> tuple[str, str, str]:
            start, end = scopes[scope]
            self.assertIn(start, content)
            before, tail = content.split(start, 1)
            if end is None:
                return before + start, tail, ""
            self.assertIn(end, tail)
            body, after = tail.split(end, 1)
            return before + start, body, end + after

        def assert_markers(snapshot: dict[str, str]) -> None:
            for marker, source, scope in markers:
                _, body, _ = scoped_parts(snapshot[edge[source]], scope)
                if marker == "readiness_object_marker":
                    self.assertEqual(body.count(edge[marker]), 2, marker)
                else:
                    self.assertIn(edge[marker], body, marker)

        assert_markers(sources)
        for marker, source, scope in markers:
            with self.subTest(marker=marker, scope=scope):
                path = edge[source]
                before, body, after = scoped_parts(sources[path], scope)
                changed = dict(sources)
                changed[path] = (
                    before + body.replace(edge[marker], "removed-edge", 1) + after
                )
                with self.assertRaises(AssertionError):
                    assert_markers(changed)
        self.assertNotIn(
            "marty-credential-template",
            {dep["name"] for dep in packages["marty-issuance-service"]["dependencies"]},
        )

    def test_issuance_revocation_profile_http_consumer_is_shadow_only(self) -> None:
        metadata = planner.cargo_metadata()
        members = set(metadata["workspace_members"])
        packages = {p["name"]: p for p in metadata["packages"] if p["id"] in members}
        result = planner.plan(
            ["rust/services/revocation-profile/src/http.rs"], metadata, ROOT
        )
        self.assertTrue(result["all"])
        self.assertEqual(result["packages"], sorted(packages))
        edges = [
            edge
            for edge in result["observed_non_cargo_consumers"]
            if edge["producer"] == "marty-revocation-profile"
            and edge["package"] == "marty-issuance-service"
            and edge.get("binding") == 'values.get("REVOCATION_PROFILE_SERVICE_URL")'
        ]
        self.assertEqual(len(edges), 1)
        edge = edges[0]
        for source_key, markers in (
            ("evidence", ("binding",)),
            (
                "runtime_evidence",
                ("readiness_runtime_marker", "lifecycle_runtime_marker"),
            ),
            (
                "readiness_evidence",
                (
                    "readiness_request_marker",
                    "readiness_send_marker",
                    "readiness_rejection_marker",
                ),
            ),
            (
                "lifecycle_evidence",
                ("allocation_marker", "revocation_marker", "lifecycle_send_marker"),
            ),
            (
                "provider_evidence",
                (
                    "profile_route_marker",
                    "profile_auth_marker",
                    "profile_auth_delegate_marker",
                    "profile_user_marker",
                    "profile_unauthorized_status_marker",
                    "allocation_route_marker",
                    "revocation_route_marker",
                ),
            ),
        ):
            source = (ROOT / edge[source_key]).read_text(encoding="utf-8")
            for marker in markers:
                with self.subTest(source=source_key, marker=marker):
                    self.assertIn(edge[marker], source)
        runtime_source = (ROOT / edge["runtime_evidence"]).read_text(encoding="utf-8")
        for constructor_marker in (
            edge["readiness_runtime_marker"],
            edge["lifecycle_runtime_marker"],
        ):
            with self.subTest(constructor=constructor_marker):
                constructor_args = runtime_source.split(constructor_marker, 1)[1].split(
                    ")?", 1
                )[0]
                self.assertIn(
                    "config.revocation_profile_service_url.clone()", constructor_args
                )
        readiness_source = (ROOT / edge["readiness_evidence"]).read_text(
            encoding="utf-8"
        )
        readiness_object = readiness_source.split("async fn object(", 1)[1].split(
            "#[async_trait]", 1
        )[0]
        self.assertIn(edge["readiness_send_marker"], readiness_object)
        self.assertIn(edge["readiness_rejection_marker"], readiness_object)
        self.assertIn("return Map::new();", readiness_object)
        self.assertNotIn('"x-user-id"', readiness_object)
        provider_source = (ROOT / edge["provider_evidence"]).read_text(encoding="utf-8")
        profile_handler = provider_source.split("async fn get_profile(", 1)[1].split(
            "async fn activate_profile(", 1
        )[0]
        self.assertIn(edge["profile_auth_marker"], profile_handler)
        authorization_handler = provider_source.split("    async fn authorize(", 1)[
            1
        ].split("\n    }\n}", 1)[0]
        self.assertIn(edge["profile_auth_delegate_marker"], authorization_handler)
        user_id_extractor = provider_source.split("fn current_user_id(", 1)[1].split(
            "#[derive(Debug, Error)]", 1
        )[0]
        self.assertIn(edge["profile_user_marker"], user_id_extractor)
        self.assertIn(".filter(|value| !value.trim().is_empty())", user_id_extractor)
        self.assertIn("ApiError::Unauthorized(", user_id_extractor)
        error_response = provider_source.split("impl IntoResponse for ApiError {", 1)[
            1
        ].split("#[cfg(test)]", 1)[0]
        self.assertIn(edge["profile_unauthorized_status_marker"], error_response)
        for route_marker, handler in (
            ("profile_route_marker", "get(get_profile)"),
            ("allocation_route_marker", "post(reserve_index)"),
            ("revocation_route_marker", "post(process_revocation)"),
        ):
            with self.subTest(route=route_marker):
                route_body = provider_source.split(edge[route_marker], 1)[1].split(
                    ".route(", 1
                )[0]
                self.assertIn(handler, route_body)
        with (ROOT / edge["deployment_evidence"]).open(encoding="utf-8") as source:
            compose = yaml.safe_load(source)
        self.assertEqual(
            compose["services"][edge["deployment_service"]]["environment"][
                "REVOCATION_PROFILE_SERVICE_URL"
            ],
            "http://revocation-profile:8013",
        )
        self.assertIn(
            edge["deployment_marker"],
            (ROOT / edge["deployment_evidence"]).read_text(encoding="utf-8"),
        )
        self.assertNotIn(
            "marty-revocation-profile",
            {dep["name"] for dep in packages["marty-issuance-service"]["dependencies"]},
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
                "marty-trust-profile",
                "marty-presentation-policy",
                "marty-flow",
                "marty-auth",
                "marty-gateway",
                "marty-applicant",
                "marty-device-registration",
            },
            "marty-revocation-profile": {
                "marty-revocation-profile",
                "marty-credential-template",
                "marty-verification-service",
                "marty-issuance-service",
                "marty-trust-profile",
                "marty-presentation-policy",
                "marty-flow",
                "marty-auth",
                "marty-gateway",
                "marty-applicant",
                "marty-device-registration",
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
                    and edge.get("binding")
                    != 'values.get("REVOCATION_PROFILE_SERVICE_URL")'
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
        result = planner.plan(
            ["rust/services/issuance/src/application_template_http.rs"], metadata, ROOT
        )
        self.assertTrue(result["all"])
        self.assertEqual(result["packages"], sorted(packages))
        self.assertIn("unmapped non-Cargo runtime consumers", result["reason"])
        edges = [
            edge
            for edge in result["observed_non_cargo_consumers"]
            if edge["producer"] == "marty-issuance-service"
            and edge["package"] == "marty-applicant"
        ]
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
        sources = {
            path: (ROOT / path).read_text(encoding="utf-8")
            for path in {edge[source] for _, source in markers}
        }

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
        self.assertNotIn(
            "marty-issuance-service",
            {dep["name"] for dep in packages["marty-applicant"]["dependencies"]},
        )

    def test_issuance_presentation_policy_status_http_consumer_is_observed_only(
        self,
    ) -> None:
        metadata = planner.cargo_metadata()
        members = set(metadata["workspace_members"])
        packages = {p["name"]: p for p in metadata["packages"] if p["id"] in members}
        result = planner.plan(["rust/services/issuance/src/http.rs"], metadata, ROOT)
        self.assertTrue(result["all"])
        self.assertEqual(result["packages"], sorted(packages))
        edges = [
            edge
            for edge in result["observed_non_cargo_consumers"]
            if edge["producer"] == "marty-issuance-service"
            and edge["package"] == "marty-presentation-policy"
        ]
        self.assertEqual(len(edges), 1)
        edge = edges[0]
        markers = (
            ("binding", "evidence"),
            ("status_marker", "evidence"),
            ("runtime_marker", "runtime_evidence"),
            ("request_marker", "request_evidence"),
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
        self.assertNotIn(
            "marty-issuance-service",
            {
                dep["name"]
                for dep in packages["marty-presentation-policy"]["dependencies"]
            },
        )

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
            ("create_marker", "request_evidence"),
            ("decrypt_marker", "request_evidence"),
            ("callsite_marker", "callsite_evidence"),
            ("envelope_callsite_marker", "callsite_evidence"),
            ("callback_marker", "callback_evidence"),
            ("provider_marker", "provider_evidence"),
            ("provider_handler_marker", "provider_evidence"),
            ("provider_create_marker", "provider_evidence"),
            ("provider_create_handler_marker", "provider_evidence"),
            ("provider_decrypt_marker", "provider_evidence"),
            ("provider_decrypt_handler_marker", "provider_evidence"),
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

    def test_device_registration_trust_profile_edge_is_source_backed_only(
        self,
    ) -> None:
        metadata = planner.cargo_metadata()
        members = set(metadata["workspace_members"])
        packages = {p["name"]: p for p in metadata["packages"] if p["id"] in members}
        device_dependencies = {
            dep["name"] for dep in packages["marty-device-registration"]["dependencies"]
        }
        compose = yaml.safe_load((ROOT / "docker-compose.base.yml").read_text())
        device_environment = compose["services"]["device-registration"]["environment"]
        producer = "marty-trust-profile"
        result = planner.plan(
            [Path(packages[producer]["manifest_path"]).relative_to(ROOT).as_posix()],
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
            and edge["package"] == "marty-device-registration"
        ]
        self.assertEqual(len(edges), 1)
        edge = edges[0]
        self.assertNotIn(producer, device_dependencies)
        self.assertEqual(
            device_environment["TRUST_PROFILE_SERVICE_URL"],
            "http://trust-profile:8004",
        )
        for marker, source in (
            ("binding", "evidence"),
            ("runtime_marker", "runtime_evidence"),
            ("request_marker", "request_evidence"),
            ("request_auth_marker", "request_evidence"),
            ("provider_marker", "provider_evidence"),
            ("provider_handler_marker", "provider_evidence"),
        ):
            with self.subTest(marker=marker):
                text = (ROOT / edge[source]).read_text(encoding="utf-8")
                self.assertIn(edge[marker], text)

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
                    and "gateway_route_marker" in edge
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
                        with (
                            self.subTest(marker=marker),
                            self.assertRaises(AssertionError),
                        ):
                            assert_markers()
                        sources[path] = original
                    assert_markers()
                    compose = (ROOT / edge["deployment_evidence"]).read_text(
                        encoding="utf-8"
                    )
                    auth_tail = compose.split("\n  auth:\n", 1)[1]
                    next_service = re.search(r"(?m)^  [a-z][a-z0-9_-]*:\s*$", auth_tail)
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

    def test_applicant_auth_profile_edge_is_source_backed_and_shadow_only(self) -> None:
        metadata = planner.cargo_metadata()
        members = set(metadata["workspace_members"])
        packages = {p["name"]: p for p in metadata["packages"] if p["id"] in members}
        result = planner.plan(["rust/services/applicant/src/http.rs"], metadata, ROOT)
        self.assertTrue(result["all"])
        self.assertEqual(result["packages"], sorted(packages))
        self.assertIn("unmapped non-Cargo runtime consumers", result["reason"])
        edges = [
            edge
            for edge in result["observed_non_cargo_consumers"]
            if edge["producer"] == "marty-applicant" and edge["package"] == "marty-auth"
        ]
        self.assertEqual(len(edges), 1)
        edge = edges[0]
        self.assertNotIn(
            "marty-applicant",
            {dep["name"] for dep in packages["marty-auth"]["dependencies"]},
        )

        # Scope markers to their owner, so a similar string in an unrelated
        # test or route cannot conceal removal of the actual request chain.
        scopes = {
            "config": (
                "applicant_service_url: origin(",
                "issuance_native_service_url: origin(",
            ),
            "startup": (
                "let applicant_profile = Arc::new(",
                "let organizations = Arc::new(",
            ),
            "jit_startup": (
                "let provisioner = Arc::new(",
                "let event_publisher = Arc::new(",
            ),
            "canvas_startup": (
                "let canvas = Arc::new(",
                "let credential_state = Arc::new(",
            ),
            "canvas_call": (
                "pub async fn finalize(",
                "let session = Session::create(",
            ),
            "login": (
                "pub async fn handle_callback(",
                "async fn publish_login_events(",
            ),
            "jit": (
                "pub async fn provision_at(",
                "impl UserProvisioner for JitUserProvisioner",
            ),
            "request": (
                "async fn upsert_profile(",
                "impl CanvasApplicantProfileProvisioner",
            ),
            "response": (
                "impl ApplicantProvisioningStore for MmfApplicantProvisioningStore",
                "pub struct MmfAuthEventPublisher",
            ),
            "route": ("pub fn router(state: HttpState)", "#[derive(Debug)]"),
            "handler": ("async fn upsert_profile(", "async fn enroll_biometric("),
            "server": ("axum::serve(", ".await"),
        }
        markers = (
            ("binding", "evidence", "config"),
            ("runtime_marker", "runtime_evidence", "startup"),
            ("runtime_url_marker", "runtime_evidence", "startup"),
            ("store_marker", "runtime_evidence", "startup"),
            ("jit_marker", "runtime_evidence", "jit_startup"),
            ("canvas_marker", "runtime_evidence", "canvas_startup"),
            ("canvas_call_marker", "canvas_callsite_evidence", "canvas_call"),
            ("callsite_marker", "callsite_evidence", "login"),
            ("jit_call_marker", "jit_evidence", "jit"),
            ("request_method_marker", "request_evidence", "request"),
            ("request_marker", "request_evidence", "request"),
            ("request_identity_marker", "request_evidence", "request"),
            ("response_identity_marker", "request_evidence", "response"),
            ("provider_route_marker", "provider_evidence", "route"),
            ("provider_identity_marker", "provider_evidence", "handler"),
            ("provider_write_marker", "provider_evidence", "handler"),
            (
                "provider_registration_marker",
                "provider_registration_evidence",
                "server",
            ),
        )
        sources = {
            edge[source]: (ROOT / edge[source]).read_text(encoding="utf-8")
            for _, source, _ in markers
        }

        def scoped_parts(content: str, scope: str) -> tuple[str, str, str]:
            start, end = scopes[scope]
            self.assertIn(start, content)
            before, tail = content.split(start, 1)
            self.assertIn(end, tail)
            section, after = tail.split(end, 1)
            return before + start, section, end + after

        def assert_markers(snapshot: dict[str, str]) -> None:
            for marker, source, scope in markers:
                self.assertIn(
                    edge[marker], scoped_parts(snapshot[edge[source]], scope)[1]
                )

        assert_markers(sources)
        for marker, source, scope in markers:
            with self.subTest(marker=marker):
                path = edge[source]
                changed = dict(sources)
                before, section, after = scoped_parts(changed[path], scope)
                changed[path] = (
                    before + section.replace(edge[marker], "removed-edge", 1) + after
                )
                with self.assertRaises(AssertionError):
                    assert_markers(changed)

        compose = (ROOT / edge["deployment_evidence"]).read_text(encoding="utf-8")
        auth = compose.split(f"\n  {edge['deployment_service']}:\n", 1)[1].split(
            "\n  organization:\n", 1
        )[0]
        applicant = compose.split(f"\n  {edge['deployment_provider_service']}:\n", 1)[
            1
        ].split("\n  notification:\n", 1)[0]
        self.assertNotIn(edge["deployment_absent_marker"], auth)
        self.assertIn(edge["deployment_provider_marker"], applicant)
        with self.assertRaises(AssertionError):
            self.assertNotIn(
                edge["deployment_absent_marker"],
                auth + edge["deployment_absent_marker"],
            )
        with self.assertRaises(AssertionError):
            self.assertIn(
                edge["deployment_provider_marker"],
                applicant.replace(edge["deployment_provider_marker"], "removed-edge"),
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
