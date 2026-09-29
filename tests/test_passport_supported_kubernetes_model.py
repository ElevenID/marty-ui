"""Disposable Kubernetes identity is only a blocked preflight prerequisite."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

from scripts import check_passport_supported_kubernetes_model as gate
from scripts import collect_passport_supported_acceptance as collector

COMMIT = "a" * 40
REFERENCE = "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "b" * 64
NAMESPACE = "marty-passport-acceptance-abcdef"
CONTEXT = "marty-passport-acceptance-context1"
CA = b"disposable test CA"
PLAN_RUN_ID = "123456"


def test_language_neutral_contract_matches_closed_model() -> None:
    contract = json.loads(
        (
            Path(__file__).resolve().parents[1]
            / "contracts/passport-supported-kubernetes-preflight.json"
        ).read_text(encoding="utf-8")
    )
    assert (
        contract["schema"]
        == "marty.passport-supported-kubernetes-preflight-contract/v1"
    )
    assert contract["status"] == "blocked"
    assert contract["resources"] == [f"{kind}/{name}" for kind, name in gate.RESOURCES]
    assert gate.SERVICES == collector.KUBERNETES_SERVICES
    assert gate.OWNER_LABEL == "com.marty.passport.acceptance.owner"
    assert gate.SOURCE_LABEL == "com.marty.passport.acceptance.source-commit"
    assert gate.RUN_LABEL == "com.marty.passport.acceptance.run-id"
    assert contract["rust_selectors"] == list(gate.FLAGS.values())
    assert "clusterip_without_external_ips_load_balancer_or_node_ports" in contract["required_identity"]
    assert "plan_run_id_and_run_bound_simulator_selectors" in contract["required_identity"]
    assert "immutable_run_scoped_configmap" in contract["required_identity"]
    assert "simulator_profile_routing_and_no_physical_provider_ingress" in contract["required_identity"]
    assert contract["runtime_identity"] == [
        "pod_replicaset_deployment_owner_uid_chain",
        "completed_current_rollout_and_pod_created_after_configmap",
        "running_process_routing_checked_without_emitting_environment",
        "second_full_identity_preflight_after_runtime_probe",
        "second_simulator_runtime_probe_after_identity_preflight",
    ]
    assert contract["runtime_accepted"] is False
    assert "python_rollback" not in contract
    assert "rollback_accepted" not in contract


def plan() -> dict:
    return {
        "schema": "marty.passport-supported-kubernetes-model/v1",
        "status": "blocked",
        "source_commit": COMMIT,
        "plan_run_id": PLAN_RUN_ID,
        "services_reference": REFERENCE,
        "cluster": {
            "context": CONTEXT,
            "name": CONTEXT,
            "server": "https://disposable.example:6443",
            "ca_sha256": "sha256:" + hashlib.sha256(CA).hexdigest(),
        },
        "namespace": {"name": NAMESPACE, "uid": "namespace-uid-1234"},
        "resources": {
            f"{kind}/{name}": f"uid-{kind}-{name}-1234" for kind, name in gate.RESOURCES
        },
    }


def runner(expected: dict, *, file_backed_ca: bool = False):
    def run(args: list[str]) -> str:
        assert args[:3] == ["kubectl", "--context", CONTEXT]
        if args[3:5] == ["config", "view"]:
            connection = {"server": "https://disposable.example:6443"}
            if file_backed_ca and "--flatten" not in args:
                connection["certificate-authority"] = "C:/disposable/ca.pem"
            else:
                connection["certificate-authority-data"] = base64.b64encode(CA).decode()
            return json.dumps(
                {
                    "current-context": CONTEXT,
                    "contexts": [{"name": CONTEXT, "context": {"cluster": CONTEXT}}],
                    "clusters": [
                        {
                            "name": CONTEXT,
                            "cluster": connection,
                        }
                    ],
                }
            )
        if args[3:5] == ["get", "namespace"]:
            return json.dumps(
                {
                    "metadata": {
                        "name": NAMESPACE,
                        "uid": "namespace-uid-1234",
                        "labels": {
                            gate.OWNER_LABEL: "supported-consumer",
                            gate.RUN_LABEL: PLAN_RUN_ID,
                            gate.SOURCE_LABEL: COMMIT,
                        },
                    },
                    "status": {"phase": "Active"},
                }
            )
        assert args[3:5] == ["-n", NAMESPACE]
        kind, name = args[6:8]
        if kind in ("deployment", "service") and name == "passport-provider-ingress":
            return ""
        if kind in ("deployment", "service") and name == "issuance":
            return ""
        if kind == "pods" and name == "-l":
            return json.dumps({"items": []})
        item = {
            "metadata": {
                "name": name,
                "namespace": NAMESPACE,
                "uid": expected["resources"][f"{kind}/{name}"],
                "labels": {
                    gate.OWNER_LABEL: "supported-consumer",
                    gate.RUN_LABEL: PLAN_RUN_ID,
                    gate.SOURCE_LABEL: COMMIT,
                },
            }
        }
        if kind == "configmap":
            item["immutable"] = True
            item["data"] = {
                **{flag: "true" for flag in gate.FLAGS.values()},
                "ISSUANCE_NATIVE_SERVICE_URL": "http://issuance-native:8005",
                "PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED": "false",
                "PASSPORT_PROVIDER_INGRESS_SERVICE_URL": "",
                "PERSONALIZATION_BUREAU_URL": "http://passport-beta-bureau:8020",
                "PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID": "passport-beta-bureau",
            }
        elif kind == "service":
            item["spec"] = {
                "type": "ClusterIP",
                "selector": gate.selector_for(name, PLAN_RUN_ID),
                "clusterIP": "10.0.0.1",
            }
        else:
            item["spec"] = {
                "selector": {"matchLabels": gate.selector_for(name, PLAN_RUN_ID)},
                "template": {
                    "metadata": {"labels": gate.selector_for(name, PLAN_RUN_ID)},
                    "spec": {
                        "automountServiceAccountToken": False,
                        "containers": [
                            {
                                "name": name,
                                "image": REFERENCE,
                                **({"envFrom": [{"configMapRef": {"name": "marty-config"}}]}
                                   if name in ("gateway", "flow") else {}),
                                **({"env": [{"name": key, "valueFrom": {"configMapKeyRef": {
                                    "name": "marty-config", "key": key}}}
                                    for key in ("PERSONALIZATION_BUREAU_URL",
                                                "PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID")]}
                                   if name == "issuance-native" else {}),
                            }
                        ],
                    }
                }
            }
        return json.dumps(item)

    return run


def test_exact_disposable_identity_stays_blocked_without_live_proof() -> None:
    expected = plan()
    report = gate.inspect(expected, COMMIT, REFERENCE, runner(expected))
    assert report["static_identity_verified"] is True
    assert report["runtime_accepted"] is False
    assert "rollback_accepted" not in report
    assert report["status"] == "blocked"
    assert report["resource_uids"] == expected["resources"]


def test_file_backed_kubeconfig_ca_is_checked_after_flattening() -> None:
    expected = plan()
    report = gate.inspect(expected, COMMIT, REFERENCE, runner(expected, file_backed_ca=True))
    assert report["static_identity_verified"] is True
    assert report["status"] == "blocked"


@pytest.mark.parametrize(
    "mutate,match",
    [
        (lambda p: p["cluster"].update(context="marty-prod"), "cluster identity"),
        (lambda p: p["cluster"].update(ca_sha256="sha256:" + "f" * 64), "CA digest"),
        (lambda p: p["cluster"].update(server="https://prod.example:6443"), "server"),
        (lambda p: p["namespace"].update(name="marty-prod"), "namespace identity"),
        (lambda p: p.update(plan_run_id="0"), "source or images"),
        (
            lambda p: p["namespace"].update(uid="wrong-namespace-uid"),
            "namespace identity",
        ),
        (
            lambda p: p["resources"].update(
                {"deployment/gateway": "wrong-gateway-uid"}
            ),
            "identity changed",
        ),
        (
            lambda p: p["resources"].update({"service/gateway": "wrong-service-uid"}),
            "identity changed",
        ),
        (lambda p: p.update(rollback_model={"gateway_owner": "python"}),
         "source or images"),
        (
            lambda p: p.update(
                services_reference="ghcr.io/other/services@sha256:" + "b" * 64
            ),
            "source or images",
        ),
    ],
)
def test_identity_or_legacy_model_drift_fails_closed(mutate, match: str) -> None:
    expected = plan()
    mutate(expected)
    with pytest.raises(gate.KubernetesPreflightError, match=match):
        gate.inspect(expected, COMMIT, REFERENCE, runner(plan()))


@pytest.mark.parametrize(
    "target,change,match",
    [
        (
            "config",
            lambda x: x["clusters"][0]["cluster"].update(
                **{"insecure-skip-tls-verify": True}
            ),
            "TLS authority",
        ),
        (
            "namespace",
            lambda x: x["metadata"]["labels"].update(**{gate.SOURCE_LABEL: "f" * 40}),
            "namespace identity",
        ),
        (
            "namespace",
            lambda x: x["metadata"]["labels"].update(**{gate.RUN_LABEL: "987654"}),
            "namespace identity",
        ),
        (
            "deployment/gateway",
            lambda x: x["spec"]["template"]["spec"].update(hostNetwork=True),
            "deployment/gateway is unsafe",
        ),
        (
            "deployment/flow",
            lambda x: x["spec"]["template"]["spec"]["containers"][0].update(
                image="ghcr.io/elevenid/marty-credentials-issuance@sha256:" + "f" * 64
            ),
            "deployment/flow is unsafe",
        ),
        (
            "service/gateway",
            lambda x: x["spec"].update(type="LoadBalancer"),
            "service/gateway is not private",
        ),
        (
            "service/gateway",
            lambda x: x["spec"].update(externalIPs=["203.0.113.1"]),
            "service/gateway is not private",
        ),
        (
            "service/passport-beta-bureau",
            lambda x: x["spec"].update(selector={"app": "passport-beta-bureau"}),
            "service/passport-beta-bureau is not private",
        ),
        (
            "deployment/passport-callback-signer",
            lambda x: x["spec"]["selector"].update(
                matchLabels={"app": "passport-callback-signer"}),
            "deployment/passport-callback-signer selector is invalid",
        ),
        (
            "deployment/flow",
            lambda x: x["spec"]["template"]["spec"]["containers"][0]
            .setdefault("env", []).append({"name": "ISSUANCE_NATIVE_SERVICE_URL",
                                         "value": "http://issuance:8005"}),
            "deployment/flow is not simulator-bound",
        ),
        (
            "configmap/marty-config",
            lambda x: x.update(immutable=False),
            "ConfigMap must be immutable",
        ),
        (
            "configmap/marty-config",
            lambda x: x["data"].update(PASSPORT_NATIVE_FLOW_ENABLED="false"),
            "Rust selector model",
        ),
        (
            "configmap/marty-config",
            lambda x: x["data"].update(PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED="true"),
            "Rust selector model",
        ),
        (
            "configmap/marty-config",
            lambda x: x["data"].update(
                PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID="external-provider"),
            "Rust selector model",
        ),
    ],
)
def test_live_cluster_drift_fails_closed(target, change, match: str) -> None:
    expected = plan()
    baseline = runner(expected)

    def changed(args: list[str]) -> str:
        key = (
            "config"
            if args[3:5] == ["config", "view"]
            else "namespace"
            if args[3:5] == ["get", "namespace"]
            else "/".join(args[6:8])
        )
        raw = baseline(args)
        if not raw.strip():
            return raw
        value = json.loads(raw)
        if key == target:
            change(value)
        return json.dumps(value)

    with pytest.raises(gate.KubernetesPreflightError, match=match):
        gate.inspect(expected, COMMIT, REFERENCE, changed)


@pytest.mark.parametrize("kind", ["deployment", "service", "pods"])
def test_preflight_rejects_physical_provider_in_disposable_namespace(kind: str) -> None:
    expected = plan()
    baseline = runner(expected)

    def mixed(args: list[str]) -> str:
        if args[3:5] == ["-n", NAMESPACE] and args[6] == kind:
            if kind == "pods" and args[8] == "app=passport-provider-ingress":
                return json.dumps({"items": [{"metadata": {"name": "foreign-provider"}}]})
            if len(args) > 7 and args[7] == "passport-provider-ingress":
                return json.dumps({"kind": kind})
        return baseline(args)

    with pytest.raises(gate.KubernetesPreflightError, match="physical provider"):
        gate.inspect(expected, COMMIT, REFERENCE, mixed)


@pytest.mark.parametrize("kind", ["deployment", "service", "pods"])
def test_preflight_rejects_python_issuance_in_rust_only_namespace(kind: str) -> None:
    expected = plan()
    baseline = runner(expected)

    def mixed(args: list[str]) -> str:
        if args[3:5] == ["-n", NAMESPACE] and args[6] == kind:
            if kind == "pods" and args[8] == "app=issuance":
                return json.dumps({"items": [{"metadata": {"name": "issuance-old"}}]})
            if len(args) > 7 and args[7] == "issuance":
                return json.dumps({"kind": kind})
        return baseline(args)

    with pytest.raises(gate.KubernetesPreflightError, match="Python issuance"):
        gate.inspect(expected, COMMIT, REFERENCE, mixed)


def manifest_file(tmp_path: Path) -> Path:
    manifest = tmp_path / "stack-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema": "marty.stack/v1",
                "components": [
                    {
                        "name": "marty-ui",
                        "repository": "ElevenID/marty-ui",
                        "commit": COMMIT,
                        "artifacts": [
                            {
                                "type": "oci",
                                "uri": f"ghcr.io/elevenid/marty-ui-oss/{role}",
                                "digest": "sha256:" + letter * 64,
                            }
                            for role, letter in (
                                ("ui", "d"),
                                ("services", "b"),
                                ("migrations", "e"),
                            )
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return manifest


def test_collector_never_probes_kubernetes_without_identity_plan(
    tmp_path: Path,
) -> None:
    manifest = manifest_file(tmp_path)
    calls = []
    report = collector.collect(
        manifest,
        COMMIT,
        namespace=NAMESPACE,
        kubernetes_context=CONTEXT,
        kubernetes_probe=lambda *args: calls.append(args),
        attest=lambda *args: True,
    )
    assert calls == []
    surface = report["surfaces"]["kubernetes"]
    assert surface["runtime_images"] is None
    assert surface["runtime_accepted"] is False
    assert "rollback_accepted" not in surface
    assert surface["blocker"] == "disposable Kubernetes identity plan is absent"


def test_collector_rejects_deployment_replacement_after_preflight(
    tmp_path: Path,
) -> None:
    expected = plan()
    identity = tmp_path / "identity.json"
    identity.write_text(json.dumps(expected), encoding="utf-8")
    model = gate.inspect(expected, COMMIT, REFERENCE, runner(expected))
    calls = []

    def changed(*args):
        calls.append(args)
        return {
            name: {"deployment_uid": "replacement-uid", "oci_reference": REFERENCE}
            for name in gate.SERVICES
        }

    report = collector.collect(
        manifest_file(tmp_path),
        COMMIT,
        namespace=NAMESPACE,
        kubernetes_context=CONTEXT,
        kubernetes_identity_plan=identity,
        kubernetes_preflight=lambda *args: model,
        kubernetes_probe=changed,
        attest=lambda *args: True,
    )
    assert len(calls) == 1
    surface = report["surfaces"]["kubernetes"]
    assert surface["runtime_images"] is None
    assert surface["blocker"] == "disposable runtime probe failed"
    assert surface["runtime_accepted"] is False


def test_collector_rejects_service_replacement_during_runtime_probe(
    tmp_path: Path,
) -> None:
    expected = plan()
    identity = tmp_path / "identity.json"
    identity.write_text(json.dumps(expected), encoding="utf-8")
    model = gate.inspect(expected, COMMIT, REFERENCE, runner(expected))
    calls = []

    def preflight(*args):
        calls.append("preflight")
        if len(calls) == 1:
            return model
        replaced = dict(model)
        replaced["resource_uids"] = {
            **model["resource_uids"], "service/gateway": "replacement-uid"
        }
        return replaced

    def probe(*args):
        calls.append("probe")
        return {
            name: {"deployment_uid": model["resource_uids"][f"deployment/{name}"],
                   "oci_reference": REFERENCE}
            for name in collector.KUBERNETES_SERVICES
        }

    report = collector.collect(
        manifest_file(tmp_path), COMMIT, namespace=NAMESPACE,
        kubernetes_context=CONTEXT, kubernetes_identity_plan=identity,
        kubernetes_preflight=preflight, kubernetes_probe=probe,
        attest=lambda *args: True,
    )
    assert calls == ["preflight", "probe", "preflight"]
    surface = report["surfaces"]["kubernetes"]
    assert surface["runtime_images"] is None
    assert surface["runtime_accepted"] is False


def test_collector_records_stable_rust_only_identity_as_blocked(
    tmp_path: Path,
) -> None:
    expected = plan()
    identity = tmp_path / "identity.json"
    identity.write_text(json.dumps(expected), encoding="utf-8")
    model = gate.inspect(expected, COMMIT, REFERENCE, runner(expected))
    calls = []

    def probe(*args):
        calls.append(args)
        return {
            name: {"deployment_uid": model["resource_uids"][f"deployment/{name}"],
                   "oci_reference": REFERENCE, "container_id": name + "-container"}
            for name in collector.KUBERNETES_SERVICES
        }

    report = collector.collect(
        manifest_file(tmp_path), COMMIT, namespace=NAMESPACE,
        kubernetes_context=CONTEXT, kubernetes_identity_plan=identity,
        kubernetes_preflight=lambda *args: model, kubernetes_probe=probe,
        attest=lambda *args: True,
    )
    assert len(calls) == 2
    assert all(args[-1] == COMMIT for args in calls)
    surface = report["surfaces"]["kubernetes"]
    assert surface["identity_preflight"] == model
    assert surface["runtime_accepted"] is False
    assert report["status"] == "blocked"
    assert surface["blocker"] == "nine-route/Kubernetes simulator/restart acceptance is pending"


def test_collector_rechecks_simulator_routing_after_identity_preflight(
    tmp_path: Path,
) -> None:
    expected = plan()
    identity = tmp_path / "identity.json"
    identity.write_text(json.dumps(expected), encoding="utf-8")
    model = gate.inspect(expected, COMMIT, REFERENCE, runner(expected))
    calls = []

    def probe(*args):
        calls.append("probe")
        runtime = {
            name: {"deployment_uid": model["resource_uids"][f"deployment/{name}"],
                   "oci_reference": REFERENCE}
            for name in collector.KUBERNETES_SERVICES
        }
        if len(calls) == 2:
            runtime["gateway"]["simulator_binding"] = "replaced"
        return runtime

    report = collector.collect(
        manifest_file(tmp_path), COMMIT, namespace=NAMESPACE,
        kubernetes_context=CONTEXT, kubernetes_identity_plan=identity,
        kubernetes_preflight=lambda *args: model, kubernetes_probe=probe,
        attest=lambda *args: True,
    )
    assert calls == ["probe", "probe"]
    surface = report["surfaces"]["kubernetes"]
    assert surface["runtime_images"] is None
    assert surface["blocker"] == "disposable runtime probe failed"
