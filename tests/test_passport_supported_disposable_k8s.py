"""Freeze the disposable Kubernetes simulator component used by acceptance."""

from pathlib import Path

import yaml

from scripts.collect_passport_supported_acceptance import KUBERNETES_SERVICES


ROOT = Path(__file__).resolve().parents[1]
MODEL = ROOT / "k8s/passport-supported-disposable/01-simulator.yaml"
NAMESPACE = "${PASSPORT_ACCEPTANCE_NAMESPACE}"
IMAGE = "${MARTY_SERVICES_IMAGE}"
OWNER_LABELS = {
    "com.marty.passport.acceptance.owner": "supported-consumer",
    "com.marty.passport.acceptance.run-id": "${PASSPORT_ACCEPTANCE_PLAN_RUN_ID}",
    "com.marty.passport.acceptance.source-commit": "${PASSPORT_ACCEPTANCE_SOURCE_COMMIT}",
}


def test_disposable_kubernetes_selects_marty_simulator_without_provider() -> None:
    source = MODEL.read_text(encoding="utf-8")
    objects = {(item["kind"], item["metadata"]["name"]): item
               for item in yaml.safe_load_all(source)}
    assert len(objects) == 5
    assert set(KUBERNETES_SERVICES) == {
        "gateway", "flow", "issuance-native", "passport-callback-signer",
        "passport-beta-bureau",
    }
    assert set(objects) == {
        ("Deployment", "passport-callback-signer"),
        ("Deployment", "passport-beta-bureau"),
        ("Service", "passport-callback-signer"),
        ("Service", "passport-beta-bureau"),
        ("NetworkPolicy", "passport-acceptance-callback-signer-ingress"),
    }
    assert all(item["metadata"]["namespace"] == NAMESPACE for item in objects.values())
    assert "marty-prod" not in source
    assert "passport-provider-ingress" not in source
    assert "PASSPORT_PROVIDER_WEBHOOK_SECRET" not in source

    for name, role, flag in (
        ("passport-callback-signer", "passport_callback_signer",
         "PASSPORT_CALLBACK_SIGNER_ENABLED"),
        ("passport-beta-bureau", "passport_beta_bureau",
         "PASSPORT_BETA_BUREAU_ENABLED"),
    ):
        deployment = objects[("Deployment", name)]
        template = deployment["spec"]["template"]
        assert all(deployment["metadata"]["labels"][key] == value
                   and template["metadata"]["labels"][key] == value
                   for key, value in OWNER_LABELS.items())
        assert deployment["metadata"]["annotations"]["com.marty.passport.acceptance.services-image"] == IMAGE
        assert template["metadata"]["annotations"]["com.marty.passport.acceptance.services-image"] == IMAGE
        pod = template["spec"]
        assert pod["automountServiceAccountToken"] is False
        assert pod["securityContext"]["runAsNonRoot"] is True
        container, = pod["containers"]
        assert container["image"] == IMAGE
        env = {item["name"]: item["value"] for item in container["env"]}
        assert env["SERVICE_NAME"] == role
        assert env["ENVIRONMENT"] == "beta"
        assert env[flag] == "true"
        service = objects[("Service", name)]
        assert service["spec"]["selector"] == {"app": name}
        assert all(service["metadata"]["labels"][key] == value
                   for key, value in OWNER_LABELS.items())
        assert service["metadata"]["annotations"]["com.marty.passport.acceptance.services-image"] == IMAGE

    bureau_env = {item["name"]: item["value"] for item in objects[
        ("Deployment", "passport-beta-bureau")]["spec"]["template"]["spec"]["containers"][0]["env"]}
    assert bureau_env["PASSPORT_BUREAU_CALLBACK_URL"] == (
        "http://issuance-native:8005/v1/passport/webhooks/personalization")
    assert bureau_env["SIGNING_KEYS_INTERNAL_URL"] == (
        "http://passport-callback-signer:8018/internal/documents")
    policy = objects[("NetworkPolicy", "passport-acceptance-callback-signer-ingress")]
    assert policy["spec"]["podSelector"]["matchLabels"] == {"app": "passport-callback-signer"}
    assert policy["spec"]["ingress"][0]["from"][0]["podSelector"]["matchLabels"] == {
        "app": "passport-beta-bureau"}
