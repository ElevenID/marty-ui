import importlib.util
from pathlib import Path

from marty_devops import DeploymentCatalog
from marty_devops.cli import main as devops_cli_main


REPO_ROOT = Path(__file__).resolve().parents[2]


def test_deployment_catalog_loads_and_validates():
    catalog = DeploymentCatalog.load(REPO_ROOT)

    assert "selfhost-production" in catalog.stacks
    assert "selfhost-beta-tunnel" in catalog.stacks
    assert "tunnel-beta-experiments" in catalog.stacks
    assert "kubernetes-production" in catalog.stacks
    assert "selfhost-commercial" in catalog.artifacts
    assert "license_key" in catalog.secrets


def test_provider_neutral_kubernetes_scripts_exist():
    assert (REPO_ROOT / "scripts" / "deploy-kubernetes.sh").exists()
    assert (REPO_ROOT / "scripts" / "build-push-registry.sh").exists()
    assert "deploy-kubernetes.sh" in (REPO_ROOT / "scripts" / "deploy-oracle.sh").read_text(encoding="utf-8")
    assert "build-push-registry.sh" in (REPO_ROOT / "scripts" / "build-push-ocir.sh").read_text(encoding="utf-8")


def test_selfhost_production_plan_is_commercial_and_license_gated():
    catalog = DeploymentCatalog.load(REPO_ROOT)
    plan = catalog.redacted_stack_plan("selfhost-production")

    assert plan["artifact_profile"] == "selfhost-commercial"
    assert plan["artifact_commercial"] is True
    assert plan["license_policy"] == "selfhost-system"
    assert plan["license_enforcement"] == "required"
    assert "license_key" in plan["required_secret_names"]
    assert "license_public_key" not in plan["required_secret_names"]
    assert "license_public_key" not in catalog.secrets


def test_license_required_selfhost_stacks_use_commercial_artifacts():
    catalog = DeploymentCatalog.load(REPO_ROOT)

    guarded_stacks = [
        stack
        for stack, payload in catalog.stacks.items()
        if payload.get("license_policy") == "selfhost-system"
    ]

    assert guarded_stacks
    assert all(catalog.artifacts[catalog.stacks[stack]["artifact_profile"]]["commercial"] for stack in guarded_stacks)


def test_beta_tunnel_compose_command_uses_profile_and_no_deps():
    catalog = DeploymentCatalog.load(REPO_ROOT)

    command = catalog.compose_command("selfhost-beta-tunnel", "up")

    assert command[:4] == ["docker", "compose", "--env-file", ".env.selfhost.production.local"]
    assert ["--profile", "beta-tunnel"] == command[command.index("--profile") : command.index("--profile") + 2]
    assert "--no-deps" in command
    assert "tunnel-nginx-proxy" in command
    assert "cloudflared-beta" in command


def test_beta_experiments_plan_includes_canvas_services_and_secret():
    catalog = DeploymentCatalog.load(REPO_ROOT)
    plan = catalog.redacted_stack_plan("tunnel-beta-experiments")

    assert plan["artifact_profile"] == "source-debuggable"
    assert plan["artifact_commercial"] is False
    assert plan["license_policy"] == "internal-dev"
    assert "docker-compose.profile.canvas-real.yml" in plan["compose_files"]
    assert "canvas-real" in plan["required_services"]
    assert "issuance-canvas-localhost-bridge" in plan["required_services"]
    assert "canvas_credentials_shared_secret" in plan["required_secret_names"]


def test_stack_service_expansion_deduplicates_group_and_direct_services():
    catalog = DeploymentCatalog.load(REPO_ROOT)

    services = catalog.expanded_services_for_stack("selfhost-beta-tunnel")

    assert services == ["tunnel-nginx-proxy", "cloudflared-beta"]


def test_selfhost_bundle_manifest_assets_exist():
    catalog = DeploymentCatalog.load(REPO_ROOT)

    assets = catalog.bundle_assets("selfhost")

    assert REPO_ROOT / "docker" / "tunnel-nginx-proxy.edge.conf" in assets
    assert all(asset.exists() for asset in assets)


def test_redacted_plan_contains_secret_names_not_values():
    catalog = DeploymentCatalog.load(REPO_ROOT)
    plan = catalog.redacted_stack_plan("selfhost-production")
    rendered = repr(plan)

    assert "required_secret_names" in plan
    assert "change-me" not in rendered
    assert "eyJ" not in rendered


def test_selfhost_running_services_exclude_one_shots_and_optional_services():
    catalog = DeploymentCatalog.load(REPO_ROOT)

    running_services = catalog.running_services_for_stack("selfhost-production")

    assert "db-migrate" not in running_services
    assert "keycloak-configurator" not in running_services
    assert "device-registration" not in running_services
    assert "gateway" in running_services
    assert "cloudflared" in running_services


def test_services_cli_can_print_compose_services_for_running_stack(capsys):
    exit_code = devops_cli_main(
        [
            "--repo-root",
            str(REPO_ROOT),
            "services",
            "selfhost-production",
            "--running-only",
            "--field",
            "compose_service",
        ]
    )

    output = capsys.readouterr().out.splitlines()
    assert exit_code == 0
    assert "gateway" in output
    assert "db-migrate" not in output
    assert "device-registration" not in output


def test_services_cli_can_print_app_service_name_env_values(capsys):
    exit_code = devops_cli_main(
        [
            "--repo-root",
            str(REPO_ROOT),
            "services",
            "--group",
            "app",
            "--field",
            "service_name_env",
        ]
    )

    output = capsys.readouterr().out.splitlines()
    assert exit_code == 0
    assert "credential_template" in output
    assert "device_registration" in output


def test_required_secret_specs_include_compose_file_names():
    catalog = DeploymentCatalog.load(REPO_ROOT)

    specs = catalog.required_secret_specs_for_stack("selfhost-production")
    by_id = {spec["id"]: spec for spec in specs}

    assert by_id["license_key"]["compose_secret"] == "license_key"
    assert by_id["cloudflare_tunnel_token"]["compose_secret"] == "cloudflare_tunnel_token"
    assert catalog.secret_file_name("openbao_service_token") == "openbao_service_token"


def test_selfhost_secret_examples_cover_schema():
    catalog = DeploymentCatalog.load(REPO_ROOT)
    example_dir = REPO_ROOT / "docker" / "secrets" / "selfhost.example"

    missing = [
        catalog.secret_file_name(secret_id)
        for secret_id, secret in catalog.secrets.items()
        if secret.get("compose_secret") and not (example_dir / catalog.secret_file_name(secret_id)).exists()
    ]

    assert missing == []


def test_customer_distribution_uses_embedded_license_public_key():
    compose_text = (REPO_ROOT / "docker-compose.selfhost.prod.yml").read_text(encoding="utf-8")
    secret_readme = (REPO_ROOT / "docker" / "secrets" / "selfhost.example" / "README.md").read_text(encoding="utf-8")
    bundle_readme = (REPO_ROOT / "SELFHOST_BUNDLE.md").read_text(encoding="utf-8")
    production_env = (REPO_ROOT / ".env.production.example").read_text(encoding="utf-8")
    issuer_tool = (REPO_ROOT.parent / "tools" / "selfhost-license-issuer" / "selfhost_license_issuer.py").read_text(encoding="utf-8")

    assert "LICENSE_PUBLIC_KEY_FILE" not in compose_text
    assert "license_public_key" not in compose_text
    assert not (REPO_ROOT / "docker" / "secrets" / "selfhost.example" / "license_public_key").exists()
    assert "license_public_key" not in secret_readme
    assert "license_public_key" not in bundle_readme
    assert "LICENSE_PUBLIC_KEY=" not in production_env
    assert 'secret_dir / "license_public_key"' not in issuer_tool
    assert '"LICENSE_PUBLIC_KEY"' not in issuer_tool


def test_kubernetes_required_secret_schema_matches_setup_requirements():
    catalog = DeploymentCatalog.load(REPO_ROOT)

    env_names = [spec["env"] for spec in catalog.required_secret_specs_for_stack("kubernetes-production")]

    assert env_names == [
        "POSTGRES_PASSWORD",
        "KEYCLOAK_DB_PASSWORD",
        "MARTY_DB_PASSWORD",
        "KEYCLOAK_ADMIN_PASSWORD",
        "MARTY_API_CLIENT_SECRET",
        "RABBITMQ_PASSWORD",
        "RABBITMQ_ERLANG_COOKIE",
        "SESSION_SECRET_KEY",
        "ISSUANCE_API_KEY",
        "OPENBAO_SERVICE_TOKEN",
        "LICENSE_KEY",
    ]


def test_secrets_cli_prints_required_kubernetes_env_names_only(capsys):
    exit_code = devops_cli_main(
        [
            "--repo-root",
            str(REPO_ROOT),
            "secrets",
            "kubernetes-production",
            "--field",
            "env",
        ]
    )

    output = capsys.readouterr().out.splitlines()
    assert exit_code == 0
    assert "POSTGRES_PASSWORD" in output
    assert "LICENSE_KEY" in output
    assert "CLOUDFLARE_TUNNEL_TOKEN" not in output
    assert all("change-me" not in line and "eyJ" not in line for line in output)


def test_selfhost_bundle_staging_uses_manifest_assets(tmp_path):
    module_path = REPO_ROOT / "scripts" / "package-selfhost-bundle.py"
    spec = importlib.util.spec_from_file_location("package_selfhost_bundle", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    output_dir = tmp_path / "selfhost-bundle"
    module.stage_bundle(REPO_ROOT, output_dir)

    assert (output_dir / "README.md").exists()
    assert (output_dir / "docker" / "tunnel-nginx-proxy.edge.conf").exists()
    assert not (output_dir / "docker" / "secrets" / "selfhost.example" / "license_public_key").exists()
    assert not (output_dir / "SELFHOST_BUNDLE.md").exists()
