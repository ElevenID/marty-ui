from __future__ import annotations

import ast
from copy import deepcopy
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tomllib

import pytest
import yaml
from marty_devops import DeploymentCatalog


ROOT = Path(__file__).resolve().parents[1]
PROCESSOR = (
    "issuance.infrastructure.api.canvas_routes:process_authoritative_canvas_sync_target"
)


def _yaml(path: str):
    return yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))


def test_compose_stacks_run_canvas_worker_outside_issuance_web_process() -> None:
    for path in ("docker-compose.base.yml", "docker-compose.selfhost.prod.yml"):
        services = _yaml(path)["services"]
        api = services["issuance"]
        worker = services["canvas-sync-worker"]

        assert "canvas_worker" not in str(api.get("command", ""))
        assert "issuance.canvas_worker" in str(worker["command"])
        assert worker["healthcheck"] == {"disable": True}
        assert "ports" not in worker
        assert (
            worker["depends_on"]["db-migrate"]["condition"]
            == "service_completed_successfully"
        )
        assert (
            worker["depends_on"]["issuance-migrations"]["condition"]
            == "service_completed_successfully"
        )

        environment = worker["environment"]
        api_environment = api["environment"]
        assert "CANVAS_OAUTH_COMPLETION_REDIRECT_URL" in api_environment
        assert "CANVAS_PORTABLE_INTEGRATION_ENABLED" in environment
        assert {"TOKEN_HMAC_KEY", "TOKEN_HMAC_KEY_FILE"}.intersection(environment)
        assert "CANVAS_LEGACY_EVENT_INGEST_ENABLED" in environment
        assert "CANVAS_LTI_TOOL_SIGNING_ORGANIZATION_ID" in environment
        assert "CANVAS_LTI_TOOL_ISSUER_DID" in environment
        assert "CANVAS_CREDENTIAL_ISSUER_PROFILE_IDS" in environment
        assert "CANVAS_LTI_TOOL_ACTIVE_KID" in environment
        assert "CANVAS_LTI_TOOL_PUBLIC_JWKS" in environment
        assert environment["CANVAS_BINDING_READINESS_MAX_AGE_SECONDS"].endswith(
            ":-900}"
        )
        assert environment["CANVAS_BACKGROUND_ROSTER_BATCH_SIZE"].endswith(":-500}")
        assert environment["CANVAS_BACKGROUND_ROSTER_MAX_SIZE"].endswith(":-5000}")
        assert environment["CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS"].endswith(":-600}")
        assert (
            environment["SIGNING_KEYS_INTERNAL_URL"]
            == "http://gateway:8000/internal/signing-keys"
        )
        assert {
            "SIGNING_KEYS_INTERNAL_API_KEY",
            "SIGNING_KEYS_INTERNAL_API_KEY_FILE",
        }.intersection(environment)
        for key in (
            "CANVAS_LTI_TOOL_SIGNING_ORGANIZATION_ID",
            "CANVAS_LTI_TOOL_ISSUER_DID",
            "CANVAS_CREDENTIAL_ISSUER_PROFILE_IDS",
            "CANVAS_LTI_TOOL_ACTIVE_KID",
            "CANVAS_LTI_TOOL_PUBLIC_JWKS",
        ):
            assert key in api_environment
        assert api_environment["CANVAS_ISSUANCE_EVIDENCE_MAX_AGE_SECONDS"].endswith(
            ":-900}"
        )
        assert api_environment["CANVAS_BINDING_READINESS_MAX_AGE_SECONDS"].endswith(
            ":-900}"
        )
        for private_key_setting in (
            "CANVAS_LTI_TOOL_PRIVATE_JWKS",
            "CANVAS_LTI_TOOL_PRIVATE_JWKS_FILE",
            "CANVAS_LTI_DEEP_LINKING_PRIVATE_JWK",
            "CANVAS_LTI_DEEP_LINKING_PRIVATE_JWK_FILE",
            "CANVAS_LTI_ALLOW_LOCAL_PRIVATE_JWK",
        ):
            assert private_key_setting not in environment
            assert private_key_setting not in api_environment
        assert PROCESSOR in environment["CANVAS_SYNC_PROCESSOR"]
        assert "CANVAS_SYNC_WORKER_POLL_SECONDS" in environment


def test_unrouted_rust_candidate_is_packaged_without_changing_consumers() -> None:
    cargo = (ROOT / "rust/services/issuance/Cargo.toml").read_text(encoding="utf-8")
    worker = (ROOT / "rust/services/issuance/src/bin/canvas_sync_worker.rs").read_text(
        encoding="utf-8"
    )
    service_image = (ROOT / "services/Dockerfile").read_text(encoding="utf-8")
    ci_image = (ROOT / "rust/services/Dockerfile.ci").read_text(encoding="utf-8")

    assert 'name = "marty-canvas-sync-worker"' in cargo
    worker_target = next(
        target
        for target in tomllib.loads(cargo)["bin"]
        if target["name"] == "marty-canvas-sync-worker"
    )
    assert worker_target.get("test", True), (
        "workspace tests must execute worker binary tests"
    )
    assert "NativeCanvasSyncProcessor::new" in worker
    assert "canvas_sync_processor_unavailable" not in worker
    for dockerfile in (service_image, ci_image):
        assert "--bin marty-canvas-sync-worker" in dockerfile
        assert "target/release/marty-canvas-sync-worker" in dockerfile

    # Candidate packaging is not a cutover: every production consumer remains
    # on the Python oracle until the frozen differential/deletion gates pass.
    for path in ("docker-compose.base.yml", "docker-compose.selfhost.prod.yml"):
        worker = _yaml(path)["services"]["canvas-sync-worker"]
        assert "issuance.canvas_worker" in str(worker["command"])
        assert PROCESSOR in worker["environment"]["CANVAS_SYNC_PROCESSOR"]


def test_deployments_migrate_issuance_from_the_released_credentials_image() -> None:
    for path in ("docker-compose.base.yml", "docker-compose.selfhost.prod.yml"):
        services = _yaml(path)["services"]
        migration = services["issuance-migrations"]

        assert migration["image"] == services["issuance"]["image"]
        command = str(migration["command"])
        assert "manage_migrations.py" in command
        assert "upgrade" in command
        assert migration["healthcheck"] == {"disable": True}
        assert migration["restart"] == "no"
        assert (
            migration["depends_on"]["db-migrate"]["condition"]
            == "service_completed_successfully"
        )
        assert (
            services["issuance"]["depends_on"]["issuance-migrations"]["condition"]
            == "service_completed_successfully"
        )

    kubernetes = _yaml("k8s/oracle/06a-issuance-migrations.yaml")
    assert kubernetes["kind"] == "Job"
    assert kubernetes["metadata"]["name"] == "issuance-migrations"
    container = kubernetes["spec"]["template"]["spec"]["containers"][0]
    assert container["image"] == "${OCIR_REGISTRY}/marty-ui/issuance:${IMAGE_TAG}"
    assert container["command"] == ["python", "manage_migrations.py", "upgrade"]
    assert (
        container["env"][0]["valueFrom"]["secretKeyRef"]["key"] == "DATABASE_SYNC_URL"
    )

    deploy = (ROOT / "scripts/deploy-kubernetes.sh").read_text(encoding="utf-8")
    ui_wait = deploy.index("condition=complete job/db-migrate")
    issuance_apply = deploy.index("06a-issuance-migrations.yaml")
    issuance_wait = deploy.index("condition=complete job/issuance-migrations")
    assert ui_wait < issuance_apply < issuance_wait


def test_kubernetes_runs_headless_canvas_worker_as_its_own_deployment() -> None:
    documents = list(
        yaml.safe_load_all(
            (ROOT / "k8s/oracle/07-microservices.yaml").read_text(encoding="utf-8")
        )
    )
    worker = next(
        document
        for document in documents
        if document
        and document.get("kind") == "Deployment"
        and document.get("metadata", {}).get("name") == "canvas-sync-worker"
    )
    container = worker["spec"]["template"]["spec"]["containers"][0]

    assert container["command"] == ["python"]
    assert container["args"] == ["-m", "issuance.canvas_worker"]
    assert "ports" not in container
    assert container["envFrom"] == [{"configMapRef": {"name": "marty-config"}}]
    secret_names = {
        item["name"]: item["valueFrom"]["secretKeyRef"]["key"]
        for item in container["env"]
        if "valueFrom" in item
    }
    assert secret_names == {
        "DATABASE_URL": "DATABASE_URL",
        "INTEGRATION_SECRET_MASTER_KEY": "INTEGRATION_SECRET_MASTER_KEY",
        "SIGNING_KEYS_INTERNAL_API_KEY": "SIGNING_KEYS_INTERNAL_API_KEY",
    }
    assert next(
        item for item in container["env"] if item["name"] == "SIGNING_KEYS_INTERNAL_URL"
    )["value"] == ("http://gateway:8000/internal/signing-keys")


@pytest.mark.parametrize(
    "service", ["canvas-sync-worker", "issuance", "issuance-migrations"]
)
def test_selfhost_bundle_does_not_override_unqualified_services(service) -> None:
    # Parse nodes rather than pretending Compose's !reset is ordinary YAML.
    # The executable rendering gate separately tests actual Compose merging.
    override = yaml.compose(
        (ROOT / "docker-compose.selfhost.bundle.override.yml").read_text(
            encoding="utf-8"
        )
    )
    assert isinstance(override, yaml.MappingNode)
    services = next(value for key, value in override.value if key.value == "services")
    assert isinstance(services, yaml.MappingNode)
    assert service not in {key.value for key, _ in services.value}


@pytest.fixture
def compose_worker_gate():
    return runpy.run_path(str(ROOT / "scripts/test_canvas_worker_compose_render.py"))


def test_ci_executes_real_compose_worker_merge_gate() -> None:
    workflow = _yaml(".github/workflows/ci.yml")
    steps = workflow["jobs"]["test-rust-service-images"]["steps"]
    gate = next(
        step
        for step in steps
        if step.get("name") == "Verify merged Canvas worker deployment configuration"
    )
    assert gate["run"] == "python3 scripts/test_canvas_worker_compose_render.py"
    assert "if" not in gate and "continue-on-error" not in gate


@pytest.mark.parametrize(
    "field",
    [
        None,
        "image",
        "entrypoint",
        "command",
        "environment",
        "secrets",
        "depends_on",
        "healthcheck",
        "restart",
        "ports",
        "future_field",
    ],
)
def test_bundle_worker_comparison_preserves_every_field(compose_worker_gate, field):
    base = _yaml("docker-compose.selfhost.prod.yml")
    bundle = deepcopy(base)
    worker = bundle["services"]["canvas-sync-worker"]
    if field == "image":
        worker[field] = "synthetic-rust-services-image"
    elif field == "environment":
        worker[field]["SERVICE_NAME"] = "issuance_native"
    elif field == "secrets":
        worker[field].remove("integration_secret_master_key")
    elif field == "depends_on":
        worker[field]["issuance-migrations"]["condition"] = "service_started"
    elif field is not None:
        worker[field] = "synthetic-unexpected-change"
    compare = compose_worker_gate["assert_worker_preserved"]
    if field is None:
        compare(base, bundle)
    else:
        with pytest.raises(AssertionError, match="complete unqualified Python"):
            compare(base, bundle)


def test_compose_renderer_only_reads_fixed_sources_without_secret_resolution(
    compose_worker_gate, monkeypatch
):
    expected = {"services": {"canvas-sync-worker": {"synthetic": True}}}
    calls = []

    def execute(command, **options):
        calls.append((command, options))
        return subprocess.CompletedProcess(command, 0, json.dumps(expected), "")

    monkeypatch.setattr(compose_worker_gate["subprocess"], "run", execute)
    files = [compose_worker_gate["BASE"], compose_worker_gate["BUNDLE"]]
    assert compose_worker_gate["render"](*files) == expected
    assert calls == [
        (
            [
                "docker",
                "compose",
                "--env-file",
                os.devnull,
                "-f",
                files[0],
                "-f",
                files[1],
                "config",
                "--no-interpolate",
                "--no-env-resolution",
                "--no-path-resolution",
                "--no-consistency",
                "--format",
                "json",
            ],
            {
                "cwd": ROOT,
                "check": True,
                "capture_output": True,
                "text": True,
                "stdin": subprocess.DEVNULL,
                "timeout": 30,
            },
        )
    ]


@pytest.mark.parametrize("service", ["issuance", "issuance-migrations"])
@pytest.mark.parametrize(
    "field",
    [
        None,
        "image",
        "entrypoint",
        "command",
        "environment",
        "secrets",
        "volumes",
        "depends_on",
        "healthcheck",
        "restart",
        "future_field",
    ],
)
def test_bundle_issuance_comparison_preserves_every_field(
    compose_worker_gate, service, field
):
    base = _yaml("docker-compose.selfhost.prod.yml")
    bundle = deepcopy(base)
    if field is not None:
        bundle["services"][service][field] = "synthetic-unexpected-change"
    compare = compose_worker_gate["assert_published_issuance_preserved"]
    if field is None:
        compare(base, bundle)
    else:
        with pytest.raises(AssertionError, match="complete unqualified Python"):
            compare(base, bundle)


@pytest.mark.parametrize("failure", ["command", "timeout", "invalid_json"])
def test_compose_renderer_fails_closed(compose_worker_gate, monkeypatch, failure):
    def execute(command, **options):
        if failure == "command":
            raise subprocess.CalledProcessError(1, command)
        if failure == "timeout":
            raise subprocess.TimeoutExpired(command, options["timeout"])
        return subprocess.CompletedProcess(command, 0, "not-json", "")

    monkeypatch.setattr(compose_worker_gate["subprocess"], "run", execute)
    with pytest.raises(
        (subprocess.CalledProcessError, subprocess.TimeoutExpired, json.JSONDecodeError)
    ):
        compose_worker_gate["render"](compose_worker_gate["BASE"])


@pytest.mark.parametrize("variant", ["inherited", "isolated", "beta"])
@pytest.mark.parametrize(
    "field",
    [
        None,
        "image",
        "entrypoint",
        "command",
        "environment",
        "secrets",
        "depends_on",
        "networks",
        "healthcheck",
        "restart",
        "ports",
        "future_field",
    ],
)
def test_consumer_comparison_preserves_complete_worker_with_only_reviewed_differences(
    compose_worker_gate, variant, field
):
    base = _yaml("docker-compose.base.yml")
    worker = base["services"]["canvas-sync-worker"]
    # Seed preservation-sensitive fields even when today's base inherits them.
    worker["secrets"] = ["synthetic-required-secret"]
    worker["future_field"] = {"retained": True}
    worker["container_name"] = "synthetic-source-worker"
    pristine = deepcopy(base)
    model = deepcopy(base)
    changed = model["services"]["canvas-sync-worker"]
    if variant == "isolated":
        del changed["container_name"]
    if variant == "beta":
        changed["environment"].update(compose_worker_gate["BETA_WORKER_ENVIRONMENT"])
    if field is not None:
        if field == "environment":
            changed[field].pop("CANVAS_SYNC_PROCESSOR")
        elif field == "secrets":
            changed[field] = []
        else:
            changed[field] = "synthetic-secret-must-not-appear-in-diagnostics"
    compare = compose_worker_gate["assert_consumer_worker"]
    if field is None:
        compare(
            base,
            model,
            "synthetic",
            isolated=variant == "isolated",
            beta=variant == "beta",
        )
    else:
        with pytest.raises(
            AssertionError, match="preserve complete Python worker"
        ) as caught:
            compare(
                base,
                model,
                "synthetic",
                isolated=variant == "isolated",
                beta=variant == "beta",
            )
        assert "synthetic-secret" not in str(caught.value)
    assert base == pristine


@pytest.mark.parametrize("invalid", [False, True])
def test_beta_environment_list_is_semantically_compared_without_dropping_fields(
    compose_worker_gate, invalid
):
    base = _yaml("docker-compose.base.yml")
    model = deepcopy(base)
    environment = model["services"]["canvas-sync-worker"]["environment"]
    environment.update(compose_worker_gate["BETA_WORKER_ENVIRONMENT"])
    values = [f"{name}={value}" for name, value in environment.items()]
    if invalid:
        values.append("CANVAS_SYNC_PROCESSOR=unexpected-duplicate")
    model["services"]["canvas-sync-worker"]["environment"] = values
    if invalid:
        with pytest.raises(AssertionError):
            compose_worker_gate["assert_consumer_worker"](
                base, model, "beta", beta=True
            )
    else:
        compose_worker_gate["assert_consumer_worker"](base, model, "beta", beta=True)


def test_consumer_matrix_derives_all_conformance_switches_from_real_owner(
    compose_worker_gate,
):
    cases = compose_worker_gate["conformance_cases"]()
    assert len(cases) == len({case["name"] for case in cases}) == 8
    combinations = set()
    for case in cases:
        files = case["files"]
        assert files[0] == "docker-compose.base.yml"
        assert files[-1] == "docker-compose.profile.conformance.yml"
        assert "docker-compose.profile.oidf.yml" in files
        assert case["profiles"] == ["oidf"]
        released = "docker-compose.profile.ghcr.yml" in files
        assert ("docker-compose.profile.conformance-images.yml" in files) is released
        assert ("docker-compose.profile.local-build.yml" in files) is not released
        combinations.add(
            (
                released,
                "docker-compose.profile.oidf-haip.yml" in files,
                "docker-compose.profile.didcomm-authcrypt.yml" in files,
            )
        )
    assert len(combinations) == 8


def test_consumer_matrix_uses_catalog_groups_files_and_profiles_without_claiming_tunnel_worker_start(
    compose_worker_gate,
):
    catalog = DeploymentCatalog.load(ROOT)
    cases = {case["name"]: case for case in compose_worker_gate["catalog_cases"]()}
    required = {
        name
        for name, stack in catalog.stacks.items()
        if stack.get("compose_files")
        and "canvas-sync-worker" in catalog.running_services_for_stack(name)
    }
    assert set(cases) == required | {"selfhost-beta-tunnel"}
    for name, case in cases.items():
        assert case["files"] == catalog.stack(name)["compose_files"]
        assert case["profiles"] == catalog.stack(name)["compose_profiles"]
        assert case["worker_required"] is (name in required)
    assert cases["selfhost-beta-tunnel"]["worker_required"] is False
    assert cases["selfhost-beta-tunnel"]["profiles"] == ["beta-tunnel"]
    assert (
        "docker-compose.profile.canvas-real.yml"
        in cases["tunnel-beta-experiments"]["files"]
    )
    assert (
        "docker-compose.profile.canvas-sandbox.yml"
        in cases["tunnel-beta-experiments"]["files"]
    )
    assert (
        "docker-compose.profile.northstar-admissions.yml"
        in cases["tunnel-beta-d11"]["files"]
    )


def test_beta_tracked_matrix_reads_all_seven_release_source_layers(compose_worker_gate):
    assert compose_worker_gate["beta_release_source_files"]() == [
        "docker-compose.base.yml",
        "docker-compose.beta.yml",
        "docker-compose.profile.dev.yml",
        "docker-compose.profile.tunnel.yml",
        "docker-compose.profile.waltid.yml",
        "docker-compose.profile.canvas-real.yml",
        "docker-compose.profile.canvas-sandbox.yml",
    ]


@pytest.mark.parametrize(
    "extra",
    [
        '    $AdditionalComposeFile',
        '    "docker-compose.extra.yml"',
        '    (Join-Path $script:RepoRoot $AdditionalComposeFile)',
        '    (Join-Path $script:RepoRoot "docker-compose.$Profile.yml")',
        '    (Join-Path $script:RepoRoot "../docker-compose.extra.yml")',
        '    (Join-Path $script:RepoRoot "docker-compose.extra.yml"); Invoke-Extra',
        '    ,',
        '    (Join-Path $script:RepoRoot "docker-compose.extra.yml"),,',
    ],
)
def test_beta_source_reader_rejects_any_unparsed_array_entry(
    compose_worker_gate, monkeypatch, tmp_path, extra
):
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts/deploy-local-beta-release.ps1").write_text(
        '$script:ComposeFiles = @(\n'
        '    (Join-Path $script:RepoRoot "docker-compose.base.yml"),\n'
        '    (Join-Path $script:RepoRoot "docker-compose.beta.yml"),\n'
        + extra
        + '\n)\n',
        encoding="utf-8",
    )
    namespace = compose_worker_gate["beta_release_source_files"].__globals__
    monkeypatch.setitem(namespace, "ROOT", tmp_path)
    with pytest.raises(AssertionError, match="Unsupported beta Compose source entry"):
        compose_worker_gate["beta_release_source_files"]()


@pytest.mark.parametrize("trailing_comma", ["", ","])
def test_beta_source_reader_preserves_order_blank_lines_and_optional_trailing_comma(
    compose_worker_gate, monkeypatch, tmp_path, trailing_comma
):
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts/deploy-local-beta-release.ps1").write_text(
        '$script:ComposeFiles = @(\n\n'
        '    (Join-Path $script:RepoRoot "docker-compose.base.yml"),\n'
        '   \n'
        '    (Join-Path $script:RepoRoot "docker-compose.beta.yml"),\n'
        '    (Join-Path $script:RepoRoot "docker-compose.extra.yml")'
        + trailing_comma
        + '\n\n)\n',
        encoding="utf-8",
    )
    namespace = compose_worker_gate["beta_release_source_files"].__globals__
    monkeypatch.setitem(namespace, "ROOT", tmp_path)
    assert compose_worker_gate["beta_release_source_files"]() == [
        "docker-compose.base.yml",
        "docker-compose.beta.yml",
        "docker-compose.extra.yml",
    ]


@pytest.mark.parametrize(
    "changed",
    [None, "container_name", "ports", "network", "bridge", "volume", "missing_profile"],
)
def test_conformance_complete_worker_scope_and_resource_isolation(
    compose_worker_gate, changed
):
    project = compose_worker_gate["CONFORMANCE_PROJECT"]
    model = {
        "services": {
            "canvas-sync-worker": {},
            "oidf-tls-proxy": {"ports": [{"published": "8443"}]},
        },
        "networks": {
            "marty-network": {"name": f"{project}_marty-network"},
            "oidf-runner-network": {
                "name": "${MARTY_CONFORMANCE_PROJECT:?set MARTY_CONFORMANCE_PROJECT}_oidf-runner",
                "internal": True,
            },
        },
        "volumes": {"data": {"name": f"{project}_data"}},
    }
    if changed in ("container_name", "ports"):
        model["services"]["canvas-sync-worker"][changed] = "unexpected-global-resource"
    elif changed == "network":
        model["networks"]["marty-network"]["name"] = "unscoped-production-network"
    elif changed == "bridge":
        model["networks"]["oidf-runner-network"]["internal"] = False
    elif changed == "volume":
        model["volumes"]["data"]["name"] = "unscoped-production-volume"
    elif changed == "missing_profile":
        del model["services"]["oidf-tls-proxy"]
    if changed:
        with pytest.raises(AssertionError):
            compose_worker_gate["assert_conformance_isolation"](model)
    else:
        compose_worker_gate["assert_conformance_isolation"](model)


def test_renderer_preserves_explicit_profiles_and_project_without_resolving_secrets(
    compose_worker_gate, monkeypatch
):
    calls = []

    def execute(command, **options):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, "{}", "")

    monkeypatch.setattr(compose_worker_gate["subprocess"], "run", execute)
    compose_worker_gate["render"](
        "source.yml",
        profiles=["oidf", "beta-tunnel"],
        project="marty-conformance-worker-config",
    )
    [command] = calls
    assert command[:6] == [
        "docker",
        "compose",
        "--project-name",
        "marty-conformance-worker-config",
        "--env-file",
        os.devnull,
    ]
    assert command[6:12] == [
        "-f",
        "source.yml",
        "--profile",
        "oidf",
        "--profile",
        "beta-tunnel",
    ]
    assert command[12:] == [
        "config",
        "--no-interpolate",
        "--no-env-resolution",
        "--no-path-resolution",
        "--no-consistency",
        "--format",
        "json",
    ]


def test_default_run_retains_only_original_bundle_issuance_and_rust_owners(
    compose_worker_gate, monkeypatch
):
    calls = []
    namespace = compose_worker_gate["run"].__globals__
    monkeypatch.setitem(namespace, "render", lambda *args: {})
    for name in (
        "assert_worker_preserved",
        "assert_published_issuance_preserved",
        "assert_shared_rust_services",
        "assert_consumer_matrix",
    ):

        def record(*args, owner=name):
            calls.append(owner)
            return ["synthetic"]

        monkeypatch.setitem(namespace, name, record)
    compose_worker_gate["run"]()
    assert calls == [
        "assert_worker_preserved",
        "assert_published_issuance_preserved",
        "assert_shared_rust_services",
    ]


def test_explicit_consumer_suite_runs_all_fifteen_compositions_and_no_bundle_owner(
    compose_worker_gate, monkeypatch, capsys
):
    namespace = compose_worker_gate["run"].__globals__
    comparisons = []
    scopes = []
    renders = []

    def renderer(*files, **options):
        renders.append((files, options))
        return {"networks": {"marty-network": {"name": "elevenid-beta-network"}}}

    def unexpected(*args):
        pytest.fail("Consumer suite must not silently replace the older bundle owner")

    monkeypatch.setitem(namespace, "render", renderer)
    monkeypatch.setitem(namespace, "assert_base_worker_selection", lambda model: None)
    monkeypatch.setitem(
        namespace,
        "assert_consumer_worker",
        lambda base, model, name, **options: comparisons.append((name, options)),
    )
    monkeypatch.setitem(
        namespace, "assert_conformance_isolation", lambda model: scopes.append(model)
    )
    for name in (
        "assert_worker_preserved",
        "assert_published_issuance_preserved",
        "assert_shared_rust_services",
    ):
        monkeypatch.setitem(namespace, name, unexpected)
    compose_worker_gate["run"]("consumers", ["/owned/pinned-compose"])
    assert len(comparisons) == len({name for name, _ in comparisons}) == 15
    assert len(scopes) == 8
    assert sum(options.get("isolated", False) for _, options in comparisons) == 8
    assert sum(options.get("beta", False) for _, options in comparisons) == 2
    assert len(renders) == 21
    assert all(
        options["compose_command"] == ["/owned/pinned-compose"]
        for _, options in renders
    )
    assert "15 conformance/catalog/beta compositions" in capsys.readouterr().out


@pytest.mark.parametrize("prefix", ["docker compose", [], [""], [1]])
def test_renderer_rejects_shell_strings_and_invalid_argv_before_process_launch(
    compose_worker_gate, monkeypatch, prefix
):
    def unexpected(*args, **kwargs):
        pytest.fail("Invalid Compose argv must not launch a process")

    monkeypatch.setattr(compose_worker_gate["subprocess"], "run", unexpected)
    with pytest.raises(ValueError, match="argv sequence"):
        compose_worker_gate["render"]("synthetic.yml", compose_command=prefix)


@pytest.mark.parametrize(
    "arguments,expected",
    [
        ([], ("bundle", None)),
        (
            ["--suite", "consumers", "--compose-command", "/owned path/compose"],
            ("consumers", ["/owned path/compose"]),
        ),
    ],
)
def test_actual_cli_defaults_to_bundle_and_requires_explicit_consumer_selection(
    monkeypatch, arguments, expected
):
    import argparse

    source = ast.parse(
        (ROOT / "scripts/test_canvas_worker_compose_render.py").read_text(
            encoding="utf-8"
        )
    )
    [entrypoint] = [node for node in source.body if isinstance(node, ast.If)]
    calls = []
    monkeypatch.setattr(sys, "argv", ["renderer.py", *arguments])
    namespace = {
        "__name__": "__main__",
        "__doc__": "synthetic parser test",
        "argparse": argparse,
        "run": lambda *args: calls.append(args),
    }
    exec(
        compile(
            ast.Module(body=[entrypoint], type_ignores=[]),
            "<actual-compose-cli>",
            "exec",
        ),
        namespace,
    )
    assert calls == [expected]


def test_ci_keeps_old_bundle_gate_and_checks_pinned_modern_binary_before_explicit_consumer_suite():
    workflow = _yaml(".github/workflows/ci.yml")
    steps = workflow["jobs"]["test-rust-service-images"]["steps"]
    names = [step.get("name") for step in steps]
    bundle = names.index("Verify merged Canvas worker deployment configuration")
    consumers = names.index("Verify complete Canvas worker consumer configurations")
    assert (
        steps[bundle]["run"] == "python3 scripts/test_canvas_worker_compose_render.py"
    )
    assert bundle < consumers
    gate = steps[consumers]
    assert "if" not in gate and not gate.get("continue-on-error", False)
    commands = gate["run"]
    download = commands.index(
        "https://github.com/docker/compose/releases/download/v5.4.0/docker-compose-linux-x86_64"
    )
    checksum = commands.index(
        "837fd1d35bf6a494f41b5b5988269a7be79de337cf1a1a6ff0e45ab51bb4e9be"
    )
    verify = commands.index("sha256sum --check --strict")
    execute = commands.index("python3 scripts/test_canvas_worker_compose_render.py")
    assert download < checksum < verify < commands.index("chmod +x") < execute
    assert 'compose_renderer="$RUNNER_TEMP/compose-render-v5.4.0"' in commands
    assert '--suite consumers --compose-command "$compose_renderer"' in commands
    builds = [
        index
        for index, step in enumerate(steps)
        if step.get("uses", "").startswith("docker/build-push-action@")
    ]
    assert builds and consumers < min(builds)


def test_canvas_worker_is_required_by_production_deployment_catalogs() -> None:
    catalog = DeploymentCatalog.load(ROOT)

    for stack in ("selfhost-production", "kubernetes-production"):
        assert "canvas-sync-worker" in catalog.running_services_for_stack(stack)

    service = catalog.services["canvas-sync-worker"]
    assert service["compose_service"] == "canvas-sync-worker"
    assert service["k8s_deployment"] == "canvas-sync-worker"
    assert service["image_name"] == "issuance"
    assert service["group"] == "app"
    assert "canvas-sync-worker" in catalog.service_groups["app"]


def test_kubernetes_canvas_worker_configuration_includes_safe_defaults() -> None:
    config = _yaml("k8s/oracle/01-configmap.yaml")["data"]
    expected = {
        "CANVAS_PORTABLE_INTEGRATION_ENABLED",
        "CANVAS_PILOT_ORGANIZATION_IDS",
        "CANVAS_LEGACY_EVENT_INGEST_ENABLED",
        "CANVAS_LTI_TOOL_SIGNING_ORGANIZATION_ID",
        "CANVAS_LTI_TOOL_ISSUER_DID",
        "CANVAS_CREDENTIAL_ISSUER_PROFILE_IDS",
        "CANVAS_LTI_TOOL_ACTIVE_KID",
        "CANVAS_LTI_TOOL_PUBLIC_JWKS",
        "CANVAS_BINDING_READINESS_MAX_AGE_SECONDS",
        "CANVAS_ISSUANCE_EVIDENCE_MAX_AGE_SECONDS",
        "CANVAS_BACKGROUND_ROSTER_BATCH_SIZE",
        "CANVAS_BACKGROUND_ROSTER_MAX_SIZE",
        "CANVAS_SYNC_PROCESSOR",
        "CANVAS_SYNC_WORKER_BATCH_SIZE",
        "CANVAS_SYNC_WORKER_LEASE_SECONDS",
        "CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS",
        "CANVAS_SYNC_SCHEDULE_LIMIT",
        "CANVAS_OAUTH_REVOCATION_BATCH_SIZE",
        "CANVAS_SYNC_WORKER_POLL_SECONDS",
    }

    assert expected.issubset(config)
    assert config["CANVAS_BINDING_READINESS_MAX_AGE_SECONDS"] == "900"
    assert config["CANVAS_ISSUANCE_EVIDENCE_MAX_AGE_SECONDS"] == "900"
    assert config["CANVAS_BACKGROUND_ROSTER_BATCH_SIZE"] == "500"
    assert config["CANVAS_BACKGROUND_ROSTER_MAX_SIZE"] == "5000"
    assert config["CANVAS_SYNC_PROCESSOR"] == PROCESSOR
    assert config["CANVAS_SYNC_WORKER_BATCH_SIZE"] == "10"
    assert config["CANVAS_SYNC_WORKER_LEASE_SECONDS"] == "120"
    assert config["CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS"] == "600"
    assert config["CANVAS_SYNC_SCHEDULE_LIMIT"] == "100"
    assert config["CANVAS_OAUTH_REVOCATION_BATCH_SIZE"] == "25"
    assert config["CANVAS_SYNC_WORKER_POLL_SECONDS"] == "5"


def test_production_preflight_requires_a_configured_canvas_worker_processor() -> None:
    namespace = runpy.run_path(str(ROOT / "scripts/check-selfhost-production.py"))
    validate = namespace["validate_selfhost_canvas_public_config"]
    check_error = namespace["CheckError"]
    enabled = {
        "CANVAS_PORTABLE_INTEGRATION_ENABLED": "true",
        "CANVAS_LTI_EXPERIENCE_BASE_URL": "https://marty.example.com",
        "CANVAS_PILOT_ORGANIZATION_IDS": "org-pilot",
        "CANVAS_LEGACY_EVENT_INGEST_ENABLED": "false",
        "CANVAS_LTI_TOOL_SIGNING_ORGANIZATION_ID": "system-tools",
        "CANVAS_LTI_TOOL_ISSUER_DID": "did:web:marty.example.com:orgs:system-tools",
        "CANVAS_CREDENTIAL_ISSUER_PROFILE_IDS": "ip-marty-vc-jwt-issuer",
        "CANVAS_LTI_TOOL_ACTIVE_KID": "did:web:marty.example.com:orgs:system-tools#lti-tool-rs256",
        "CANVAS_LTI_TOOL_PUBLIC_JWKS": (
            '{"keys":[{"kty":"RSA","alg":"RS256","use":"sig",'
            '"kid":"did:web:marty.example.com:orgs:system-tools#lti-tool-rs256",'
            '"n":"public-modulus","e":"AQAB"}]}'
        ),
        "CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS": "600",
    }

    with pytest.raises(check_error, match="CANVAS_SYNC_PROCESSOR"):
        validate(enabled)

    without_issuer_inventory = dict(enabled)
    without_issuer_inventory.pop("CANVAS_CREDENTIAL_ISSUER_PROFILE_IDS")
    with pytest.raises(check_error, match="must inventory"):
        validate({**without_issuer_inventory, "CANVAS_SYNC_PROCESSOR": PROCESSOR})

    result = validate({**enabled, "CANVAS_SYNC_PROCESSOR": PROCESSOR})
    assert "CANVAS_SYNC_PROCESSOR" in result
    assert "CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS" in result

    with pytest.raises(check_error, match="CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS"):
        validate(
            {
                **enabled,
                "CANVAS_SYNC_PROCESSOR": PROCESSOR,
                "CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS": "601",
            }
        )

    private_jwks = enabled["CANVAS_LTI_TOOL_PUBLIC_JWKS"].replace(
        '"e":"AQAB"',
        '"e":"AQAB","d":"private-material"',
    )
    with pytest.raises(check_error, match="private RSA parameters"):
        validate(
            {
                **enabled,
                "CANVAS_SYNC_PROCESSOR": PROCESSOR,
                "CANVAS_LTI_TOOL_PUBLIC_JWKS": private_jwks,
            }
        )

    with pytest.raises(check_error, match="must be a DID"):
        validate(
            {
                **enabled,
                "CANVAS_SYNC_PROCESSOR": PROCESSOR,
                "CANVAS_LTI_TOOL_ISSUER_DID": "kms://canvas-lti-key",
            }
        )

    with pytest.raises(check_error, match="verification method"):
        validate(
            {
                **enabled,
                "CANVAS_SYNC_PROCESSOR": PROCESSOR,
                "CANVAS_LTI_TOOL_ACTIVE_KID": "did:web:other.example#key-1",
            }
        )

    configured = validate(
        {
            **enabled,
            "CANVAS_SYNC_PROCESSOR": PROCESSOR,
        }
    )
    assert "CANVAS_LTI_TOOL_ISSUER_DID" in configured
