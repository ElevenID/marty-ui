from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_local_release_runner_is_backup_and_rehearsal_gated() -> None:
    script = text("scripts/deploy-local-beta-release.ps1")

    assert "source_kind -ne \"local-worktree-snapshot\"" in script
    assert "promotion_eligible -ne $false" in script
    assert '"--verify-manifest", $sourceManifestPath' in script
    assert "pg_dump -U postgres -Fc -d marty" in script
    assert "applicant_store.json" in script
    assert "redis-dump.rdb" in script
    assert "openbao-data.tar.gz" in script
    assert "marty-beta-copy-" in script
    assert "migration-rehearsal.log" in script
    assert "--verify-only" in script
    assert 'MARTY_KMS_BOOTSTRAP_ENABLED=$kmsBootstrapEnabled' in script
    assert '"REDIS_URL=redis://redis:6379"' in script
    assert '"BAO_ADDR=http://openbao:8200"' in script
    assert '"BAO_TOKEN"' in script
    assert "export_canvas_lti_public_jwks.py" in script
    assert "CANVAS_LTI_TOOL_PUBLIC_JWKS" in script
    assert "CANVAS_CREDENTIAL_ISSUER_KEY_REFERENCES" in script
    assert "CANVAS_SELF_MANAGED_ORIGIN_ALLOWLIST" in script
    assert '$env:CANVAS_OAUTH_COMPLETION_REDIRECT_URL = "$BetaOrigin/console/org/deploy/canvas"' in script
    assert 'MARTY_KMS_BOOTSTRAP_ENABLED=$rehearsalKmsEnabled' in script
    assert '"marty-beta-copy-openbao-' in script
    assert '"marty-beta-copy-redis-' in script
    assert '-Phase "maintenance_quiesced"' in script
    assert '-WritersStopped $true' in script
    assert "restore-local-beta-release.ps1" in script


def test_local_release_runner_preserves_maintenance_and_provenance_boundaries() -> None:
    script = text("scripts/deploy-local-beta-release.ps1")

    assert 'Invoke-Checked -FilePath docker -Arguments (@("stop")' in script
    assert 'MARTY_MIGRATION_PROFILE=beta' in script
    assert 'MARTY_RELEASE_VERSION=$releaseVersion' in script
    assert 'MARTY_UI_SHA=$sourceId' in script
    assert '"NGINX_CONFIG=nginx.spa.conf"' in script
    assert "marty-ui-release.json" in script
    assert "/.well-known/marty-release" in script
    assert 'promotion_eligible = $false' in script
    assert 'release_ready = $false' in script
    assert '"canvas-sync-worker"' in script
    assert '"marty-canvas-sync-worker"' in script
    assert '$service -eq "canvas-sync-worker"' in script
    assert '{ "issuance" } else { $service }' in script
    assert "$script:ApplicationBuildServices" in script
    assert '$env:CANVAS_ALLOW_PRIVATE_BASE_URLS = "false"' in script
    assert '$env:CANVAS_ALLOW_HTTP_LOCALHOST_BASE_URLS = "false"' in script
    assert '$script:InfrastructureWriterContainers = @("marty-keycloak")' in script
    assert "Start-ContainersBestEffort" in script
    assert "if ($LASTEXITCODE -ne 0)" in script
    assert script.count('"--verify-manifest", $sourceManifestPath') == 2
    post_build_verify = script.index('Write-Step "Reverify coordinated source after image builds"')
    final_build = script.index('Write-Step "Build marker-bearing public UI image"')
    maintenance = script.index('Write-Step "Enter maintenance window and apply live migration"')
    assert final_build < post_build_verify < maintenance


def test_release_ui_compose_uses_image_without_source_mounts() -> None:
    compose = text("docker-compose.ui-release.yml")

    assert "MARTY_UI_RELEASE_IMAGE" in compose
    assert "./ui/dist" not in compose
    assert "marty-infra-network" in compose


def test_plan_only_exits_before_artifact_writes() -> None:
    script = text("scripts/deploy-local-beta-release.ps1")

    assert "$PSNativeCommandUseErrorActionPreference = $false" in script
    assert script.count("$LASTEXITCODE -ne 0") >= 9
    assert "function Invoke-DockerLogged" in script
    assert '$ErrorActionPreference = "Continue"' in script
    assert 'throw "$FailureMessage (exit code $nativeExitCode)"' in script
    plan_exit = script.index("if ($PlanOnly)")
    write_start = script.index("New-Item -ItemType Directory", plan_exit)

    assert script.index("exit 0", plan_exit) < write_start


def test_direct_ui_proxy_uses_canonical_gateway() -> None:
    for config_path in ("ui/nginx.prod.conf", "ui/nginx.dev.conf"):
        config = text(config_path)

        assert "oid4vc-api" not in config
        assert "proxy_pass http://gateway:8000" in config


def test_canvas_beta_wrapper_enables_only_the_disposable_portable_target() -> None:
    script = text("scripts/deploy-canvas-oss-beta.ps1")

    assert '-BetaOrigin "https://beta.elevenidllc.com"' in script
    assert "-EnablePortableCanvas" in script
    assert '-CanvasOrigin "https://canvas-test.elevenidllc.com"' in script
    assert '-PilotOrganizationId "00000000-0000-0000-0000-000000000001"' in script
    assert "selfhost_production_touched" in script
    assert '"America/Denver", "Mountain Standard Time"' in script
    assert "$denverNow.Hour -lt 2 -or $denverNow.Hour -ge 6" in script
    assert "-not $AllowOutsideMaintenanceWindow" in script
    assert "maintenance_window_override = [bool]$AllowOutsideMaintenanceWindow" in script
    assert "Beta deploy AuditPath must stay under ArtifactDir" in script
    assert 'label=com.docker.compose.project=marty-selfhost-prod' in script
    assert 'ConvertFrom-Json -InputObject ($json -join "`n")' in script
    assert "$records = foreach ($container in $containers)" in script
    assert "return @($records | Sort-Object container)" in script
    for field in ("container_id", "image_id", "started_at", "running"):
        assert field in script
    assert "Compare-SelfhostProductionInvariant" in script


def test_beta_inventory_tolerates_services_added_by_the_release() -> None:
    script = text("scripts/deploy-local-beta-release.ps1")

    assert "$existingContainers = @(& docker ps -a --format '{{.Names}}')" in script
    assert "if ($container -notin $existingContainers)" in script
    assert 'ConvertFrom-Json -InputObject ($json -join "`n")' in script
    assert 'throw "Could not inspect Docker container: $container"' in script


def test_canvas_dev_profiles_are_safe_to_override_for_portable_beta() -> None:
    for profile in (
        "docker-compose.profile.canvas-real.yml",
        "docker-compose.profile.canvas-sandbox.yml",
    ):
        compose = text(profile)
        assert "CANVAS_ALLOW_PRIVATE_BASE_URLS: ${CANVAS_ALLOW_PRIVATE_BASE_URLS:-true}" in compose
        assert "CANVAS_ALLOW_HTTP_LOCALHOST_BASE_URLS: ${CANVAS_ALLOW_HTTP_LOCALHOST_BASE_URLS:-true}" in compose


def test_beta_restore_is_explicit_and_project_scoped() -> None:
    script = text("scripts/restore-local-beta-release.ps1")

    assert "-ConfirmBetaRestore is required" in script
    assert "if ($Container -notin $existingContainers) { return $false }" in script
    assert 'ConvertFrom-Json -InputObject ($json -join "`n")' in script
    assert '$workerExists -contains "marty-canvas-sync-worker"' in script
    assert "$gatewayRecord.runtime_marker_environment.PSObject.Properties[$name]" in script
    assert "foreach ($record in $preDeployDocument)" in script
    assert 'phase -ne "maintenance_quiesced"' in script
    assert "marty-ui_redis_data" in script
    assert 'ExpectedProject' in script
    assert '"marty-ui-prod"' in script
    assert "marty-selfhost-prod was not addressed" in script
