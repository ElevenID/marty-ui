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
    assert "elevenid-beta-copy-" in script
    assert "migration-rehearsal.log" in script
    assert "--verify-only" in script
    assert script.count('MARTY_KMS_BOOTSTRAP_ENABLED=true') == 2
    assert '"REDIS_URL=redis://:${encodedRedisPassword}@redis:6379"' in script
    assert '"BAO_ADDR=http://openbao:8200"' in script
    assert '"BAO_TOKEN"' in script
    assert 'CANVAS_LTI_TOOL_ISSUER_DID = $canvasLtiIssuerDid' in script
    assert '"did:web:${betaHost}:orgs:marty"' in script
    assert "CANVAS_LTI_TOOL_PUBLIC_JWKS" not in script
    assert "CANVAS_CREDENTIAL_ISSUER_KEY_REFERENCES" not in script
    assert "CANVAS_SELF_MANAGED_ORIGIN_ALLOWLIST" in script
    assert '$env:CANVAS_OAUTH_COMPLETION_REDIRECT_URL = "$BetaOrigin/console/org/deploy/canvas"' in script
    assert "$rehearsalKmsEnabled" not in script
    assert "$kmsBootstrapEnabled" not in script
    assert '"elevenid-beta-copy-openbao-' in script
    assert '"elevenid-beta-copy-redis-' in script
    assert "$rehearsalContainers = @($copyContainer, $copyOpenBaoContainer, $copyRedisContainer)" in script
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
    assert '$_ -notin @("issuance", "canvas-sync-worker")' in script
    assert "$script:ApplicationBuildServices" in script
    assert '$env:CANVAS_ALLOW_PRIVATE_BASE_URLS = "false"' in script
    assert '$env:CANVAS_ALLOW_HTTP_LOCALHOST_BASE_URLS = "false"' in script
    assert '$script:InfrastructureWriterServices = @("keycloak")' in script
    assert "Start-ContainersBestEffort" in script
    assert "if ($LASTEXITCODE -ne 0)" in script
    assert script.count('"--verify-manifest", $sourceManifestPath') == 2
    assert 'Write-Step "Verify public UI image homepage content"' in script
    assert 'docker run --rm --entrypoint cat $uiImage /usr/share/nginx/html/index.html' in script
    assert '$uiRootText -notmatch "ElevenID"' in script
    assert '$uiRootText -match "Welcome to nginx"' in script
    post_build_verify = script.index('Write-Step "Reverify coordinated source after image builds"')
    final_build = script.index('Write-Step "Build marker-bearing public UI image"')
    ui_content_verify = script.index('Write-Step "Verify public UI image homepage content"')
    maintenance = script.index('Write-Step "Enter maintenance window and apply live migration"')
    assert final_build < ui_content_verify < post_build_verify < maintenance


def test_beta_runner_reconciles_infrastructure_writer_configuration() -> None:
    script = text("scripts/deploy-local-beta-release.ps1")

    step = 'Write-Step "Recreate infrastructure writers from release configuration"'
    recreate = '@("up", "--detach", "--no-build", "--no-deps", "--force-recreate")'
    assert step in script
    assert recreate in script
    assert "+ $script:InfrastructureWriterServices" in script
    assert "Wait-ForServiceHealth $script:InfrastructureWriterServices" in script
    assert '@("start", $keycloakContainer)' not in script
    assert script.index(step) < script.index('Write-Step "Recreate application containers')


def test_release_ui_compose_uses_image_without_source_mounts() -> None:
    compose = text("docker-compose.ui-release.yml")

    assert "MARTY_UI_RELEASE_IMAGE" in compose
    assert "./ui/dist" not in compose
    assert "elevenid-beta-ui" in compose
    assert "${MARTY_NETWORK_NAME:-elevenid-beta-network}" in compose
    assert "container_name:" not in compose


def test_plan_only_exits_before_artifact_writes() -> None:
    script = text("scripts/deploy-local-beta-release.ps1")

    assert "$PSNativeCommandUseErrorActionPreference = $false" in script
    assert script.count("$LASTEXITCODE -ne 0") >= 9
    assert "function Invoke-DockerLogged" in script
    assert "function Invoke-ComposeLogged" in script
    assert '$ErrorActionPreference = "Continue"' in script
    assert 'throw "$FailureMessage (exit code $nativeExitCode)"' in script
    plan_exit = script.index("if ($PlanOnly)")
    write_start = script.index("New-Item -ItemType Directory", plan_exit)

    assert script.index("exit 0", plan_exit) < write_start


def test_beta_runner_resolves_default_env_paths_after_script_root_is_available() -> None:
    deploy = text("scripts/deploy-local-beta-release.ps1")
    restore = text("scripts/restore-local-beta-release.ps1")

    for script in (deploy, restore):
        param_block = script.split(")\n\nSet-StrictMode", 1)[0]
        assert "Split-Path -Parent $PSScriptRoot" not in param_block
        assert "[string]::IsNullOrWhiteSpace($TunnelEnvFile)" in script
        assert "[string]::IsNullOrWhiteSpace($GeneratedEnvFile)" in script
        assert '".env.tunnel.beta.local"' in script
        assert '".env.beta.generated.local"' in script


def test_beta_runner_builds_application_images_serially_before_maintenance() -> None:
    script = text("scripts/deploy-local-beta-release.ps1")

    build_step = script.index('Write-Step "Build marker-bearing application images"')
    loop = script.index("foreach ($service in $script:ApplicationBuildServices)", build_step)
    invoke = script.index(
        "Invoke-Compose -Arguments ($applicationBuildArguments + @($service))", loop
    )
    ui_build = script.index('Write-Step "Build marker-bearing public UI image"')
    maintenance = script.index('Write-Step "Enter maintenance window and apply live migration"')

    assert build_step < loop < invoke < ui_build < maintenance
    assert "($applicationBuildArguments + $script:ApplicationBuildServices)" not in script


def test_service_specific_image_metadata_cannot_fan_out_shared_runtime_layers() -> None:
    dockerfile = text("services/Dockerfile")

    assert dockerfile.count("ARG SERVICE_NAME") == 1
    service_boundary = dockerfile.index("ARG SERVICE_NAME")
    assert dockerfile.index("RUN chmod +x /app/services/entrypoint.sh") < service_boundary
    assert dockerfile.index("ENV SERVICE_NAME=${SERVICE_NAME}", service_boundary) > service_boundary

    service_specific_tail = dockerfile[service_boundary:].splitlines()
    filesystem_instructions = ("RUN ", "COPY ", "ADD ")
    assert not any(
        line.startswith(filesystem_instructions) for line in service_specific_tail
    ), "service-specific build arguments must follow every shared filesystem layer"


def test_direct_ui_proxy_uses_canonical_gateway() -> None:
    for config_path in ("ui/nginx.prod.conf", "ui/nginx.dev.conf"):
        config = text(config_path)

        assert "oid4vc-api" not in config
        assert "resolver 127.0.0.11" in config
        assert "set $gateway_upstream gateway:8000;" in config
        assert "proxy_pass http://$gateway_upstream" in config
        assert "proxy_pass http://gateway:8000" not in config


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

    assert "function Get-ComposeContainerId" in script
    assert '"label=com.docker.compose.project=$script:BetaUiProject"' in script
    assert '"ps", "--all", "--quiet", $Service' in script
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
    assert '$project = "elevenid-beta"' in script
    assert 'com.docker.compose.project' in script
    assert 'throw "Refusing container outside $project"' in script
    assert 'phase -ne "maintenance_quiesced"' in script
    assert "elevenid-beta_redis_data" in script
    assert '"elevenid-beta-ui"' in script
    assert "self-host production was not addressed" in script
    assert "Wait-ForServiceHealth" in script
    assert '$gatewayRecord[0].runtime_marker_environment.PSObject.Properties[$name]' in script
    assert '"canvas-sync-worker" -notin @($preDeploy.service)' in script
    assert 'Invoke-Checked docker @("rm", "--force", $worker)' in script
    assert "$preDeployDocument | ForEach-Object { $_ }" in script
    assert "$preDeploy = @(Get-Content" not in script
    assert 'PSObject.Properties["rollback_environment"]' in script
    assert '"postgresql", "postgresql+asyncpg"' in script
    assert '"GRPC_INSECURE_ALLOWED", "ALLOW_PLAINTEXT_GRPC"' in script


def test_beta_inventory_records_only_non_secret_rollback_connection_metadata() -> None:
    deploy = text("scripts/deploy-local-beta-release.ps1")

    assert 'rollback_environment = $rollbackEnvironment' in deploy
    assert '$rollbackEnvironment["DATABASE_DRIVER"] = $Matches[1]' in deploy
    assert 'rollbackEnvironment[$parts[0]] = $parts[1]' in deploy
    assert 'rollbackEnvironment["DATABASE_URL"]' not in deploy


def test_beta_compose_uses_the_generated_database_password_without_source_overlays() -> None:
    base = text("docker-compose.base.yml")
    tunnel = text("docker-compose.profile.tunnel.yml")

    assert "postgresql+asyncpg://marty:marty_dev_password" not in base
    assert base.count("postgresql+asyncpg://marty:${MARTY_DB_PASSWORD:-marty_dev_password}") == 14
    assert "./services/gateway/routes/signing_keys.py" not in tunnel


def test_beta_runner_targets_only_the_beta_projects_and_rust_services() -> None:
    deploy = text("scripts/deploy-local-beta-release.ps1")
    restore = text("scripts/restore-local-beta-release.ps1")
    beta = text("docker-compose.beta.yml")
    base = text("docker-compose.base.yml")

    assert '$script:BetaProject = "elevenid-beta"' in deploy
    assert '$script:BetaUiProject = "elevenid-beta-ui"' in deploy
    assert '$script:BetaNetwork = "elevenid-beta-network"' in deploy
    assert "docker-compose.beta.yml" in deploy
    assert "event-stream-rust.yml" not in deploy
    assert "event-stream-rust.yml" not in restore
    assert "dockerfile: rust/services/event-stream/Dockerfile" not in base
    assert "EVENT_STREAM_SERVICE_PORT=8015" in base
    assert "revocation-profile-rust.yml" not in deploy
    assert "revocation-profile-rust.yml" not in restore
    application_services = deploy.split("$script:ApplicationServices = @(", 1)[1].split(")", 1)[0]
    for rust_service in (
        "event-stream",
        "notification",
        "revocation-profile",
        "signing-keys",
    ):
        assert f'"{rust_service}"' in application_services
    assert "SERVICE_NAME: signing-keys" in base
    assert "ENVIRONMENT: beta" in beta
    assert "GRPC_SERVICE_TOKEN:?GRPC_SERVICE_TOKEN must be set" in beta
    assert "GRPC_SERVICE_TOKEN:-dev-grpc-service-token-change-before-production" in base
    assert "PUBLIC_DOMAIN:?PUBLIC_DOMAIN must be set for beta" in beta
    assert beta.count("<<: *beta-grpc-service-auth") == 17
    assert "-TunnelEnvFile" in deploy and "-GeneratedEnvFile" in deploy
    assert 'mip_version -ne "0.5.0"' in deploy
    assert 'mip_version = "0.5.0"' in deploy
    assert "name: elevenid-beta" in beta
    assert "name: elevenid-beta-network" in beta
    assert "container_name:" not in base
    assert "${MARTY_NETWORK_NAME:-marty-infra-network}" in base
    assert '$env:MARTY_ISSUANCE_IMAGE = "$($martyIssuance.uri)@$($martyIssuance.digest)"' in restore
    assert 'com.docker.compose.service=docs' in restore


def test_beta_rust_cutover_requires_a_persistent_shared_service_token() -> None:
    deploy = text("scripts/deploy-local-beta-release.ps1")
    initializer = text("scripts/ensure-beta-grpc-service-token.ps1")

    assert 'Get-DotEnvValue -Path $GeneratedEnvFile -Name "GRPC_SERVICE_TOKEN"' in deploy
    assert "GRPC_SERVICE_TOKEN must be a non-placeholder value" in deploy
    assert "RandomNumberGenerator" in initializer
    assert "its value was not displayed" in initializer


def test_beta_flow_cutover_requires_distinct_workload_identity() -> None:
    deploy = text("scripts/deploy-local-beta-release.ps1")
    initializer = text("scripts/ensure-beta-workload-identity.ps1")
    beta = text("docker-compose.beta.yml")

    assert '"FLOW_APPLICATION_EVENT_HMAC_KEY"' in deploy
    assert '"FLOW_WEBHOOK_SECRET"' in deploy
    assert 'Invoke-Checked -FilePath openssl -Arguments @("verify"' in deploy
    assert "spiffe://marty.internal/service/auth" in initializer
    assert "spiffe://marty.internal/service/applicant" in initializer
    assert "spiffe://marty.internal/service/flow" in initializer
    assert "private keys and certificate contents were not displayed" in initializer
    assert "GRPC_WORKLOAD_TLS_SERVER_CERT: /run/secrets/flow_workload_server_cert" in beta
    assert "GRPC_WORKLOAD_TLS_CLIENT_CERT: /run/secrets/auth_workload_client_cert" in beta
    assert "GRPC_WORKLOAD_TLS_CLIENT_CERT: /run/secrets/applicant_workload_client_cert" in beta
    assert "GRPC_WORKLOAD_TLS_SERVER_CERT: /run/secrets/pp_workload_server_cert" in beta


def test_beta_runner_resolves_all_required_immutable_compose_inputs() -> None:
    script = text("scripts/deploy-local-beta-release.ps1")

    assert '$env:MARTY_COMMON_URI = $martyCommon.Uri' in script
    assert '$env:MARTY_COMMON_DIGEST = $martyCommon.Digest' in script
    assert '$env:MARTY_RS_URI = $martyRs.Uri' in script
    assert '$env:MARTY_RS_DIGEST = $martyRs.Digest' in script
    assert '$env:MARTY_VERIFICATION_URI = $martyVerification.Uri' in script
    assert '$env:MARTY_VERIFICATION_DIGEST = $martyVerification.Digest' in script
    assert '$env:MARTY_ISO18013_URI = $martyIso18013.Uri' in script
    assert '$env:MARTY_ISO18013_DIGEST = $martyIso18013.Digest' in script
    assert '$env:MARTY_ISSUANCE_IMAGE = "$($martyIssuance.Uri)@$($martyIssuance.Digest)"' in script
    assert 'com.docker.compose.service=docs' in script
    assert 'Existing beta docs image is not immutable' in script


def test_beta_runner_authenticates_backups_and_uses_the_packaged_migration_path() -> None:
    script = text("scripts/deploy-local-beta-release.ps1")

    assert 'Get-DotEnvValue -Path $GeneratedEnvFile -Name "REDIS_PASSWORD"' in script
    assert '$encodedRedisPassword = [Uri]::EscapeDataString($redisPassword)' in script
    assert 'docker exec --env "REDISCLI_AUTH=$RedisPassword" $redis redis-cli SAVE' in script
    assert 'throw "Authenticated beta Redis snapshot failed"' in script
    assert '"redis-server", "--requirepass", $copyRedisPassword' in script
    assert '$redisPing = docker exec $copyRedisContainer redis-cli --no-auth-warning -a $copyRedisPassword ping' in script
    assert '$LASTEXITCODE -eq 0 -and $redisPing -eq "PONG"' in script
    assert '$encodedCopyRedisPassword = [Uri]::EscapeDataString($copyRedisPassword)' in script
    assert '"REDIS_URL=redis://:${encodedCopyRedisPassword}@${copyRedisContainer}:6379"' in script
    assert '"REDIS_URL=redis://:${encodedRedisPassword}@redis:6379"' in script
    assert '"REDIS_URL=redis://redis:6379"' not in script
    assert script.count('-RedisPassword $redisPassword') == 2
    assert script.count('"/app/services/run_all_migrations.py"') == 3
    assert '"/app/run_all_migrations.py"' not in script
    assert script.count('"issuance-migrations"') == 4
    assert "issuance-migration-rehearsal.log" in script
    assert "issuance-migration-rehearsal-verify.log" in script
    assert "issuance-migration-live.log" in script
    assert "issuance-migration-live-verify.log" in script
    assert script.index("issuance-migration-rehearsal.log") < script.index(
        'Write-Step "Build marker-bearing application images"'
    )
    assert script.index("migration-live.log") < script.index(
        "issuance-migration-live.log"
    )


def test_beta_runner_always_isolates_required_openbao_migration_state() -> None:
    script = text("scripts/deploy-local-beta-release.ps1")

    assert 'Get-DotEnvValue -Path $GeneratedEnvFile -Name "BAO_DEV_ROOT_TOKEN"' in script
    assert (
        "$rehearsalContainers = "
        "@($copyContainer, $copyOpenBaoContainer, $copyRedisContainer)"
    ) in script
    assert '"BAO_DEV_ROOT_TOKEN_ID=$copyBaoToken"' in script
    assert '"BAO_ADDR=http://${copyOpenBaoContainer}:8200"' in script
    assert '"BAO_TOKEN=$copyBaoToken"' in script
    assert '$env:BAO_TOKEN = $baoDevRootToken' in script
    assert '"BAO_ADDR=http://openbao:8200"' in script
    assert script.count('"--env", "BAO_TOKEN"') == 1
    assert '"dev-only-token"' not in script


def test_beta_runner_preserves_the_pinned_external_issuance_image_role() -> None:
    script = text("scripts/deploy-local-beta-release.ps1")

    assert '$service -in @("issuance", "canvas-sync-worker")' in script
    assert "image: ${MARTY_ISSUANCE_IMAGE}" in script
    assert 'Invoke-Checked -FilePath docker -Arguments @("pull", $env:MARTY_ISSUANCE_IMAGE)' in script
    assert '$imageRef = if ($service -in @("issuance", "canvas-sync-worker"))' in script
    assert '"elevenid-local/issuance:${releaseVersion}"' not in script


def test_beta_compose_requires_credential_login_issuer_identity() -> None:
    base_compose = text("docker-compose.base.yml")
    beta_compose = text("docker-compose.beta.yml")

    assert "CREDENTIAL_LOGIN_ORGANIZATION_ID:" in base_compose
    assert "CREDENTIAL_LOGIN_ISSUER_DID:" in base_compose
    assert (
        "CREDENTIAL_LOGIN_ORGANIZATION_ID: ${MARTY_ORG_ID:?MARTY_ORG_ID must be set for beta}"
        in beta_compose
    )
    assert (
        "CREDENTIAL_LOGIN_ISSUER_DID: "
        "${MARTY_ISSUER_DID:?MARTY_ISSUER_DID must be set for beta}"
        in beta_compose
    )
