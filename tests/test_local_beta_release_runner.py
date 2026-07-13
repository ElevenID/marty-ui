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


def test_release_ui_compose_uses_image_without_source_mounts() -> None:
    compose = text("docker-compose.ui-release.yml")

    assert "MARTY_UI_RELEASE_IMAGE" in compose
    assert "./ui/dist" not in compose
    assert "marty-infra-network" in compose


def test_plan_only_exits_before_artifact_writes() -> None:
    script = text("scripts/deploy-local-beta-release.ps1")

    plan_exit = script.index("if ($PlanOnly)")
    write_start = script.index("New-Item -ItemType Directory", plan_exit)

    assert script.index("exit 0", plan_exit) < write_start


def test_direct_ui_proxy_uses_canonical_gateway() -> None:
    for config_path in ("ui/nginx.prod.conf", "ui/nginx.dev.conf"):
        config = text(config_path)

        assert "oid4vc-api" not in config
        assert "proxy_pass http://gateway:8000" in config
