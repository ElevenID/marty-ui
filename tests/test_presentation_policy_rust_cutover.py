import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_public_service_image_executes_the_native_presentation_policy_binary() -> None:
    dockerfile = text("services/Dockerfile")
    entrypoint = text("services/entrypoint.sh")
    assert (
        "-p marty-presentation-policy --bin marty-presentation-policy"
    ) in dockerfile
    assert (
        "/build/rust/target/release/marty-presentation-policy "
        "/usr/local/bin/marty-presentation-policy"
    ) in dockerfile
    assert (
        "-p marty-presentation-policy --bin marty-presentation-policy "
        "--bin marty-verifier-positive-gate"
    ) in dockerfile
    assert (
        "/build/rust/target/release/marty-verifier-positive-gate "
        "/usr/local/bin/marty-verifier-positive-gate"
    ) in dockerfile
    assert 'if [ "$MODULE_NAME" = "presentation_policy" ]; then' in entrypoint
    assert "exec /usr/local/bin/marty-presentation-policy" in entrypoint


def test_ci_builds_the_dedicated_native_image_target() -> None:
    dockerfile = text("rust/services/Dockerfile.ci")
    workflow = text(".github/workflows/ci.yml")
    assert "FROM runtime AS presentation_policy" in dockerfile
    assert "target: presentation_policy" in workflow
    assert "tags: marty-presentation-policy:ci" in workflow


def test_only_the_native_presentation_policy_runtime_remains() -> None:
    behavior = json.loads(text("contracts/presentation-policy-rust-cutover.json"))

    assert (ROOT / behavior["runtime_owner"]).is_dir()
    assert (ROOT / behavior["migration_owner"]).is_file()
    assert (ROOT / behavior["catalog_owner"]).is_file()
    assert (ROOT / behavior["surface_contract"]).is_file()
    assert (ROOT / behavior["migration_history_contract"]).is_file()
    assert not list((ROOT / behavior["python_runtime_removed"]).rglob("*.*"))
    assert behavior["python_runtime_fallback"] is False


def test_python_migration_runner_does_not_import_deleted_presentation_policy() -> None:
    migration_runner = text("services/run_all_migrations.py")

    assert '"name": "presentation_policy"' not in migration_runner
    assert '"module": "presentation_policy.infrastructure.models"' not in migration_runner


def test_deleted_python_service_cannot_reenter_ownership_inventory() -> None:
    ownership = json.loads(text("docs/rust-migration-ownership.json"))
    capability = next(
        item
        for item in ownership["capabilities"]
        if item["id"] == "presentation-policy-service"
    )

    assert capability["status"] == "native-active"
    assert capability["canonical"]["paths"] == ["rust/services/presentation-policy"]
    assert capability["legacy"] == []
