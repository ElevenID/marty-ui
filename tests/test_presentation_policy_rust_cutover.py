from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_public_service_image_executes_the_native_presentation_policy_binary() -> None:
    dockerfile = text("services/Dockerfile")
    entrypoint = text("services/entrypoint.sh")
    assert (
        "cargo build --locked --release -p marty-presentation-policy "
        "--bin marty-presentation-policy"
    ) in dockerfile
    assert (
        "/build/rust/target/release/marty-presentation-policy "
        "/usr/local/bin/marty-presentation-policy"
    ) in dockerfile
    assert 'if [ "$MODULE_NAME" = "presentation_policy" ]; then' in entrypoint
    assert "exec /usr/local/bin/marty-presentation-policy" in entrypoint


def test_ci_builds_the_dedicated_native_image_target() -> None:
    dockerfile = text("rust/services/Dockerfile.ci")
    workflow = text(".github/workflows/ci.yml")
    assert "FROM runtime AS presentation_policy" in dockerfile
    assert "target: presentation_policy" in workflow
    assert "tags: marty-presentation-policy:ci" in workflow
