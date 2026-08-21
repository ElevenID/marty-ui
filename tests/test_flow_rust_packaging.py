from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def text(path: str) -> str:
    return (REPO_ROOT / path).read_text(encoding="utf-8")


def test_shared_service_image_contains_native_flow_binary() -> None:
    dockerfile = text("services/Dockerfile")
    assert "cargo build --locked --release -p marty-flow --bin marty-flow" in dockerfile
    assert (
        "COPY --from=rust-service-builder "
        "/build/rust/target/release/marty-flow /usr/local/bin/marty-flow"
    ) in dockerfile


def test_production_equivalent_ci_image_runs_only_native_flow() -> None:
    dockerfile = text("rust/services/Dockerfile.ci")
    target = dockerfile.split("FROM runtime AS flow", maxsplit=1)[1]
    assert "COPY --from=builder /build/rust/target/release/marty-flow" in target
    assert "EXPOSE 8011 9011" in target
    assert 'CMD ["curl", "--fail", "http://127.0.0.1:8011/health"]' in target
    assert "exec /usr/local/bin/marty-flow" in target
    assert "python" not in target.lower()


def test_ci_builds_the_native_flow_image_target() -> None:
    workflow = text(".github/workflows/ci.yml")
    step = workflow.split("- name: Build flow image", maxsplit=1)[1]
    assert "file: rust/services/Dockerfile.ci" in step
    assert "target: flow" in step
    assert "tags: marty-flow:ci" in step
