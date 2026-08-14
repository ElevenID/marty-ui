from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_shared_service_image_dispatches_signing_keys_to_rust() -> None:
    dockerfile = (ROOT / "services" / "Dockerfile").read_text(encoding="utf-8")
    entrypoint = (ROOT / "services" / "entrypoint.sh").read_text(encoding="utf-8")

    assert "cargo build --locked --release -p marty-signing-keys" in dockerfile
    assert "target/release/marty-signing-keys" in dockerfile
    assert 'if [ "$MODULE_NAME" = "signing_keys" ]' in entrypoint
    assert "exec /usr/local/bin/marty-signing-keys" in entrypoint


def test_superseded_python_signing_keys_scaffold_is_deleted() -> None:
    assert not list((ROOT / "services" / "signing_keys").glob("*.py"))


def test_base_stack_wires_gateway_to_the_rust_signing_keys_service() -> None:
    compose = (ROOT / "docker-compose.base.yml").read_text(encoding="utf-8")

    assert "SIGNING_KEYS_SERVICE_URL: http://signing-keys:8017" in compose
    assert 'SIGNING_KEYS_SERVICE_PORT: "8017"' in compose
    assert "SERVICE_NAME: signing-keys" in compose
