"""Opt-in real datastore checks for customer bootstrap and memory pressure.

Set MARTY_TEST_POSTGRES_BIN to a PostgreSQL 15+ bin directory and
MARTY_TEST_REDIS_SERVER to a Redis 7+ executable. Set MARTY_TEST_DEPLOY_BIN to the
source-matched native publisher to test its database URIs. Every server and data
directory is disposable; these tests never connect to an existing installation.
"""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time

import pytest

from tests.test_marty_helm_chart import HELM, render, resources


ROOT = Path(__file__).resolve().parents[1]


def unused_tcp_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def test_packaged_postgres_bootstrap_matches_canonical_script() -> None:
    assert (ROOT / "docker/init-databases.sh").read_bytes() == (
        ROOT / "deploy/helm/marty/files/postgres/init-databases.sh"
    ).read_bytes()


@contextmanager
def postgres_server():
    selected = os.environ.get("MARTY_TEST_POSTGRES_BIN")
    if not selected:
        pytest.skip("set MARTY_TEST_POSTGRES_BIN for the real PostgreSQL bootstrap check")
    binaries = Path(selected)
    for name in ("initdb", "postgres", "pg_isready", "psql"):
        assert (binaries / name).is_file(), f"missing selected PostgreSQL binary: {name}"
    with tempfile.TemporaryDirectory(prefix="marty-init-pg-") as directory:
        root = Path(directory)
        data = root / "data"
        admin_password = root / "admin-password"
        admin_password.write_text("disposable-bootstrap-admin-password", encoding="utf-8")
        admin_password.chmod(0o600)
        subprocess.run([
            str(binaries / "initdb"), "-D", str(data), "--auth-local=trust",
            "--auth-host=scram-sha-256", "--username=installer_test_admin",
            "--pwfile", str(admin_password), "--encoding=UTF8", "--no-locale",
        ], check=True, capture_output=True, timeout=30)
        port = unused_tcp_port()
        with (root / "server.log").open("wb") as log:
            process = subprocess.Popen([
                str(binaries / "postgres"), "-D", str(data), "-h", "127.0.0.1",
                "-p", str(port), "-c", "unix_socket_directories=",
                "-c", "password_encryption=scram-sha-256",
            ], stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 15
                while subprocess.run([
                    str(binaries / "pg_isready"), "-h", "127.0.0.1", "-p", str(port),
                ], capture_output=True, check=False).returncode:
                    assert process.poll() is None, "disposable PostgreSQL stopped before readiness"
                    assert time.monotonic() < deadline, "disposable PostgreSQL did not become ready"
                    time.sleep(0.05)
                yield binaries, root, port
            finally:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


@pytest.mark.parametrize("script", [
    "docker/init-databases.sh",
    "deploy/helm/marty/files/postgres/init-databases.sh",
])
def test_customer_database_passwords_authenticate_without_sql_interpolation(script: str) -> None:
    with postgres_server() as (binaries, root, port):
        passwords = {
            "marty": "customer%40%2F@:/?#'quote\\slash$$; CREATE ROLE unexpected LOGIN; --\né-東京",
            "keycloak": "identity'quote\\slash:percent%$;--\nfinish",
        }
        password_file = root / "keycloak-password"
        password_file.write_text(passwords["keycloak"] + "\n", encoding="utf-8")
        password_file.chmod(0o600)
        environment = {
            **os.environ, "PATH": f"{binaries}:/usr/bin:/bin", "PGHOST": "127.0.0.1",
            "PGPORT": str(port), "POSTGRES_USER": "installer_test_admin", "POSTGRES_DB": "postgres",
            "PGPASSWORD": "disposable-bootstrap-admin-password",
            "MARTY_DB_PASSWORD": passwords["marty"], "KEYCLOAK_DB_PASSWORD_FILE": str(password_file),
        }
        for name in ("MARTY_DB_PASSWORD_FILE", "KEYCLOAK_DB_PASSWORD", "MARTY_INITIALIZE_KEYCLOAK_DATABASE"):
            environment.pop(name, None)

        def initialize() -> None:
            result = subprocess.run(
                ["/bin/sh", str(ROOT / script)], env=environment,
                capture_output=True, text=True, check=False, timeout=15,
            )
            assert result.returncode == 0, result.stdout + result.stderr
            assert all(password not in result.stdout + result.stderr for password in passwords.values())

        def authenticate(user: str, password: str) -> subprocess.CompletedProcess:
            return subprocess.run([
                str(binaries / "psql"), "-X", "-w", "-h", "127.0.0.1", "-p", str(port),
                "-U", user, "-d", user, "-At", "-c", "SELECT current_user",
            ], env={**environment, "PGPASSWORD": password}, capture_output=True,
                text=True, check=False, timeout=10)

        initialize()
        for user, password in passwords.items():
            valid = authenticate(user, password)
            assert valid.returncode == 0 and valid.stdout.strip() == user, valid.stderr
            assert authenticate(user, "incorrect-password").returncode != 0
        # Exercise the actual consumer loader, then hand its URI to libpq only
        # through private stdin. No credential-bearing URI enters argv/logs.
        uri_environment = {
            **environment,
            "DATABASE_URL_TEMPLATE": f"postgresql://marty:${{MARTY_DB_PASSWORD}}@127.0.0.1:{port}/marty",
        }
        uri_consumer = subprocess.run([
            "/bin/sh", "-c",
            '. "$1"; printf "%s\\n" "\\connect $DATABASE_URL" "SELECT current_user;" | '
            'psql -X -q -w -v ON_ERROR_STOP=1 -U installer_test_admin -d postgres -At',
            "uri-consumer", str(ROOT / "scripts/load-secrets-env.sh"),
        ], env=uri_environment, capture_output=True, text=True, check=False, timeout=10)
        assert uri_consumer.returncode == 0, uri_consumer.stderr
        assert uri_consumer.stdout.strip() == "marty"
        assert passwords["marty"] not in uri_consumer.stdout + uri_consumer.stderr
        # Repeating initialization must retain the existing users' passwords.
        environment["MARTY_DB_PASSWORD"] = "replacement-must-not-overwrite-existing-user"
        initialize()
        assert authenticate("marty", passwords["marty"]).returncode == 0
        roles = subprocess.run([
            str(binaries / "psql"), "-X", "-U", "installer_test_admin", "-d", "postgres", "-At",
            "-c", "SELECT rolname FROM pg_roles WHERE rolname = 'unexpected'",
        ], env=environment, capture_output=True, text=True, check=True, timeout=10)
        assert roles.stdout == ""


def test_native_published_database_uris_authenticate_with_customer_password(tmp_path: Path) -> None:
    binary = os.environ.get("MARTY_TEST_DEPLOY_BIN")
    if not binary:
        pytest.skip("set MARTY_TEST_DEPLOY_BIN for native publication-to-PostgreSQL authentication")
    assert Path(binary).is_file(), "selected native publisher is unavailable"
    password = "customer%40%2F@:/?#'quote\\slash$`\né-東京"
    with postgres_server() as (binaries, root, port):
        environment = {
            "PATH": f"{binaries}:/usr/bin:/bin", "PGHOST": "127.0.0.1", "PGPORT": str(port),
            "POSTGRES_USER": "installer_test_admin", "POSTGRES_DB": "postgres",
            "PGPASSWORD": "disposable-bootstrap-admin-password", "MARTY_DB_PASSWORD": password,
            "MARTY_INITIALIZE_KEYCLOAK_DATABASE": "false",
        }
        initialized = subprocess.run([
            "/bin/sh", str(ROOT / "docker/init-databases.sh"),
        ], env=environment, capture_output=True, text=True, check=False, timeout=15)
        assert initialized.returncode == 0, initialized.stderr
        # This closed kubectl double records only stdin. No cluster access.
        kubectl = tmp_path / "kubectl"
        kubectl.write_text(
            '#!/bin/sh\nset -eu\n[ "$#" = 3 ] && [ "$1" = apply ] && [ "$2" = -f ] && [ "$3" = - ]\n'
            'umask 077\ncat >> "$MARTY_TEST_MANIFEST"\nprintf "\\n" >> "$MARTY_TEST_MANIFEST"\n',
            encoding="utf-8",
        )
        kubectl.chmod(0o700)
        secret_catalog = json.loads((ROOT / "deploy-config/catalog/secrets.json").read_text())
        publication = json.loads((ROOT / "deploy-config/catalog/kubernetes-secrets.json").read_text())
        names = {secret["env"] for secret in secret_catalog["secrets"].values() if secret.get("env")}
        names.update(publication["required"])
        names.update(field["env"] for secret in publication["secrets"]
                     for field in secret["fields"].values() if "env" in field)
        manifest = tmp_path / "published.jsonl"
        publisher_environment = {
            name: f"synthetic-distinct-credential-for-{name}" for name in names
        }
        publisher_environment.update({
            "PATH": f"{tmp_path}:/usr/bin:/bin", "MARTY_TEST_MANIFEST": str(manifest),
            "MARTY_DB_PASSWORD": password,
        })
        published = subprocess.run([
            binary, "--repo-root", str(ROOT), "kubernetes-secrets", "kubernetes-production", "uri-test",
        ], env=publisher_environment, capture_output=True, text=True, check=False, timeout=15)
        assert published.returncode == 0, published.stderr
        assert password not in published.stdout + published.stderr
        assert manifest.stat().st_mode & 0o777 == 0o600
        secrets = [json.loads(line) for line in manifest.read_text().splitlines()]
        main = next(secret["stringData"] for secret in secrets if secret["metadata"]["name"] == "marty-secrets")
        assert main["MARTY_DB_PASSWORD"] == password
        for name in ("DATABASE_URL", "DATABASE_SYNC_URL"):
            # Map only the fixed deployment endpoint to this disposable server;
            # the published credential bytes must pass through unchanged.
            uri = main[name].replace("postgresql+asyncpg://", "postgresql://").replace(
                "@postgres:5432/marty", f"@127.0.0.1:{port}/marty",
            )
            consumed = subprocess.run([
                str(binaries / "psql"), "-X", "-q", "-w", "-v", "ON_ERROR_STOP=1",
                "-U", "installer_test_admin", "-d", "postgres", "-At",
            ], env=environment, input=f"\\connect {uri}\nSELECT current_user;\n",
                capture_output=True, text=True, check=False, timeout=10)
            assert consumed.returncode == 0, consumed.stderr
            assert consumed.stdout.strip() == "marty"
            assert password not in consumed.stdout + consumed.stderr


class RedisFailure(Exception):
    pass


class RedisConnection:
    """The small RESP subset needed here avoids an extra test dependency."""

    def __init__(self, port: int):
        self.socket = socket.socket()
        self.socket.settimeout(3)
        try:
            self.socket.connect(("127.0.0.1", port))
        except OSError:
            self.socket.close()
            raise
        self.stream = self.socket.makefile("rb")

    def close(self) -> None:
        self.stream.close()
        self.socket.close()

    def command(self, *arguments: str) -> str | int | None:
        values = [argument.encode() for argument in arguments]
        self.socket.sendall(b"*%d\r\n" % len(values) + b"".join(
            b"$%d\r\n" % len(value) + value + b"\r\n" for value in values
        ))
        line = self.stream.readline()
        if line.startswith(b"-"):
            raise RedisFailure(line[1:-2].decode())
        if line.startswith(b"+"):
            return line[1:-2].decode()
        if line.startswith(b":"):
            return int(line[1:-2])
        assert line.startswith(b"$"), "unexpected Redis reply"
        length = int(line[1:-2])
        if length == -1:
            return None
        value = self.stream.read(length)
        assert self.stream.read(2) == b"\r\n"
        return value.decode()


@contextmanager
def redis_server(binary: str, root: Path, policy: str):
    port = unused_tcp_port()
    with (root / "redis.log").open("ab") as log:
        process = subprocess.Popen([
            binary, "--bind", "127.0.0.1", "--port", str(port),
            "--dir", str(root), "--save", "", "--appendonly", "yes",
            "--maxmemory", "128mb", "--maxmemory-policy", policy,
        ], stdout=log, stderr=log)
        connection = None
        try:
            deadline = time.monotonic() + 10
            while connection is None:
                assert process.poll() is None, "disposable Redis stopped before readiness"
                try:
                    connection = RedisConnection(port)
                except ConnectionRefusedError:
                    assert time.monotonic() < deadline, "disposable Redis did not become ready"
                    time.sleep(0.05)
            assert connection.command("PING") == "PONG"
            yield connection
        finally:
            if connection is not None:
                connection.close()
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def redis_info(connection: RedisConnection, section: str) -> dict[str, str]:
    value = connection.command("INFO", section)
    assert isinstance(value, str)
    return dict(line.split(":", 1) for line in value.splitlines() if ":" in line)


@pytest.mark.skipif(HELM is None, reason="Helm 3 is required to select the rendered Redis policy")
def test_redis_pressure_preserves_registry_and_unexpired_replay_markers(tmp_path: Path) -> None:
    binary = os.environ.get("MARTY_TEST_REDIS_SERVER")
    if not binary:
        pytest.skip("set MARTY_TEST_REDIS_SERVER for the real Redis pressure check")
    assert Path(binary).is_file(), "selected Redis executable is unavailable"
    server = resources(render(tmp_path), "StatefulSet")["redis"]["spec"]["template"]["spec"]["containers"][0]
    policy = server["args"][server["args"].index("--maxmemory-policy") + 1]
    registry_key = "org:customer-pressure:signing-key-services"
    registry = '{"services":[{"id":"retained-managed-issuer"}]}'
    replay_key = "marty:issuer-signing-grant:used:v1:synthetic-pressure-grant"
    with tempfile.TemporaryDirectory(prefix="marty-pressure-") as directory:
        root = Path(directory)
        with redis_server(binary, root, policy) as connection:
            assert connection.command("SELECT", "2") == "OK"
            assert connection.command("SET", registry_key, registry) == "OK"
            assert connection.command("SET", replay_key, "1", "NX", "EX", "60") == "OK"
            # Lower only this disposable instance's cap to exercise pressure
            # with a few hundred KiB rather than changing deployment sizing.
            limit = int(redis_info(connection, "memory")["used_memory"]) + 256 * 1024
            assert connection.command("CONFIG", "SET", "maxmemory", str(limit)) == "OK"
            written = []
            for index in range(128):
                try:
                    key = f"synthetic-pressure:{index}"
                    connection.command("SET", key, "x" * 65536)
                    written.append(key)
                except RedisFailure as error:
                    assert str(error).startswith("OOM "), str(error)
                    break
            else:
                pytest.fail("memory pressure did not refuse writes; retained state can be evicted")
            assert connection.command("GET", registry_key) == registry
            assert connection.command("GET", replay_key) == "1"
            assert int(connection.command("TTL", replay_key)) > 0
            assert redis_info(connection, "stats")["evicted_keys"] == "0"
            for key in written:
                connection.command("DEL", key)
            assert connection.command("SET", replay_key, "1", "NX", "EX", "60") is None
        # A normal process restart also retains the accepted identity/replay
        # writes through the same append-only persistence selected by the chart.
        with redis_server(binary, root, policy) as connection:
            assert connection.command("SELECT", "2") == "OK"
            assert connection.command("GET", registry_key) == registry
            assert connection.command("SET", replay_key, "1", "NX", "EX", "60") is None
