#!/usr/bin/env python3
"""Execute native pairing scope tests on newly created, owned PostgreSQL/Redis.

Uses pinned repository fixture images and removes only exact owned container IDs.
This is database/adapter qualification, not installed-wallet or rootless acceptance.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import time
from urllib.parse import urlsplit

import probe_signing_keys_openbao_policy as fixtures

POSTGRES_CASE = "additive_verifier_migration_preserves_legacy_pairing_and_rejects_scope_substitution"
REDIS_CASE = "pairing_token_is_not_stored_and_redeems_once_under_race"
OWNER_LABEL = "wallet-verifier-pairing-qualification"


def remove_owned(name: str, cid: str):
    if re.fullmatch(r"[0-9a-f]{64}", cid) is None:
        raise RuntimeError("invalid owned fixture container identity")
    if not fixtures.require_docker("ps", "-aq", "--filter", f"id={cid}"):
        return
    actual = json.loads(fixtures.require_docker("inspect", cid))[0]
    labels = actual["Config"].get("Labels") or {}
    if actual["Id"] != cid or actual["Name"] != f"/{name}" or labels.get("codex.purpose") != OWNER_LABEL or labels.get("marty.disposable") != "wallet-verifier-pairing":
        raise RuntimeError("refuse unowned verifier fixture cleanup")
    fixtures.require_docker("rm", "-f", "-v", cid, timeout=30)
    if fixtures.require_docker("ps", "-aq", "--filter", f"id={cid}"):
        raise RuntimeError("owned verifier fixture removal was not verified")


@contextmanager
def disposable_postgres():
    name = "wallet-verifier-postgres-" + secrets.token_hex(6)
    password, nonce = secrets.token_hex(32), secrets.token_hex(32)
    database = "marty_wallet_verifier_test"
    cid = fixtures.require_docker("run", "--rm", "-d", "--name", name,
        "--label", "marty.disposable=wallet-verifier-pairing",
        "--label", f"codex.purpose={OWNER_LABEL}",
        "--memory", "256m", "--memory-swap", "256m",
        "--tmpfs", "/var/lib/postgresql/data:rw,mode=700",
        "-e", f"POSTGRES_PASSWORD={password}", "-e", f"POSTGRES_DB={database}",
        "-p", "127.0.0.1::5432", fixtures.POSTGRES_IMAGE)
    receipt = {"ownedPostgresRemoved": False}
    try:
        for _ in range(80):
            ready = fixtures.docker("exec", cid, "pg_isready", "-h", "127.0.0.1", "-U", "postgres", "-d", database)
            if ready.returncode == 0:
                break
            time.sleep(.25)
        else:
            raise RuntimeError("owned PostgreSQL fixture readiness failed")
        fixtures.require_docker("exec", cid, "psql", "-X", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", database, "-c",
            f"CREATE TABLE public.marty_disposable_guard(nonce text NOT NULL); INSERT INTO public.marty_disposable_guard VALUES ('{nonce}')")
        port = int(fixtures.require_docker("port", cid, "5432/tcp").splitlines()[0].rsplit(":", 1)[1])
        yield {"DEVICE_REGISTRATION_POSTGRES_TEST_URL": f"postgres://postgres:{password}@127.0.0.1:{port}/{database}",
               "MARTY_TEST_POSTGRES_DISPOSABLE_NONCE": nonce}, receipt
    finally:
        remove_owned(name, cid)
        receipt["ownedPostgresRemoved"] = True


def discover(binary: Path, name: str, case: str) -> Path:
    binary = binary.resolve(strict=True)
    if not binary.is_file() or not binary.name.startswith(name + "-"):
        raise ValueError("expected a compiled " + name + " test executable")
    result = subprocess.run([str(binary), case, "--ignored", "--exact", "--list"],
        capture_output=True, text=True, timeout=30, check=False)
    if result.returncode != 0 or [line for line in result.stdout.splitlines() if line.endswith(": test")] != [f"{case}: test"]:
        raise RuntimeError("exact pairing test discovery failed before fixture allocation")
    return binary


@contextmanager
def disposable_redis():
    name = "wallet-verifier-redis-" + secrets.token_hex(6)
    cid = fixtures.require_docker("run", "--rm", "-d", "--name", name,
        "--label", "marty.disposable=wallet-verifier-pairing",
        "--label", f"codex.purpose={OWNER_LABEL}",
        "--memory", "128m", "--memory-swap", "128m", "--tmpfs", "/data:rw,mode=700",
        "-p", "127.0.0.1::6379", fixtures.REDIS_IMAGE,
        "redis-server", "--save", "", "--appendonly", "no")
    receipt = {"ownedRedisRemoved": False}
    try:
        for _ in range(40):
            ready = fixtures.docker("exec", cid, "redis-cli", "ping")
            if ready.returncode == 0 and ready.stdout.strip() == "PONG":
                break
            time.sleep(.25)
        else:
            raise RuntimeError("owned Redis fixture readiness failed")
        nonce = secrets.token_hex(32)
        fixtures.require_docker("exec", cid, "redis-cli", "-n", "13", "SET", "marty:tests:disposable-guard", nonce)
        port = int(fixtures.require_docker("port", cid, "6379/tcp").splitlines()[0].rsplit(":", 1)[1])
        yield {"MARTY_TEST_REDIS_URL": f"redis://127.0.0.1:{port}/13",
               "MARTY_TEST_REDIS_DISPOSABLE_NONCE": nonce}, receipt
    finally:
        remove_owned(name, cid)
        receipt["ownedRedisRemoved"] = True


def execute(binary: Path, case: str, environment: dict[str, str]):
    private = list(environment.values())
    private += [urlsplit(value).password for value in environment.values() if "://" in value]
    try:
        result = subprocess.run([str(binary), case, "--ignored", "--exact", "--nocapture"],
            env=dict(os.environ, **environment), capture_output=True, text=True, timeout=120, check=False)
        detail = result.stdout + result.stderr
        passed = result.returncode == 0 and "test result: ok. 1 passed; 0 failed; 0 ignored;" in detail
    except subprocess.TimeoutExpired as error:
        detail = (error.stdout or b"").decode(errors="replace") if isinstance(error.stdout, bytes) else (error.stdout or "")
        passed = False
    for secret in private:
        if secret:
            detail = detail.replace(secret, "[fixture-private]")
    if not passed:
        raise RuntimeError("native pairing qualification failed:\n" + detail[-6000:])
    return detail


def qualify(postgres_binary: Path, redis_binary: Path) -> dict:
    postgres_binary = discover(postgres_binary, "verifier_pairing_postgres", POSTGRES_CASE)
    redis_binary = discover(redis_binary, "pairing_ticket_redis", REDIS_CASE)
    with disposable_postgres() as (environment, postgres_receipt):
        postgres_detail = execute(postgres_binary, POSTGRES_CASE, environment)
    with disposable_redis() as (environment, redis_receipt):
        redis_detail = execute(redis_binary, REDIS_CASE, environment)
    # Preserve actual sanitized libtest receipts for the shared CI execution
    # guard; a driver's JSON declaration alone is not a native test summary.
    print(postgres_detail, end="")
    print(redis_detail, end="")
    return {"postgresPassed": 1, "redisPassed": 1, "ignored": 0,
        **postgres_receipt, **redis_receipt,
        "scope": "actual fresh PostgreSQL migration/scope and Redis atomic persistence; not installed-wallet, KMS, rootless or official-suite acceptance"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--postgres-test-binary", required=True, type=Path)
    parser.add_argument("--redis-test-binary", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(qualify(args.postgres_test_binary, args.redis_test_binary)))
