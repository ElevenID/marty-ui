#!/usr/bin/env python3
"""Renew an independent Keycloak provider with an authenticated native operator.

This does not enroll a full application installation or replace its renewal
contract. Only the five existing master/11id signing and JWE policies are used.
Never print credentials, native output, HTTP response bodies, or exception text.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import time
from urllib.error import HTTPError
from urllib.parse import urlsplit

from selfhost_openbao_client import Bao
from source_matched_native import verified_native_binary

POLICY = "selfhost-kms-renewal"
ROLE_PATH = "auth/selfhost-renew/role/kms-renewer"
LEAF_PATH = "auth/token/create/selfhost-renew-leaf"
LEAF_FILES = {
    "keycloak_signing_kms_token": "sign",
    **{f"keycloak_{r}_{p}_token": f"{r}-{p}"
       for r in ("master", "11id") for p in ("cookie", "ciba")},
}
OUTPUTS = set(LEAF_FILES) | {"keycloak_master_rs256_cert", "keycloak_11id_rs256_cert"}
# A resumed projection must survive the next four-hour timer plus jitter.
MINIMUM_PUBLICATION_TTL = 4 * 3600 + 10 * 60
ROLE_SETTINGS = {
    "bind_secret_id": True, "secret_id_ttl": 604800, "secret_id_num_uses": 0,
    "token_policies": [POLICY], "token_no_default_policy": True,
    "token_ttl": 28800, "token_max_ttl": 28800, "token_explicit_max_ttl": 28800,
    "token_period": 0, "token_num_uses": 0, "token_type": "service",
}


def require(condition: bool) -> None:
    if not condition:
        raise ValueError("Standalone Keycloak lifecycle validation refused")


def read_file(path: Path, modes=(0o600,), maximum=1048576) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) in modes
                and 0 < info.st_size <= maximum)
        value = stream.read(maximum + 1)
        require(len(value) == info.st_size)
        return value


def write_file(path: Path, data: bytes, mode=0o600, *, replace=False) -> None:
    """Publish one complete leaf atomically; never follow an existing link."""
    if path.exists() or path.is_symlink():
        require(replace)
        read_file(path, modes=(0o444, 0o600))
    temporary = path.with_name("." + path.name + "." + secrets.token_hex(8))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
        if replace:
            os.replace(temporary, path)
        else:
            os.link(temporary, path, follow_symlinks=False)
            temporary.unlink()
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def save(path: Path, value, *, replace=False) -> None:
    write_file(path, (json.dumps(value, sort_keys=True, indent=2) + "\n").encode(),
               replace=replace)


def policy_names(names: dict[str, str]) -> list[str]:
    require(set(names) == set(LEAF_FILES))
    for file, scope in LEAF_FILES.items():
        require(re.fullmatch(r"selfhost-keycloak-" + re.escape(scope) + r"-[a-f0-9]{12}",
                             names[file]) is not None)
    require(len(set(names.values())) == 5)
    return sorted(names.values())


def renewal_policy(names: dict[str, str]) -> str:
    """Exact paths, no policy editing, key creation/export, or unrelated minting."""
    allowed = policy_names(names)
    paths = {}
    for path, capabilities in [
        ("sys/mounts", ["read"]), ("sys/policies/acl", ["list"]),
        ("sys/policies/acl/" + POLICY, ["read"]),
        ("auth/token/lookup", ["update"]), ("auth/token/revoke-self", ["update"]),
        ("auth/token/roles/selfhost-renew-leaf", ["read"]),
        (ROLE_PATH, ["read"]), (ROLE_PATH + "/secret-id", ["update"]),
        (ROLE_PATH + "/secret-id-accessor/destroy", ["update"]),
        ("keycloak-pki/cert/ca", ["read"]),
        ("keycloak-pki/roles/rs256", ["read"]),
        ("keycloak-pki/sign/rs256", ["update"]),
    ]:
        paths[path] = {"capabilities": capabilities}
    paths[LEAF_PATH] = {
        "capabilities": ["update"],
        "required_parameters": ["policies", "ttl", "explicit_max_ttl", "no_default_policy"],
        # OpenBao 2.5's policy parser cannot represent nested array values.
        # The immutable token role enforces the exact five-policy allowlist;
        # native mint validation requires one purpose per returned leaf.
        "allowed_parameters": {"policies": [], "ttl": ["8h"],
                               "explicit_max_ttl": ["8h"], "no_default_policy": [True]},
    }
    for name in allowed:
        paths["sys/policies/acl/" + name] = {"capabilities": ["read"]}
    for realm in ("master", "11id"):
        for kind in ("rs256", "hs512"):
            paths[f"transit/keys/keycloak-{realm}-{kind}"] = {"capabilities": ["read"]}
        paths[f"transit/keys/keycloak-{realm}-rs256/csr"] = {"capabilities": ["update"]}
        for purpose in ("cookie", "ciba"):
            paths[f"didcomm/keycloak/keys/{realm}/{purpose}"] = {"capabilities": ["read"]}
    return json.dumps({"path": paths}, sort_keys=True, separators=(",", ":"))


def leaf_valid(data, policy: str, *, minimum=25200) -> None:
    ttl, created = data.get("ttl", 0), data.get("creation_ttl", 0)
    require(data.get("policies") == [policy] and data.get("orphan") is True
            and data.get("type") == "service" and data.get("num_uses") == 0
            and data.get("explicit_max_ttl") == 28800
            and minimum <= ttl <= created <= 28800
            and data.get("path") == LEAF_PATH
            and not data.get("identity_policies")
            and data.get("token_policies", [policy]) == [policy]
            and not data.get("period") and not data.get("token_period"))


class Lifecycle:
    def __init__(self, root: Path):
        require(os.name == "posix" and root.is_absolute() and not root.is_symlink())
        info = root.stat()
        require(root.resolve() == root and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) == 0o700)
        self.root, self.runtime = root, root / "runtime"
        require(self.runtime.is_dir() and not self.runtime.is_symlink()
                and self.runtime.stat().st_uid == os.getuid()
                and stat.S_IMODE(self.runtime.stat().st_mode) == 0o555)
        self.state = root / "renewal"
        if not self.state.exists():
            self.state.mkdir(mode=0o700)
        info = self.state.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) == 0o700)
        self.config = json.loads(read_file(root / "lifecycle-config.json"))
        require(set(self.config) == {"schema", "endpoint", "operator_sha256",
                                    "operator_source_sha", "operator_release_tag"}
                and self.config["schema"] == "elevenid.standalone-keycloak-lifecycle/v1")
        endpoint = urlsplit(self.config["endpoint"])
        require(endpoint.scheme == "https" and endpoint.hostname in ("127.0.0.1", "localhost")
                and not endpoint.username and not endpoint.password
                and endpoint.path in ("", "/") and not endpoint.query and not endpoint.fragment)
        self.endpoint, self.ca = self.config["endpoint"].rstrip("/"), root / "openbao-ca.crt"
        read_file(self.ca, modes=(0o600, 0o644, 0o444))
        os.environ.update({"MARTY_DEPLOY_BIN": str(root / "marty-deploy"),
                           "MARTY_DEPLOY_BIN_SHA256": self.config["operator_sha256"],
                           "MARTY_DEPLOY_SOURCE_SHA": self.config["operator_source_sha"],
                           "MARTY_DEPLOY_RELEASE_TAG": self.config["operator_release_tag"]})
        tool = (root / "marty-deploy").lstat()
        require(stat.S_ISREG(tool.st_mode) and tool.st_uid == os.getuid()
                and stat.S_IMODE(tool.st_mode) == 0o700 and tool.st_nlink == 1)
        self.native = verified_native_binary(root / "source/selfhost-prepared", "MARTY_DEPLOY")
        require(self.native is not None)

    @contextmanager
    def lock(self):
        import fcntl
        fd = os.open(self.state / "lifecycle.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                    and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        finally:
            os.close(fd)

    def native_json(self, operation, args=(), body=None):
        result = subprocess.run([str(self.native), "operator", operation, *args],
                                input=json.dumps(body).encode(), capture_output=True,
                                timeout=None if operation == "keycloak-provision" else 10)
        if result.returncode:
            # An interrupted native mint can leave live leaves. Keep pending state.
            save(self.state / "last-native-failure.json", {
                "operation": operation, "exit_code": result.returncode,
                "diagnostic_sha256": hashlib.sha256(result.stderr).hexdigest(),
                "observed": int(time.time())},
                replace=(self.state / "last-native-failure.json").exists())
            raise RuntimeError("Native lifecycle operation refused; preserve pending state")
        return json.loads(result.stdout)

    def authority(self):
        return json.loads(read_file(self.state / "authority.json"))

    def login(self, authority=None):
        authority = self.authority() if authority is None else authority
        bao = Bao(self.endpoint, self.ca, "")
        data = bao.request("POST", "auth/selfhost-renew/login", {
            "role_id": authority["role_id"], "secret_id": authority["secret_id"]},
            authenticate=False)
        token = data["auth"]["client_token"]
        require(isinstance(token, str) and len(token) >= 20)
        bao.token = token
        try:
            metadata = bao.request("POST", "auth/token/lookup", {"token": token})["data"]
            require(metadata["policies"] == [POLICY] and metadata["path"] == "auth/selfhost-renew/login"
                    and metadata["orphan"] is True and metadata["explicit_max_ttl"] == 28800
                    and metadata["type"] == "service" and 3600 <= metadata["ttl"] <= 28800
                    and not metadata.get("period") and not metadata.get("identity_policies"))
            role = bao.request("GET", ROLE_PATH)["data"]
            require(all(role.get(k) == v for k, v in ROLE_SETTINGS.items()))
            acl = bao.request("GET", "sys/policies/acl/" + POLICY)["data"]["policy"]
            require(hashlib.sha256(acl.encode()).hexdigest() == authority["acl_sha256"]
                    and acl == renewal_policy(authority["policies"]))
            leaf = bao.request("GET", "auth/token/roles/selfhost-renew-leaf")["data"]
            require(sorted(leaf["allowed_policies"]) == policy_names(authority["policies"])
                    and set(leaf["disallowed_policies"]) == {"root", "default"}
                    and leaf["orphan"] is True and leaf["token_no_default_policy"] is True
                    and leaf["token_explicit_max_ttl"] == 28800 and leaf["token_type"] == "service"
                    and not leaf.get("allowed_policies_glob")
                    and not leaf.get("disallowed_policies_glob")
                    and not leaf.get("period") and not leaf.get("token_period"))
            return bao, authority
        except Exception:
            bao.request("POST", "auth/token/revoke-self", {})
            raise

    @staticmethod
    def close(bao):
        bao.request("POST", "auth/token/revoke-self", {})

    def bootstrap(self):
        require(not (self.state / "authority.json").exists()
                and not (self.state / "bootstrap-pending.json").exists())
        root_token = read_file(self.root / "openbao-root.token").decode().strip()
        bao = Bao(self.endpoint, self.ca, root_token)
        require("selfhost-renew/" not in bao.request("GET", "sys/auth")["data"])
        require(POLICY not in bao.request("LIST", "sys/policies/acl")["data"]["keys"])
        try:
            bao.request("GET", "auth/token/roles/selfhost-renew-leaf")
        except HTTPError as error:
            require(error.code == 404)
        else:
            raise ValueError("Existing leaf role must be preserved")
        names = {}
        for file, scope in LEAF_FILES.items():
            token = read_file(self.runtime / file, modes=(0o444,)).decode().strip()
            data = bao.request("POST", "auth/token/lookup", {"token": token})["data"]
            require(len(data["policies"]) == 1)
            names[file] = data["policies"][0]
            require(re.fullmatch(r"selfhost-keycloak-" + re.escape(scope) + r"-[a-f0-9]{12}",
                                 names[file]) is not None)
            context = {"scope": "signing"}
            if scope != "sign":
                realm, purpose = scope.split("-")
                version = bao.request("GET", f"didcomm/keycloak/keys/{realm}/{purpose}")["data"]["version"]
                context = {"scope": "jwe", "realm": realm, "purpose": purpose, "version": version}
            expected = self.native_json("keycloak-policy", body=context)
            actual = bao.request("GET", "sys/policies/acl/" + names[file])["data"]["policy"]
            require(actual == expected)
        allowed = policy_names(names)
        acl = renewal_policy(names)
        save(self.state / "bootstrap-pending.json", {"started": int(time.time()), "policies": names})
        bao.request("PUT", "sys/policies/acl/" + POLICY, {"policy": acl})
        bao.request("POST", "sys/auth/selfhost-renew", {"type": "approle"})
        bao.request("POST", "auth/token/roles/selfhost-renew-leaf", {
            "allowed_policies": allowed, "disallowed_policies": ["default", "root"],
            "orphan": True, "token_no_default_policy": True,
            "token_explicit_max_ttl": 28800, "token_type": "service"})
        bao.request("POST", ROLE_PATH, ROLE_SETTINGS)
        role_id = bao.request("GET", ROLE_PATH + "/role-id")["data"]["role_id"]
        secret = bao.request("POST", ROLE_PATH + "/secret-id", {"ttl": "168h", "num_uses": 0})["data"]
        authority = {"role_id": role_id, "secret_id": secret["secret_id"],
                     "accessor": secret["secret_id_accessor"], "policies": names,
                     "created": int(time.time()), "expires": int(time.time()) + 604800,
                     "acl_sha256": hashlib.sha256(acl.encode()).hexdigest()}
        save(self.state / "authority.json", authority)
        operator, _ = self.login()
        self.close(operator)
        (self.state / "bootstrap-pending.json").unlink()

    def rotate_secret_id(self):
        require(not (self.state / "rotation-pending.json").exists())
        bao, authority = self.login()
        try:
            save(self.state / "rotation-pending.json", {"started": int(time.time())})
            secret = bao.request("POST", ROLE_PATH + "/secret-id", {"ttl": "168h", "num_uses": 0})["data"]
            candidate = {**authority, "secret_id": secret["secret_id"],
                         "accessor": secret["secret_id_accessor"], "created": int(time.time()),
                         "expires": int(time.time()) + 604800}
            save(self.state / "rotation-pending.json", {"candidate": candidate, "previous": authority}, replace=True)
            self.finish_rotation(authority, candidate)
        finally:
            self.close(bao)

    def old_identity_denied(self, authority):
        probe = Bao(self.endpoint, self.ca, "")
        try:
            response = probe.request("POST", "auth/selfhost-renew/login", {
                "role_id": authority["role_id"], "secret_id": authority["secret_id"]},
                authenticate=False)
        except HTTPError as error:
            require(error.code in (400, 403))
            return True
        probe.token = response["auth"]["client_token"]
        self.close(probe)
        return False

    def finish_rotation(self, previous, candidate):
        require(previous["role_id"] == candidate["role_id"]
                and previous["secret_id"] != candidate["secret_id"]
                and previous["accessor"] != candidate["accessor"]
                and previous["policies"] == candidate["policies"]
                and previous["acl_sha256"] == candidate["acl_sha256"]
                and self.authority() in (previous, candidate))
        # A recovered operation can already have published the new authority or
        # retired the old accessor. Validate the replacement before either step.
        bao, _ = self.login(candidate)
        try:
            save(self.state / "authority.json", candidate, replace=True)
            if not self.old_identity_denied(previous):
                bao.request("POST", ROLE_PATH + "/secret-id-accessor/destroy",
                            {"secret_id_accessor": previous["accessor"]})
                require(self.old_identity_denied(previous))
            save(self.state / "last-rotation.json", {
                "schema": "elevenid.standalone-keycloak-secret-rotation/v1",
                "completed": int(time.time()), "retired_identity_denied": True,
                "secret_id_maximum_lifetime_seconds": 604800, "passed": True},
                replace=(self.state / "last-rotation.json").exists())
            (self.state / "rotation-pending.json").unlink()
        finally:
            self.close(bao)

    def resume_rotation(self):
        require(not (self.state / "generation-pending.json").exists())
        pending = json.loads(read_file(self.state / "rotation-pending.json"))
        self.finish_rotation(pending["previous"], pending["candidate"])

    def validate_outputs(self, bao, authority, outputs):
        require(set(outputs) == OUTPUTS and all(isinstance(v, str) and v and len(v) < 65536
                                              and "PRIVATE KEY" not in v for v in outputs.values()))
        for file in LEAF_FILES:
            metadata = bao.request("POST", "auth/token/lookup", {"token": outputs[file]})["data"]
            leaf_valid(metadata, authority["policies"][file], minimum=MINIMUM_PUBLICATION_TTL)
        for realm in ("master", "11id"):
            # Native keycloak-provision already validates the signed CSR/SPKI and
            # seven-hour validity before returning. Pending recovery rechecks expiry.
            public = bao.request("GET", f"transit/keys/keycloak-{realm}-rs256")["data"]["keys"]["1"]["public_key"]
            der = []
            for operation, material in [("certificate-spki", outputs[f"keycloak_{realm}_rs256_cert"]),
                                        ("public-spki", public)]:
                result = subprocess.run([str(self.native), "operator", operation],
                                        input=material.encode(), capture_output=True, timeout=10)
                require(result.returncode == 0 and bool(result.stdout))
                der.append(result.stdout)
            require(der[0] == der[1])
            result = subprocess.run([str(self.native), "operator", "certificate-expiry",
                                     str(MINIMUM_PUBLICATION_TTL)],
                                    input=outputs[f"keycloak_{realm}_rs256_cert"].encode(),
                                    capture_output=True, timeout=10)
            require(result.returncode == 0 and json.loads(result.stdout) is True)

    def renew(self, *, resume=False):
        pending = self.state / "generation-pending.json"
        require(not (self.state / "rotation-pending.json").exists())
        require(pending.exists() == resume)
        bao, authority = self.login()
        try:
            if resume:
                generation = json.loads(read_file(pending))
                require(generation.get("phase") == "staged")
                outputs = generation["outputs"]
            else:
                generation = {"phase": "mint-started", "started": int(time.time()),
                              "id": secrets.token_hex(12)}
                save(pending, generation)
                outputs = self.native_json("keycloak-provision", (self.endpoint, str(self.ca)), {
                    "token": bao.token, "renew": True, "pki_mount": "keycloak-pki",
                    "nonce": secrets.token_hex(6)})
                generation.update({"phase": "staged", "outputs": outputs})
                save(pending, generation, replace=True)
            self.validate_outputs(bao, authority, outputs)
            projection = dict(outputs)
            for realm in ("master", "11id"):
                projection[f"keycloak-{realm}-rs256.crt"] = outputs[f"keycloak_{realm}_rs256_cert"]
                for purpose in ("cookie", "ciba"):
                    projection[f"{realm}-{purpose}.token"] = outputs[f"keycloak_{realm}_{purpose}_token"]
            require(self.runtime.is_dir() and not self.runtime.is_symlink()
                    and self.runtime.stat().st_uid == os.getuid()
                    and stat.S_IMODE(self.runtime.stat().st_mode) == 0o555)
            # Every field refers to the same retained key/version and purpose.
            # Old/new leaves can overlap safely; each individual replacement is atomic.
            for name in projection:
                read_file(self.runtime / name, modes=(0o444,))
            self.runtime.chmod(0o755)
            try:
                for name, content in projection.items():
                    write_file(self.runtime / name, content.encode(), mode=0o444, replace=True)
            finally:
                self.runtime.chmod(0o555)
            require(all(read_file(self.runtime / name, modes=(0o444,)).decode() == value
                        for name, value in projection.items()))
            receipt = {"schema": "elevenid.standalone-keycloak-renewal/v1",
                       "generation": generation["id"], "completed": int(time.time()),
                       "orphan_leaves": 5, "maximum_lifetime_seconds": 28800,
                       "retained_key_versions": True, "private_keys_exported": False,
                       "operator_source_sha": self.config["operator_source_sha"], "passed": True}
            save(self.state / "last-renewal.json", receipt,
                 replace=(self.state / "last-renewal.json").exists())
            pending.unlink()
            return receipt
        finally:
            self.close(bao)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-root", required=True, type=Path)
    parser.add_argument("command", choices=("bootstrap", "renew", "resume", "rotate-secret-id",
                                           "resume-rotation", "cycle"))
    args = parser.parse_args()
    try:
        lifecycle = Lifecycle(args.state_root)
        with lifecycle.lock():
            require(args.command == "bootstrap"
                    or not (lifecycle.state / "bootstrap-pending.json").exists())
            if args.command == "bootstrap":
                lifecycle.bootstrap()
            elif args.command == "rotate-secret-id":
                lifecycle.rotate_secret_id()
            elif args.command == "resume-rotation":
                lifecycle.resume_rotation()
            else:
                if args.command == "cycle":
                    require(not (lifecycle.state / "generation-pending.json").exists()
                            and not (lifecycle.state / "rotation-pending.json").exists())
                    if time.time() - lifecycle.authority()["created"] >= 172800:
                        lifecycle.rotate_secret_id()
                receipt = lifecycle.renew(resume=args.command == "resume")
                print(json.dumps(receipt, sort_keys=True))
    except Exception as error:
        print("Standalone Keycloak lifecycle refused (" + type(error).__name__
              + "); preserve private pending state for recovery")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
