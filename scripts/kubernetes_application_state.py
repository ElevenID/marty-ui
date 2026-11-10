"""Private current-generation selection for the Kubernetes development adapter.

Staging and activation hold the same directory flock for their entire operation.
The lock coordinates cooperating local writers; the retained state must remain
on private operator storage. A durable pending intent blocks fresh staging after
an interrupted cluster mutation. Only its exact activation attempt may publish
or reconcile selection, and neither old credentials nor old selector bytes are
discarded before a verified successor and completion receipt exist.
"""
from __future__ import annotations

from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass
from functools import wraps
import json
import os
from pathlib import Path
import re
import secrets
import stat

import bootstrap_kubernetes_openbao as bootstrap


SELECTOR = "application-current.json"
PENDING = "application-activation-pending.json"
VERIFIED = "application-activation-verified.json"
COMPLETE = "application-activation-complete.json"
SELECTOR_SCHEMA = "marty.kubernetes-application-current/v1"
PENDING_SCHEMA = "marty.kubernetes-application-activation-pending/v1"
VERIFIED_SCHEMA = "marty.kubernetes-application-activation-verified/v1"
COMPLETE_SCHEMA = "marty.kubernetes-application-activation-completion/v1"
GENERATION_SELECTOR_SCHEMA = "marty.kubernetes-generation-current/v1"
GENERATION_PENDING_SCHEMA = "marty.kubernetes-generation-activation-pending/v1"
RETAINED_INTENT = "generation-activation-intent.json"
RENEWAL_VERIFIED = "renewal-activation-verified.json"
RENEWAL_COMPLETE = "renewal-activation-complete.json"
RENEWAL_VERIFIED_SCHEMA = "marty.kubernetes-renewal-activation-verified/v1"
RENEWAL_COMPLETE_SCHEMA = "marty.kubernetes-renewal-activation-completion/v1"
DOMAINS = {"application", "renewal"}
MAX_RECORD = 262144
REFUSAL = "Kubernetes application selection custody or evidence differs; preserve private state"
PENDING_REFUSAL = "application activation is pending; reconcile the same private attempt"


def require(condition: bool, message: str = REFUSAL) -> None:
    bootstrap.require(condition, message)


def safe_errors(function):
    @wraps(function)
    def checked(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except (OSError, ValueError, KeyError, TypeError, RecursionError):
            raise bootstrap.BootstrapError(REFUSAL) from None
    return checked


def directory_identity(info: os.stat_result) -> tuple[int, ...]:
    return info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode


def file_identity(info: os.stat_result) -> tuple[int, ...]:
    return (*directory_identity(info), info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def canonical_directory(path: Path) -> None:
    require(isinstance(path, Path) and path.is_absolute() and path.resolve(strict=True) == path)


def directory_fd(path: Path) -> int:
    canonical_directory(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        bound_directory(path, descriptor)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def bound_directory(path: Path, descriptor: int) -> tuple[int, ...]:
    canonical_directory(path)
    info = os.fstat(descriptor)
    linked = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == 0o700
            and directory_identity(info) == directory_identity(linked))
    return directory_identity(info)


def owned_directory(path: Path) -> tuple[int, ...]:
    descriptor = directory_fd(path)
    try:
        return bound_directory(path, descriptor)
    finally:
        os.close(descriptor)


def path_value(value: object) -> Path:
    require(isinstance(value, str) and 0 < len(value) <= 4096)
    path = Path(value)
    require(str(path) == value)
    canonical_directory(path)
    return path


@dataclass(frozen=True)
class PrivateFile:
    raw: bytes
    identity: tuple[int, ...]


@dataclass(frozen=True)
class Record:
    raw: bytes
    value: dict
    identity: tuple[int, ...]


def decode(raw: bytes) -> dict:
    try:
        value = json.loads(raw, object_pairs_hook=bootstrap.unique_json_members)
    except (ValueError, UnicodeError):
        raise bootstrap.BootstrapError(REFUSAL) from None
    require(isinstance(value, dict))
    return value


def read_file_at(parent: int, name: str, *, missing: bool = False,
                 allow_empty: bool = False) -> PrivateFile | None:
    require(Path(name).name == name and name not in {"", ".", ".."})
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    except FileNotFoundError:
        if missing:
            return None
        raise
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600
                and (0 if allow_empty else 1) <= before.st_size <= MAX_RECORD)
        raw = stream.read(MAX_RECORD + 1)
        after = os.fstat(stream.fileno())
        linked = os.stat(name, dir_fd=parent, follow_symlinks=False)
        require(len(raw) == before.st_size and len(raw) <= MAX_RECORD
                and file_identity(before) == file_identity(after) == file_identity(linked))
    return PrivateFile(raw, file_identity(after))


def read_at(parent: int, name: str, *, missing: bool = False) -> Record | None:
    result = read_file_at(parent, name, missing=missing)
    return None if result is None else Record(result.raw, decode(result.raw), result.identity)


def write_file_at(parent: int, name: str, raw: bytes) -> PrivateFile:
    require(Path(name).name == name and name not in {"", ".", ".."} and len(raw) <= MAX_RECORD)
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=parent)
    with os.fdopen(descriptor, "wb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.fsync(parent)
    result = read_file_at(parent, name, allow_empty=True)
    require(result is not None and result.raw == raw)
    return result


def sync_file_at(parent: int, name: str, expected: PrivateFile | Record) -> None:
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    try:
        require(file_identity(os.fstat(descriptor)) == expected.identity)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.fsync(parent)
    observed = read_file_at(parent, name)
    require(observed is not None and observed.raw == expected.raw and observed.identity == expected.identity)


def private_record(path: Path) -> Record:
    parent = directory_fd(path.parent)
    try:
        record = read_at(parent, path.name)
        bound_directory(path.parent, parent)
        assert record is not None
        return record
    finally:
        os.close(parent)


@dataclass(frozen=True)
class Selection:
    directory: Path
    activation_id: str | None
    selector: bytes | None
    identity: tuple[int, ...] | None
    directory_identity: tuple[int, ...]
    # The ordinary marker remains distinct from whichever operation selected
    # this generation. Existing application callers continue to use it.
    renewal_activation_id: str | None = None
    generation_activation_id: str | None = None


def activation_domain(value: dict) -> str:
    if value.get("schema") in {SELECTOR_SCHEMA, PENDING_SCHEMA}:
        return "application"
    require(value.get("schema") in {GENERATION_SELECTOR_SCHEMA, GENERATION_PENDING_SCHEMA}
            and value.get("domain") in DOMAINS)
    return value["domain"]


def receipt_names(domain: str) -> tuple[str, str, str, str]:
    require(domain in DOMAINS)
    if domain == "renewal":
        return RENEWAL_VERIFIED, RENEWAL_COMPLETE, RENEWAL_VERIFIED_SCHEMA, RENEWAL_COMPLETE_SCHEMA
    return VERIFIED, COMPLETE, VERIFIED_SCHEMA, COMPLETE_SCHEMA


def valid_identity(value: object, length: int) -> bool:
    return (isinstance(value, list) and len(value) == length
            and all(type(item) is int and item >= 0 for item in value))


def identifier(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", value) is not None


class LockedState:
    def __init__(self, path: Path, descriptor: int):
        self.path = path
        self.descriptor = descriptor
        self.active = True
        self.root_identity = bound_directory(path, descriptor)

    def bound(self) -> None:
        require(self.active and bound_directory(self.path, self.descriptor) == self.root_identity)

    def read(self, name: str, *, missing: bool = False) -> Record | None:
        self.bound()
        result = read_at(self.descriptor, name, missing=missing)
        self.bound()
        return result

    def write_new(self, name: str, value: dict) -> Record:
        self.bound()
        raw = bootstrap.encoded(value)
        require(0 < len(raw) <= MAX_RECORD)
        write_file_at(self.descriptor, name, raw)
        result = self.read(name)
        require(result is not None and result.raw == raw)
        return result

    def renewal_secret_names(self) -> set[str]:
        """Use the retained admitted publication contract, not another inventory."""
        complete = self.read("bootstrap-complete.json")
        require(complete is not None)
        publication = complete.value.get("credentialPublication")
        require(isinstance(publication, dict) and set(publication) == {"schema", "catalog"}
                and publication["schema"] == bootstrap.PUBLICATION_SCHEMA)
        catalog = publication["catalog"]
        require(isinstance(catalog, dict) and isinstance(catalog.get("secrets"), list)
                and 0 < len(catalog["secrets"]) <= 128)
        renewable = {name.upper() for name in set(bootstrap.SELFHOST_TLS_FILES) | bootstrap.KEYCLOAK_FILES
                     if name != "workload_identity_ca_cert"}
        names, selected, covered = set(), set(), set()
        for entry in catalog["secrets"]:
            require(isinstance(entry, dict) and isinstance(entry.get("name"), str)
                    and entry["name"] not in names and isinstance(entry.get("fields"), dict)
                    and entry["fields"])
            names.add(entry["name"])
            inputs = set()
            for field in entry["fields"].values():
                require(isinstance(field, dict))
                if "env" in field:
                    require(isinstance(field["env"], str))
                    if field["env"] in renewable:
                        inputs.add(field["env"])
            if inputs:
                selected.add(entry["name"])
                covered.update(inputs)
        require(len(renewable) == 39 and covered == renewable and len(selected) == 33)
        return selected

    @staticmethod
    def no_foreign_receipts(operation: Path, domain: str) -> None:
        other = "renewal" if domain == "application" else "application"
        verified, complete, _, _ = receipt_names(other)
        parent = directory_fd(operation)
        try:
            for name in (verified, complete):
                require(read_file_at(parent, name, missing=True, allow_empty=True) is None)
            bound_directory(operation, parent)
        finally:
            os.close(parent)

    def proof(self, operation: Path, binding: dict, *, domain: str = "application") -> Record:
        verified, _, schema, _ = receipt_names(domain)
        self.no_foreign_receipts(operation, domain)
        evidence = private_record(operation / verified)
        value = evidence.value
        secret_key = "secrets" if domain == "renewal" else "secret"
        require(set(value) == {
            "schema", "binding", "activationId", "operationDirectory", "candidateDirectory",
            "previousDirectory", "runtime", secret_key, "deployments", "status",
            "credentialDeliveryVerified", "credentialConsumptionVerified",
        })
        status = "secrets-and-rollouts-verified" if domain == "renewal" else "secret-and-rollouts-verified"
        require(value["schema"] == schema and value["binding"] == binding
                and value["status"] == status
                and value["credentialDeliveryVerified"] is True
                and value["credentialConsumptionVerified"] is False
                and isinstance(value["activationId"], str)
                and re.fullmatch(r"[0-9a-f]{32}", value["activationId"]) is not None)
        require(path_value(value["operationDirectory"]) == operation
                and path_value(value["candidateDirectory"]) == operation / "candidate"
                and operation != self.path and not self.path.is_relative_to(operation)
                and not operation.is_relative_to(self.path / "credentials")
                and not operation.is_relative_to(self.path / "application-identity")
                and not operation.is_relative_to(self.path / "renewal-identity"))
        previous = path_value(value["previousDirectory"])
        require(not previous.is_relative_to(operation) and not operation.is_relative_to(previous))
        owned_directory(previous)
        owned_directory(operation / "candidate")
        images = self.read("marty-images.json")
        require(images is not None and isinstance(value["runtime"], dict) and value["runtime"]
                and value["runtime"] == images.value.get("release"))
        required_secrets = self.renewal_secret_names() if domain == "renewal" else {"marty-secrets"}
        secret_values = value["secrets"] if domain == "renewal" else [value["secret"]]
        require(isinstance(secret_values, list) and len(secret_values) == len(required_secrets))
        secret_names, secret_uids = set(), set()
        for secret in secret_values:
            require(isinstance(secret, dict) and set(secret) == {"name", "uid", "resourceVersion"}
                    and isinstance(secret["name"], str) and secret["name"] in required_secrets
                    and secret["name"] not in secret_names and identifier(secret["uid"])
                    and secret["uid"] not in secret_uids and identifier(secret["resourceVersion"]))
            secret_names.add(secret["name"])
            secret_uids.add(secret["uid"])
        require(secret_names == required_secrets)
        deployments = value["deployments"]
        require(isinstance(deployments, list) and 0 < len(deployments) <= 64)
        names, uids, pods = set(), set(), set()
        for deployment in deployments:
            require(isinstance(deployment, dict) and set(deployment) == {
                "name", "uid", "generation", "revision", "podUids",
            })
            name, uid, pod_uids = deployment["name"], deployment["uid"], deployment["podUids"]
            require(isinstance(name, str) and re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,251}[a-z0-9]|[a-z0-9]", name)
                    is not None and name not in names and identifier(uid) and uid not in uids
                    and type(deployment["generation"]) is int and deployment["generation"] > 0
                    and type(deployment["revision"]) is int and deployment["revision"] > 0)
            require(isinstance(pod_uids, list) and 0 < len(pod_uids) <= 256
                    and all(identifier(pod) for pod in pod_uids)
                    and pod_uids == sorted(set(pod_uids)) and not pods.intersection(pod_uids))
            names.add(name)
            uids.add(uid)
            pods.update(pod_uids)
        return evidence

    @staticmethod
    def selector_value(proof: Record, candidate_identity: tuple[int, ...], *,
                       domain: str = "application", previous: Selection | None = None,
                       intent: Record | None = None) -> dict:
        value = proof.value
        result = {
            "schema": SELECTOR_SCHEMA, "binding": value["binding"],
            "activationId": value["activationId"],
            "operationDirectory": value["operationDirectory"],
            "candidateDirectory": value["candidateDirectory"],
            "generationIdentity": list(candidate_identity),
            "verificationIdentity": list(proof.identity), "verification": value,
        }
        if intent is None:
            require(domain == "application" and (previous is None or previous.renewal_activation_id is None))
            return result
        require(previous is not None and activation_domain(intent.value) == domain)
        return {**result, "schema": GENERATION_SELECTOR_SCHEMA, "domain": domain,
                "applicationActivationId": value["activationId"] if domain == "application" else previous.activation_id,
                "renewalActivationId": value["activationId"] if domain == "renewal" else previous.renewal_activation_id,
                "intentIdentity": list(intent.identity)}

    def selection(self, binding: dict, record: Record | None, *, complete: bool,
                  _seen: frozenset[Path] = frozenset()) -> Selection:
        if record is None:
            path = self.path / "credentials"
            return Selection(path, None, None, None, owned_directory(path))
        value = record.value
        modern = value.get("schema") == GENERATION_SELECTOR_SCHEMA
        fields = {"schema", "binding", "activationId", "operationDirectory", "candidateDirectory",
                  "generationIdentity", "verificationIdentity", "verification"}
        if modern:
            fields.update({"domain", "applicationActivationId", "renewalActivationId", "intentIdentity"})
        require(set(value) == fields and value["schema"] in {SELECTOR_SCHEMA, GENERATION_SELECTOR_SCHEMA}
                and value["binding"] == binding)
        domain = activation_domain(value)
        operation = path_value(value["operationDirectory"])
        require(operation not in _seen)
        proof = self.proof(operation, binding, domain=domain)
        candidate = operation / "candidate"
        candidate_identity = owned_directory(candidate)
        intent, previous = None, None
        if modern:
            intent = private_record(operation / RETAINED_INTENT)
            require(intent.value.get("schema") == GENERATION_PENDING_SCHEMA
                    and intent.value.get("operationDirectory") == str(operation)
                    and intent.value.get("activationId") == proof.value["activationId"]
                    and activation_domain(intent.value) == domain)
            previous = self.validate_intent(binding, intent, _seen=_seen | {operation})
            require(proof.value["previousDirectory"] == str(previous.directory)
                    and list(candidate_identity) == intent.value["candidateIdentity"])
        else:
            parent = directory_fd(operation)
            try:
                require(read_file_at(parent, RETAINED_INTENT, missing=True, allow_empty=True) is None)
            finally:
                os.close(parent)
        require(value == self.selector_value(proof, candidate_identity, domain=domain,
                                             previous=previous, intent=intent))
        if complete:
            _, completion_name, _, completion_schema = receipt_names(domain)
            completion = private_record(operation / completion_name)
            require(completion.value == {
                **proof.value, "schema": completion_schema, "status": domain + "-generation-selected",
            })
        return Selection(candidate, value["applicationActivationId"] if modern else value["activationId"],
                         record.raw, record.identity, candidate_identity,
                         value["renewalActivationId"] if modern else None, value["activationId"])

    def validate_intent(self, binding: dict, record: Record, *,
                        _seen: frozenset[Path] = frozenset()) -> Selection:
        value = record.value
        modern = value.get("schema") == GENERATION_PENDING_SCHEMA
        fields = {"schema", "binding", "activationId", "operationDirectory", "candidateDirectory",
                  "currentDirectory", "expectedSelector", "expectedSelectorIdentity",
                  "currentIdentity", "candidateIdentity", "operationIdentity"}
        if modern:
            fields.update({"domain", "previousApplicationActivationId", "previousRenewalActivationId"})
        require(set(value) == fields and value["schema"] in {PENDING_SCHEMA, GENERATION_PENDING_SCHEMA}
                and value["binding"] == binding and isinstance(value["activationId"], str)
                and re.fullmatch(r"[0-9a-f]{32}", value["activationId"]) is not None)
        domain = activation_domain(value)
        operation = path_value(value["operationDirectory"])
        candidate = path_value(value["candidateDirectory"])
        current = path_value(value["currentDirectory"])
        require(candidate == operation / "candidate" and not operation.is_relative_to(current)
                and not current.is_relative_to(operation) and operation != self.path
                and not self.path.is_relative_to(operation)
                and not operation.is_relative_to(self.path / "credentials")
                and not operation.is_relative_to(self.path / "application-identity")
                and not operation.is_relative_to(self.path / "renewal-identity"))
        self.no_foreign_receipts(operation, domain)
        for path, key in ((operation, "operationIdentity"), (candidate, "candidateIdentity"),
                          (current, "currentIdentity")):
            require(valid_identity(value[key], 5) and tuple(value[key]) == owned_directory(path))
        previous, identity = value["expectedSelector"], value["expectedSelectorIdentity"]
        require((previous is None and identity is None)
                or (isinstance(previous, str) and 0 < len(previous.encode()) <= MAX_RECORD
                    and valid_identity(identity, 9)))
        predecessor = None if previous is None else Record(
            previous.encode(), decode(previous.encode()), tuple(identity))
        selection = self.selection(binding, predecessor, complete=True, _seen=_seen | {operation})
        require(str(selection.directory) == value["currentDirectory"]
                and list(selection.directory_identity) == value["currentIdentity"]
                and value["activationId"] not in {selection.activation_id, selection.renewal_activation_id,
                                                 selection.generation_activation_id})
        if modern:
            require(value["previousApplicationActivationId"] == selection.activation_id
                    and value["previousRenewalActivationId"] == selection.renewal_activation_id)
        else:
            require(selection.renewal_activation_id is None)
            parent = directory_fd(operation)
            try:
                require(read_file_at(parent, RETAINED_INTENT, missing=True, allow_empty=True) is None)
            finally:
                os.close(parent)
        return selection

    def pending_record(self, binding: dict) -> Record | None:
        binding = bootstrap.application_binding(binding)
        record = self.read(PENDING, missing=True)
        if record is None:
            return None
        self.validate_intent(binding, record)
        if record.value["schema"] == GENERATION_PENDING_SCHEMA:
            operation = path_value(record.value["operationDirectory"])
            retained = private_record(operation / RETAINED_INTENT)
            require(retained.raw == record.raw)
        return record

    @safe_errors
    def pending(self, binding: dict, operation: Path | None = None, *,
                domain: str = "application") -> dict | None:
        receipt_names(domain)
        record = self.pending_record(binding)
        if record is not None and operation is not None:
            require(path_value(record.value["operationDirectory"]) == operation
                    and activation_domain(record.value) == domain, PENDING_REFUSAL)
        return None if record is None else record.value

    def previous_selection(self, binding: dict, intent: Record) -> Selection:
        return self.validate_intent(binding, intent)

    @safe_errors
    def current(self, binding: dict, *, pending_operation: Path | None = None,
                domain: str = "application") -> Selection:
        receipt_names(domain)
        binding = bootstrap.application_binding(binding)
        intent = self.pending_record(binding)
        if intent is None:
            require(pending_operation is None, PENDING_REFUSAL)
            return self.selection(binding, self.read(SELECTOR, missing=True), complete=True)
        require(pending_operation is not None and activation_domain(intent.value) == domain
                and intent.value["operationDirectory"] == str(pending_operation), PENDING_REFUSAL)
        previous = self.previous_selection(binding, intent)
        observed = self.selection(binding, self.read(SELECTOR, missing=True), complete=False)
        if observed.selector == previous.selector:
            require(observed == previous)
        else:
            proof = self.proof(pending_operation, binding, domain=domain)
            require(proof.value["activationId"] == intent.value["activationId"]
                    and proof.value["previousDirectory"] == intent.value["currentDirectory"]
                    and observed.directory == pending_operation / "candidate"
                    and observed.generation_activation_id == intent.value["activationId"])
        return previous

    @safe_errors
    def require_current(self, binding: dict, *, expected: Selection) -> None:
        require(self.current(binding) == expected, "selected application generation changed")

    @safe_errors
    def begin(self, binding: dict, operation: Path, candidate: Path, activation_id: str,
              *, expected: Selection, domain: str = "application") -> dict:
        receipt_names(domain)
        binding = bootstrap.application_binding(binding)
        require(isinstance(activation_id, str) and re.fullmatch(r"[0-9a-f]{32}", activation_id) is not None
                and activation_id not in {expected.activation_id, expected.renewal_activation_id,
                                          expected.generation_activation_id})
        require(candidate == operation / "candidate" and not operation.is_relative_to(expected.directory)
                and not expected.directory.is_relative_to(operation) and operation != self.path
                and not self.path.is_relative_to(operation)
                and not operation.is_relative_to(self.path / "credentials")
                and not operation.is_relative_to(self.path / "application-identity")
                and not operation.is_relative_to(self.path / "renewal-identity"))
        self.no_foreign_receipts(operation, domain)
        modern = domain == "renewal" or expected.renewal_activation_id is not None
        value = {
            "schema": PENDING_SCHEMA, "binding": binding, "activationId": activation_id,
            "operationDirectory": str(operation), "candidateDirectory": str(candidate),
            "currentDirectory": str(expected.directory),
            "expectedSelector": None if expected.selector is None else expected.selector.decode(),
            "expectedSelectorIdentity": None if expected.identity is None else list(expected.identity),
            "currentIdentity": list(expected.directory_identity),
            "candidateIdentity": list(owned_directory(candidate)),
            "operationIdentity": list(owned_directory(operation)),
        }
        if modern:
            value.update({"schema": GENERATION_PENDING_SCHEMA, "domain": domain,
                          "previousApplicationActivationId": expected.activation_id,
                          "previousRenewalActivationId": expected.renewal_activation_id})
        existing = self.pending_record(binding)
        if existing is not None:
            require(existing.value == value, PENDING_REFUSAL)
            require(self.current(binding, pending_operation=operation, domain=domain) == expected)
            sync_file_at(self.descriptor, PENDING, existing)
            require(self.pending_record(binding) == existing)
            return existing.value
        self.require_current(binding, expected=expected)
        parent = directory_fd(operation)
        try:
            retained = read_at(parent, RETAINED_INTENT, missing=True)
            if modern:
                raw = bootstrap.encoded(value)
                if retained is None:
                    write_file_at(parent, RETAINED_INTENT, raw)
                else:
                    require(retained.raw == raw)
                    sync_file_at(parent, RETAINED_INTENT, retained)
                require(bound_directory(operation, parent) == tuple(value["operationIdentity"]))
            else:
                require(retained is None)
        finally:
            os.close(parent)
        record = self.write_new(PENDING, value)
        require(self.pending_record(binding) == record)
        return value

    @safe_errors
    def publish(self, binding: dict, operation: Path, *, expected: Selection,
                domain: str = "application") -> None:
        receipt_names(domain)
        binding = bootstrap.application_binding(binding)
        intent = self.pending_record(binding)
        require(intent is not None and intent.value["operationDirectory"] == str(operation)
                and activation_domain(intent.value) == domain, PENDING_REFUSAL)
        require(self.current(binding, pending_operation=operation, domain=domain) == expected)
        proof = self.proof(operation, binding, domain=domain)
        require(proof.value["activationId"] == intent.value["activationId"]
                and proof.value["previousDirectory"] == str(expected.directory))
        retained = (private_record(operation / RETAINED_INTENT)
                    if intent.value["schema"] == GENERATION_PENDING_SCHEMA else None)
        require(retained is None or retained.raw == intent.raw)
        value = self.selector_value(proof, tuple(intent.value["candidateIdentity"]),
                                    domain=domain, previous=expected, intent=retained)
        raw = bootstrap.encoded(value)
        old = self.read(SELECTOR, missing=True)
        if old is not None and old.raw == raw:
            # The previous process may have stopped after publication. The same
            # immutable proof and private pending intent make this idempotent.
            self.selection(binding, old, complete=False)
            os.fsync(self.descriptor)
            return
        require((None if old is None else old.raw) == expected.selector
                and (None if old is None else old.identity) == expected.identity)
        temporary = "application-current-" + secrets.token_hex(16) + ".tmp"
        written = self.write_new(temporary, value)
        # As in the native generation owner, retain the predecessor and compare
        # its bytes and inode at the publication boundary. Directory flock is
        # held throughout; uncoordinated writers are outside this adapter's
        # single-writer contract and observed drift always refuses completion.
        require(self.pending_record(binding) == intent
                and self.proof(operation, binding, domain=domain) == proof)
        require(self.read(SELECTOR, missing=True) == old)
        self.bound()
        os.replace(temporary, SELECTOR, src_dir_fd=self.descriptor, dst_dir_fd=self.descriptor)
        os.fsync(self.descriptor)
        published = self.read(SELECTOR)
        require(published is not None and published.raw == written.raw
                and published.identity[:7] == written.identity[:7])
        self.selection(binding, published, complete=False)
        require(self.pending_record(binding) == intent)

    @safe_errors
    def complete(self, binding: dict, operation: Path, *, domain: str = "application") -> dict:
        """Durably complete this selection, retaining an exact interrupted prefix."""
        _, completion_name, _, completion_schema = receipt_names(domain)
        binding = bootstrap.application_binding(binding)
        intent = self.pending_record(binding)
        require(intent is not None and intent.value["operationDirectory"] == str(operation)
                and activation_domain(intent.value) == domain, PENDING_REFUSAL)
        selector = self.read(SELECTOR)
        selected = self.selection(binding, selector, complete=False)
        proof = self.proof(operation, binding, domain=domain)
        require(selected.directory == operation / "candidate"
                and selected.generation_activation_id == intent.value["activationId"]
                and proof.value["previousDirectory"] == intent.value["currentDirectory"])
        value = {**proof.value, "schema": completion_schema, "status": domain + "-generation-selected"}
        raw = bootstrap.encoded(value)
        parent = directory_fd(operation)
        try:
            previous = read_file_at(parent, completion_name, missing=True, allow_empty=True)
            if previous is not None and previous.raw == raw:
                sync_file_at(parent, completion_name, previous)
            else:
                if previous is not None:
                    require(len(previous.raw) < len(raw) and raw.startswith(previous.raw))
                    backup = domain + "-activation-complete-interrupted-" + secrets.token_hex(16) + ".partial"
                    write_file_at(parent, backup, previous.raw)
                temporary = domain + "-activation-complete-" + secrets.token_hex(16) + ".tmp"
                written = write_file_at(parent, temporary, raw)
                require(self.pending_record(binding) == intent
                        and self.proof(operation, binding, domain=domain) == proof
                        and self.read(SELECTOR) == selector)
                require(read_file_at(parent, completion_name, missing=True, allow_empty=True) == previous)
                require(bound_directory(operation, parent) == tuple(intent.value["operationIdentity"]))
                os.replace(temporary, completion_name, src_dir_fd=parent, dst_dir_fd=parent)
                os.fsync(parent)
                completed = read_file_at(parent, completion_name)
                require(completed is not None and completed.raw == raw
                        and completed.identity[:7] == written.identity[:7])
            require(bound_directory(operation, parent) == tuple(intent.value["operationIdentity"]))
            require(self.pending_record(binding) == intent
                    and self.proof(operation, binding, domain=domain) == proof
                    and self.read(SELECTOR) == selector)
            self.selection(binding, selector, complete=True)
            return value
        finally:
            os.close(parent)

    @safe_errors
    def finish(self, binding: dict, operation: Path, *, domain: str = "application",
               check_deadline: Callable[[], object] | None = None) -> None:
        """Clear pending only after durable selection still meets the caller's budget.

        Local history validation and directory sync can consume the remaining
        activation lifetime. Keep the shared lock while restoring the exact
        pending intent after any post-unlink failure, including budget expiry.
        """
        receipt_names(domain)
        binding = bootstrap.application_binding(binding)
        intent = self.pending_record(binding)
        require(intent is not None and intent.value["operationDirectory"] == str(operation)
                and activation_domain(intent.value) == domain, PENDING_REFUSAL)
        selected = self.selection(binding, self.read(SELECTOR, missing=True), complete=True)
        require(selected.directory == operation / "candidate"
                and selected.generation_activation_id == intent.value["activationId"])
        proof = self.proof(operation, binding, domain=domain)
        require(proof.value["previousDirectory"] == intent.value["currentDirectory"]
                and self.pending_record(binding) == intent)
        self.bound()
        if check_deadline is not None:
            check_deadline()
        os.unlink(PENDING, dir_fd=self.descriptor)
        try:
            os.fsync(self.descriptor)
            require(self.read(PENDING, missing=True) is None)
            require(self.current(binding) == selected)
            if check_deadline is not None:
                check_deadline()
        except BaseException:
            self.bound()
            observed = self.read(PENDING, missing=True)
            if observed is None:
                write_file_at(self.descriptor, PENDING, intent.raw)
            else:
                require(observed.raw == intent.raw)
                sync_file_at(self.descriptor, PENDING, observed)
            restored = self.read(PENDING)
            require(restored is not None and restored.raw == intent.raw)
            raise


@safe_errors
def acquire(state_dir: Path) -> LockedState:
    require(os.name == "posix", "Kubernetes application state requires a POSIX operator host")
    import fcntl

    descriptor = directory_fd(state_dir)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise bootstrap.BootstrapError("another Kubernetes application operation holds this private state") from None
        return LockedState(state_dir, descriptor)
    except BaseException:
        os.close(descriptor)
        raise


@contextmanager
def locked(state_dir: Path):
    """Serialize local staging/activation using the retained directory inode."""
    state = acquire(state_dir)
    try:
        yield state
    finally:
        state.active = False
        os.close(state.descriptor)
