"""Closed MDOC operator configuration delta; no execution authority on import.

The private production operator supplies hash-bound shared transport, journal,
ACL, created-container and runtime readers. This module never invokes Docker,
reads secret contents, grants operator authority, or qualifies a release.
"""

from copy import deepcopy
import json
import ipaddress
import re
import unicodedata
from urllib.parse import urlsplit
from uuid import UUID

from scoped_native_runtime import daemon_source, require

ROLES = frozenset(("gateway", "signing-keys"))
NAMES = ("mdoc_iaca_issue_gateway_key", "mdoc_dsc_issue_gateway_key")
PUBLIC = "SIGNING_KEYS_MDOC_CERTIFICATE_AUTHORITIES_JSON"


def variable(name):
    return "SIGNING_KEYS_" + name.upper()


def _object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "DUPLICATE_PUBLIC_JSON_KEY")
        result[key] = value
    return result


def _public_host(host):
    """Conservative literal IP/ASCII DNS subset of the runtime URL parser.

    urllib splits authorities without validating URL host syntax. Do not accept
    percent escapes, scoped IPs, ambiguous numeric hosts or invalid A-labels as
    proof that reqwest::Url will parse the signer configuration at startup.
    """
    require(
        isinstance(host, str) and host and "%" not in host, "PUBLIC_URI_HOST_REQUIRED"
    )
    if ":" in host:
        ipaddress.IPv6Address(host)
        return
    labels = host.rstrip(".").split(".")
    require(
        len(host.rstrip(".")) <= 253
        and all(
            re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", part)
            for part in labels
        ),
        "PUBLIC_URI_HOST_REQUIRED",
    )
    if re.fullmatch(r"(?:[0-9]+|0[xX][0-9a-fA-F]+)", labels[-1]):
        ipaddress.IPv4Address(host)
    for label in labels:
        if label.lower().startswith("xn--"):
            try:
                require(
                    label.encode("ascii").decode("idna").encode("idna").decode("ascii")
                    == label.lower(),
                    "PUBLIC_URI_HOST_REQUIRED",
                )
            except UnicodeError as error:
                raise ValueError("PUBLIC_URI_HOST_REQUIRED") from error


def authorities(raw):
    if raw is None:
        return []
    require(
        isinstance(raw, str) and len(raw.encode("utf-8")) <= 262144,
        "BOUNDED_PUBLIC_AUTHORITY_JSON_REQUIRED",
    )
    rows = json.loads(raw, object_pairs_hook=_object)
    require(
        isinstance(rows, list) and len(rows) <= 128, "PUBLIC_AUTHORITY_ARRAY_REQUIRED"
    )
    seen = set()
    for row in rows:
        require(
            isinstance(row, dict)
            and set(row) == {"organization_id", "issuer_did", "certificate"},
            "TYPED_PUBLIC_AUTHORITY_REQUIRED",
        )
        org, did = row["organization_id"], row["issuer_did"]
        require(
            isinstance(org, str) and str(UUID(org)) == org,
            "CANONICAL_ORGANIZATION_REQUIRED",
        )
        require(
            isinstance(did, str)
            and did.startswith("did:")
            and len(did.encode("utf-8")) <= 2048
            and not any(unicodedata.category(c) == "Cc" for c in did),
            "ISSUER_DID_REQUIRED",
        )
        key = (org, did)
        require(key not in seen, "DUPLICATE_PUBLIC_AUTHORITY")
        seen.add(key)
        cert = row["certificate"]
        require(
            isinstance(cert, dict)
            and set(cert) == {"issuer_contact_uri", "crl_distribution_uri"},
            "TYPED_PUBLIC_CERTIFICATE_METADATA_REQUIRED",
        )
        for uri in cert.values():
            require(
                isinstance(uri, str)
                and uri.isascii()
                and len(uri) <= 2048
                and not any(ord(c) <= 32 or ord(c) == 127 for c in uri),
                "PUBLIC_URI_REQUIRED",
            )
            parsed = urlsplit(uri)
            _public_host(parsed.hostname)
            require(
                parsed.scheme in ("http", "https")
                and parsed.hostname
                and "@" not in parsed.netloc
                and "\\" not in uri
                and (parsed.port is None or 1 <= parsed.port <= 65535)
                and "?" not in uri
                and "#" not in uri,
                "PUBLIC_URI_REQUIRED",
            )
    return rows


def merged_authorities(existing, additions):
    """Preserve all existing rows; reject collision rather than replace authority."""
    old = authorities(existing)
    new = authorities(json.dumps(additions, separators=(",", ":")))
    require(
        len(new) == 2 and len({r["organization_id"] for r in new}) == 1,
        "EXACT_TWO_OWNED_IACAS_REQUIRED",
    )
    require(
        not (
            {(r["organization_id"], r["issuer_did"]) for r in old}
            & {(r["organization_id"], r["issuer_did"]) for r in new}
        ),
        "EXISTING_OWNED_AUTHORITY_COLLISION",
    )
    raw = json.dumps(old + new, sort_keys=True, separators=(",", ":"))
    authorities(raw)
    return raw


def binding_contract(bindings):
    require(
        isinstance(bindings, dict) and set(bindings) == set(NAMES),
        "EXACT_TWO_OPERATOR_BINDINGS_REQUIRED",
    )
    digests = set()
    sources = set()
    for name, bound in bindings.items():
        require(
            isinstance(bound, dict)
            and set(bound) == {"path", "sha256", "bytes"}
            and bound["bytes"] == 64
            and re.fullmatch(r"[a-f0-9]{64}", bound["sha256"]),
            "EXACT_OPERATOR_FILE_REF_REQUIRED",
        )
        sources.add(daemon_source(bound["path"]))
        digests.add(bound["sha256"])
    require(len(sources) == len(digests) == 2, "DISTINCT_OPERATOR_FILES_REQUIRED")


def _mounts(rows):
    require(
        isinstance(rows, list)
        and all(isinstance(r, dict) and "target" in r for r in rows),
        "COMPOSE_MOUNT_ARRAY_REQUIRED",
    )
    result = {r["target"]: r for r in rows}
    require(len(result) == len(rows), "DUPLICATE_MOUNT_TARGET")
    return result


def overlay(before, bindings, additions):
    """Build the only permitted Compose overlay; file custody is host-operator work."""
    binding_contract(bindings)
    require(ROLES.issubset(before["services"]), "MDOC_RUNTIME_ROLES_REQUIRED")
    services = {}
    for role in sorted(ROLES):
        prior = before["services"][role]
        env = prior.get("environment", {})
        require(isinstance(env, dict), "COMPOSE_ENVIRONMENT_MAP_REQUIRED")
        mounts = _mounts(prior.get("volumes", []))
        for name in NAMES:
            require(
                variable(name) not in env and variable(name) + "_FILE" not in env,
                "OPERATOR_ALREADY_CONFIGURED",
            )
            require(
                "/run/secrets/" + name not in mounts,
                "OPERATOR_MOUNT_ALREADY_CONFIGURED",
            )
        new_env = {variable(n) + "_FILE": "/run/secrets/" + n for n in NAMES}
        if role == "signing-keys":
            new_env[PUBLIC] = merged_authorities(env.get(PUBLIC), additions)
        services[role] = {
            "environment": new_env,
            "volumes": [
                {
                    "type": "bind",
                    "source": bindings[n]["path"],
                    "target": "/run/secrets/" + n,
                    "read_only": True,
                    "bind": {"create_host_path": False},
                }
                for n in NAMES
            ],
        }
    return {"services": services}


def validate_delta(before, after, bindings, additions):
    expected = overlay(before, bindings, additions)
    require(
        set(before) == set(after)
        and {k: v for k, v in before.items() if k != "services"}
        == {k: v for k, v in after.items() if k != "services"},
        "PROJECT_SETTINGS_CHANGED",
    )
    require(set(before["services"]) == set(after["services"]), "SERVICE_SET_CHANGED")
    for role, service in before["services"].items():
        old, actual = deepcopy(service), deepcopy(after["services"][role])
        if role in ROLES:
            wanted = expected["services"][role]
            require(
                actual.pop("environment", {})
                == {**old.pop("environment", {}), **wanted["environment"]},
                "UNAPPROVED_ENVIRONMENT_DELTA",
            )
            a, b = _mounts(old.pop("volumes", [])), _mounts(actual.pop("volumes", []))
            new = _mounts(wanted["volumes"])
            require(set(b) == set(a) | set(new), "UNAPPROVED_MOUNT_SET")
            require(all(b[k] == v for k, v in a.items()), "EXISTING_MOUNT_CHANGED")
            for target, wanted_mount in new.items():
                found = deepcopy(b[target])
                wanted_mount = deepcopy(wanted_mount)
                found["source"] = daemon_source(found["source"])
                wanted_mount["source"] = daemon_source(wanted_mount["source"])
                require(found == wanted_mount, "UNAPPROVED_OPERATOR_MOUNT")
        require(old == actual, "UNRELATED_SERVICE_SETTINGS_CHANGED:" + role)
    return {
        "roles": sorted(ROLES),
        "newOperatorFiles": 2,
        "newIacaMetadataRows": 2,
        "releaseQualified": False,
        "recordingQualified": False,
    }


def peel_inspect_environment(before, actual, role, additions):
    """Validate, then remove only new env from a copy for the existing strict checker.

    This is deliberately not a container acceptance function: the caller must
    separately prove exact mounts, Config/HostConfig/network/provenance and
    immutable executable with the existing production created/readback checker.
    """
    require(role in ROLES, "MDOC_RUNTIME_ROLE_REQUIRED")

    def parse(rows):
        require(
            isinstance(rows, list)
            and all(isinstance(s, str) and "=" in s for s in rows),
            "INSPECT_ENVIRONMENT_ARRAY_REQUIRED",
        )
        pairs = [s.split("=", 1) for s in rows]
        result = dict(pairs)
        require(len(result) == len(pairs), "DUPLICATE_ENVIRONMENT_KEY")
        return result

    old, new = parse(before), parse(actual)
    require(
        all(variable(n) not in old and variable(n) + "_FILE" not in old for n in NAMES),
        "OPERATOR_ALREADY_CONFIGURED",
    )
    expected = {**old, **{variable(n) + "_FILE": "/run/secrets/" + n for n in NAMES}}
    if role == "signing-keys":
        expected[PUBLIC] = merged_authorities(old.get(PUBLIC), additions)
    require(new == expected, "UNAPPROVED_RUNTIME_ENVIRONMENT_DELTA")
    return list(before)


def daemon_mount_map(rows):
    require(isinstance(rows, list), "INSPECT_MOUNT_ARRAY_REQUIRED")
    parsed = {}
    for row in rows:
        require(
            isinstance(row, dict)
            and isinstance(row.get("Destination"), str)
            and row["Destination"].startswith("/")
            and row["Destination"] not in parsed,
            "CLOSED_UNIQUE_DAEMON_MOUNTS_REQUIRED",
        )
        parsed[row["Destination"]] = row
    return parsed


def named_volume(source, observed):
    require(
        isinstance(source, str)
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", source)
        and observed.get("Type") == "volume"
        and observed.get("Name") == source,
        "EXACT_EXISTING_NAMED_VOLUME_REQUIRED",
    )
    return source


def bind_map(rows, mounts):
    """Typed Binds: retain named volumes, normalize only actual bind paths."""
    require(isinstance(rows, list), "HOST_BIND_ARRAY_REQUIRED")
    parsed = {}
    for bind in rows:
        require(isinstance(bind, str), "HOST_BIND_STRING_REQUIRED")
        parts = bind.rsplit(":", 2)
        require(
            len(parts) == 3 and parts[1] not in parsed and parts[1] in mounts,
            "CLOSED_UNIQUE_HOST_BINDS_REQUIRED",
        )
        source, target, mode = parts
        observed = mounts[target]
        require(
            isinstance(mode, str)
            and re.fullmatch(r"[A-Za-z0-9_,.-]+", mode)
            and type(observed.get("RW")) is bool
            and observed["RW"] == ("ro" not in mode.split(",")),
            "HOST_BIND_READONLY_CHANGED",
        )
        if observed.get("Type") == "bind":
            source = daemon_source(source)
            require(
                source == daemon_source(observed["Source"]),
                "HOST_BIND_SOURCE_CHANGED",
            )
        else:
            source = named_volume(source, observed)
        parsed[target] = (observed["Type"], source, mode)
    return parsed


def host_mount_map(rows, mounts):
    require(isinstance(rows, list), "HOST_MOUNT_ARRAY_REQUIRED")
    parsed = {}
    for row in rows:
        require(
            isinstance(row, dict)
            and isinstance(row.get("Target"), str)
            and row["Target"] in mounts
            and row["Target"] not in parsed
            and type(row.get("ReadOnly")) is bool,
            "CLOSED_UNIQUE_HOST_MOUNTS_REQUIRED",
        )
        target = row["Target"]
        observed = mounts[target]
        require(
            row.get("Type") == observed.get("Type")
            and type(observed.get("RW")) is bool
            and row["ReadOnly"] is (not observed["RW"]),
            "HOST_MOUNT_TYPE_OR_READONLY_CHANGED",
        )
        normalized = deepcopy(row)
        if row["Type"] == "bind":
            normalized["Source"] = daemon_source(row["Source"])
            require(
                normalized["Source"] == daemon_source(observed["Source"]),
                "HOST_MOUNT_SOURCE_CHANGED",
            )
        else:
            normalized["Source"] = named_volume(row.get("Source"), observed)
        # Preserve every option and metadata field on retained mounts.
        parsed[target] = normalized
    return parsed


def host_mounts(inspect):
    mounts = daemon_mount_map(inspect["Mounts"])
    host = inspect["HostConfig"]
    binds = bind_map(host.get("Binds") or [], mounts)
    api = host_mount_map(host.get("Mounts") or [], mounts)
    require(not set(binds) & set(api), "DUPLICATE_HOST_MOUNT_REPRESENTATION")
    require(
        set(binds) | set(api) == set(mounts),
        "COMPLETE_HOST_MOUNT_REPRESENTATIONS_REQUIRED",
    )
    return binds, api


def peel_validated_inspect(before, actual, role, bindings, additions):
    """Remove validated additions for an independent existing strict checker.

    All Config/HostConfig fields outside these exact additions remain in the
    returned document. Docker identity, lifecycle, network and provenance
    differences are left for the existing production checker, never ignored.
    This function alone is not an acceptance receipt.
    """
    binding_contract(bindings)
    result = deepcopy(actual)
    result["Config"]["Env"] = peel_inspect_environment(
        before["Config"]["Env"], actual["Config"]["Env"], role, additions
    )
    targets = {"/run/secrets/" + n: n for n in NAMES}

    old, new = daemon_mount_map(before["Mounts"]), daemon_mount_map(actual["Mounts"])
    require(
        not set(old) & set(targets) and set(new) == set(old) | set(targets),
        "EXACT_ADDITIVE_RUNTIME_MOUNTS_REQUIRED",
    )
    for target, name in targets.items():
        row = new[target]
        require(
            set(row) == {"Type", "Source", "Destination", "Mode", "RW", "Propagation"}
            and row["Type"] == "bind"
            and row["RW"] is False
            and row["Mode"] == "ro"
            and row["Propagation"] == "rprivate"
            and daemon_source(row["Source"]) == daemon_source(bindings[name]["path"]),
            "EXACT_READONLY_OPERATOR_RUNTIME_MOUNT_REQUIRED",
        )
    # Existing mounts retain their actual values for the strict checker.
    result["Mounts"] = [m for m in actual["Mounts"] if m["Destination"] not in targets]
    old_binds, old_api = host_mounts(before)
    new_binds, new_api = host_mounts(actual)
    require(old_binds == new_binds, "EXISTING_HOST_BINDS_CHANGED")
    # Compose 5.4.0 create.go bindRequiresMountAPI chooses HostConfig.Mounts
    # when the reviewed long-syntax bind has create_host_path=false. Existing
    # named volumes may remain in Binds; never reinterpret them as host paths.
    require(
        not set(old_api) & set(targets)
        and set(new_api) == set(old_api) | set(targets)
        and all(new_api[k] == v for k, v in old_api.items()),
        "EXACT_ADDITIVE_HOST_API_MOUNTS_REQUIRED",
    )
    for target, name in targets.items():
        require(
            new_api[target]
            == {
                "Type": "bind",
                "Source": daemon_source(bindings[name]["path"]),
                "Target": target,
                "ReadOnly": True,
                "BindOptions": {},
            },
            "EXACT_READONLY_OPERATOR_HOST_API_MOUNT_REQUIRED",
        )
    for key in ("Binds", "Mounts"):
        if key in before["HostConfig"]:
            result["HostConfig"][key] = deepcopy(before["HostConfig"][key])
        else:
            result["HostConfig"].pop(key, None)
    return result


def checked_container(before, actual, role, bindings, additions, strict_checker):
    """Executable seam: the caller must supply the frozen production checker.

    The private wrapper binds checker source SHA and inputs before calling this
    function. A successful return means both the new delta and the original
    complete container contract were checked. No Docker mutation occurs here.
    """
    require(callable(strict_checker), "EXISTING_STRICT_CONTAINER_CHECKER_REQUIRED")
    peeled = peel_validated_inspect(before, actual, role, bindings, additions)
    strict_checker(before, peeled, role)
    return {
        "role": role,
        "operatorMountsValidated": 2,
        "strictContainerCheckerCalled": True,
        "releaseQualified": False,
        "recordingQualified": False,
    }


def checked_rollback_container(before, actual, role, strict_checker):
    """Inverse seam for the existing explicitly requested rollback operation.

    The private wrapper must first pass the existing journal phase/known-outcome
    and ownership gates. This function grants no rollback authority and never
    performs rollback. It prevents the apply-time additions being silently kept
    when the original strict checker validates the restored container.
    """
    require(
        role in ROLES and callable(strict_checker),
        "EXISTING_STRICT_ROLLBACK_CHECKER_REQUIRED",
    )
    forbidden = {variable(n) for n in NAMES} | {variable(n) + "_FILE" for n in NAMES}
    targets = {"/run/secrets/" + n for n in NAMES}
    for row in (before, actual):
        entries = row["Config"]["Env"]
        require(
            isinstance(entries, list)
            and all(isinstance(s, str) and "=" in s for s in entries),
            "INSPECT_ENVIRONMENT_ARRAY_REQUIRED",
        )
        keys = [s.split("=", 1)[0] for s in entries]
        require(
            len(set(keys)) == len(keys) and not set(keys) & forbidden,
            "ROLLBACK_OPERATOR_ENVIRONMENT_RETAINED",
        )
        require(
            not {m["Destination"] for m in row["Mounts"]} & targets,
            "ROLLBACK_OPERATOR_MOUNT_RETAINED",
        )
    # Keep only the already proven Windows/Desktop source equivalence.
    require(
        host_mounts(before) == host_mounts(actual),
        "ROLLBACK_HOST_MOUNT_CONFIGURATION_CHANGED",
    )
    checked = deepcopy(actual)
    for key in ("Binds", "Mounts"):
        if key in before["HostConfig"]:
            checked["HostConfig"][key] = deepcopy(before["HostConfig"][key])
        else:
            checked["HostConfig"].pop(key, None)
    strict_checker(before, checked, role)
    return {
        "role": role,
        "operatorAdditionsAbsent": True,
        "strictContainerCheckerCalled": True,
        "releaseQualified": False,
        "recordingQualified": False,
    }
