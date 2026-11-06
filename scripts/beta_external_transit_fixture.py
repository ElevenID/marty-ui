"""D02/D10 scoped Transit custody using the existing beta TLS/API authority.

This provisions test custody, not fixture, demo, release or wallet qualification.
No provider bootstrap, private-key export, Docker-by-name operation or legacy
runtime receipt is used. The incoming historical producer remains immutable.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid

OWNER_SHA = "9fdce7f6956b30abb99aced66cef84a3beffb6bac6ff65898afe5425bf4b82be"
JOB_SHA = "d3966eb82abdf9b9f7e8fb36f2ff0577c15bc2600c0b2bdc8eac34fd6729fdf8"
SCHEMA = "marty.beta-external-transit-fixture/v1"
MEMORY = 1024**3
MAX_TTL = 3600


class FixtureError(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise FixtureError(code)


def sha(file):
    with Path(file).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def bound(ref):
    file = Path(ref["path"])
    require(file.is_absolute() and file.is_file() and not file.is_symlink(), "INPUT_PATH_CHANGED")
    require(sha(file) == ref["sha256"], "INPUT_HASH_CHANGED")
    if "bytes" in ref:
        require(file.stat().st_size == ref["bytes"], "INPUT_SIZE_CHANGED")
    return file


def load(ref):
    return json.loads(bound(ref).read_bytes().removeprefix(b"\xef\xbb\xbf"))


def encoded(value):
    return value if isinstance(value, bytes) else (json.dumps(value, sort_keys=True) + "\n").encode()


def durable_new(file, value):
    data = encoded(value)
    fd = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        require(stream.write(data) == len(data), "CUSTODY_SHORT_WRITE")
        stream.flush()
        os.fsync(stream.fileno())


def scenario_for_key(key):
    match = re.fullmatch(r"(d02|d10)-external-[a-z0-9-]{1,100}", key)
    require(match is not None, "OWNED_KEY_NAME_REQUIRED")
    return match.group(1).upper()


def policy_text(key):
    # The shared D02/D10 policy contract from the existing producer is unchanged.
    scenario = scenario_for_key(key)
    rules = (f'path "transit/keys/{key}" {{ capabilities = ["read"] }}\n'
             f'path "transit/sign/{key}" {{ capabilities = ["update"] }}\n')
    if scenario == "D02":
        rules += f'path "transit/keys/{key}-unpublished" {{ capabilities = ["read"] }}'
    return rules


def load_owner(ref):
    require(ref["sha256"] == OWNER_SHA, "AUTHORITY_OWNER_CHANGED")
    spec = importlib.util.spec_from_file_location("bound_beta_service_authority", bound(ref))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# This static adapter calls the existing full native verifier. No replacement
# observer, cached success flag, native mount policy or runtime proof is invented.
NATIVE_GUARD = r"""
const fs=require('fs'),assert=require('assert/strict'),crypto=require('crypto');
const c=JSON.parse(fs.readFileSync(0,'utf8')),r=c.runtime;
const hash=p=>crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
const binding=require(r.recorderRepository+'/src/externalQualification');
binding.assertSourceBinding(r.recorderRepository,r.recorderRevision);
for(const ref of Object.values(r.sourceFiles))assert.equal(hash(ref.path),ref.sha256);
for(const ref of [r.observation,r.profile,r.dockerTransport,r.dockerCanary])assert.equal(hash(ref.path),ref.sha256);
const transport=require(r.recorderRepository+'/src/canvasDockerTransport');
process.env[transport.ENV]=r.dockerTransport.path;process.env[transport.ENV+'_SHA256']=r.dockerTransport.sha256;
process.env[transport.CANARY_ENV]=r.dockerCanary.path;process.env[transport.CANARY_ENV+'_SHA256']=r.dockerCanary.sha256;
if(c.protectOutput)require(r.recorderRepository+'/src/ownedNativeWallet').protectOwnedDirectory(c.protectOutput,require('path').dirname(c.protectOutput));
const actual=require(r.recorderRepository+'/src/localNativeLiveBinding').verifyFunctionalLiveBinding({receipt:r.observation.path,sha256:r.observation.sha256,profile:r.profile.path,functionalRerun:true,origin:'https://beta.elevenidllc.com',imageSourceId:r.imageSourceId});
assert.equal(actual.binding.roles.length,22);
console.log(JSON.stringify({state:'CURRENT_NATIVE_22_LIVE_VERIFIED',profileSha256:r.profile.sha256,receiptSha256:r.observation.sha256,driver:actual.driver,bindingSha256:crypto.createHash('sha256').update(JSON.stringify(actual.binding)).digest('hex'),roles:22}));
"""


def native_guard(config, *, protect_output=None):
    runtime = config["runtime"]
    node = bound(runtime["nodeExecutable"])
    observed = subprocess.run([str(node), "-e", NATIVE_GUARD],
                              input=json.dumps({"runtime": runtime, "protectOutput": str(protect_output) if protect_output else None}).encode(),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600, check=False)
    require(observed.returncode == 0 and len(observed.stdout) <= 32768,
            "CURRENT_NATIVE_RUNTIME_REFUSED")
    result = json.loads(observed.stdout)
    require(result.get("state") == "CURRENT_NATIVE_22_LIVE_VERIFIED" and result.get("roles") == 22,
            "CURRENT_NATIVE_RUNTIME_SCHEMA")
    return result


def job_helper(config):
    helper = config["jobHelper"]
    require(helper["sha256"] == JOB_SHA, "JOB_HELPER_CHANGED")
    return bound(helper)


def require_job(config):
    helper = job_helper(config)
    observed = subprocess.run([sys.executable, "-B", str(helper), "--inspect-parent", str(os.getpid())],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, check=False)
    require(observed.returncode == 0 and len(observed.stdout) <= 16384, "GENUINE_JOB_REQUIRED")
    value = json.loads(observed.stdout)
    require(value.get("schema") == "marty.windows-job-observation/v1"
            and value.get("controllerPid") == os.getpid()
            and value.get("controllerMemberVerified") is True and value.get("inspectorMemberVerified") is True
            and value.get("queryOpenedJobHandle") is True and value.get("queryHandleClosed") is True
            and value.get("controllerQueryHandleClosed") is True and value.get("queryAccessMask") == 4
            and value.get("queryHandleInheritable") is False and value.get("jobMemoryBytes") == MEMORY
            and value.get("activeProcessLimit") == 32 and value.get("limitFlags") == 0x2208,
            "GENUINE_JOB_LIMITS_CHANGED")
    return value


def inputs(config, action):
    require(config.get("schema") == SCHEMA and config.get("sourceSha256") == sha(__file__), "OPERATOR_SOURCE_CHANGED")
    require(action in ("provision", "revoke") and config.get("executeAuthorized") is True, "MUTATION_NOT_ARMED")
    job_helper(config)
    require(config.get("scenario") in ("D02", "D10"), "SCENARIO_REQUIRED")
    run = config.get("runId", "")
    require(str(uuid.UUID(run)) == run and uuid.UUID(run).version == 4, "UUID4_REQUIRED")
    output = Path(config["outputDir"])
    private = (Path.home()/".codex/private").resolve()
    require(output.is_absolute() and output.resolve().is_relative_to(private) and output.resolve() != private
            and not output.is_symlink() and output.parent.is_dir(), "PRIVATE_OUTPUT_REQUIRED")
    require(not output.exists() if action == "provision" else output.is_dir(), "OUTPUT_STATE_CHANGED")
    # All runtime inputs are actual refs; do not reinterpret a legacy developer receipt.
    runtime = config["runtime"]
    require(re.fullmatch(r"[a-f0-9]{40}", runtime["recorderRevision"]) is not None, "RECORDER_REVISION_REQUIRED")
    for ref in [runtime["observation"], runtime["profile"], runtime["dockerTransport"], runtime["dockerCanary"],
                runtime["nodeExecutable"], *runtime["sourceFiles"].values()]:
        bound(ref)
    owner = load_owner(config["authorityOwner"])
    # Reuse ONLY its current phase/TLS/recovery input owner. Its svc27 KEY,
    # policy, output, mint, detach and revoke actions are never used or mutated.
    phase, ca, root, _, _ = owner.inputs(load(config["kmsAuthorityInput"]), "preflight")
    return {"config": config, "owner": owner, "phase": phase, "ca": ca, "root": root,
            "output": output, "key": config["scenario"].lower()+"-external-"+run}


def api(ctx, credential, method, route, body=None):
    return ctx["owner"].api(ctx["ca"], credential, method, route, body)


def check_cluster(ctx):
    status, result = api(ctx, ctx["root"], "GET", "/v1/sys/seal-status")
    require(status == 200 and result.get("sealed") is False
            and result.get("cluster_id") == ctx["phase"]["clusterId"], "KMS_CLUSTER_CHANGED")
    status, mounts = api(ctx, ctx["root"], "GET", "/v1/sys/mounts")
    require(status == 200 and mounts.get("data", {}).get("transit/", {}).get("type") == "transit",
            "EXISTING_TRANSIT_MOUNT_REQUIRED")


def require_absent(ctx, route, credential=None):
    status, body = api(ctx, credential or ctx["root"], "GET", route)
    require(status == 404 and not body.get("data"), "OWNED_RESOURCE_NOT_ABSENT")
    return {"observer": "existing-beta-TLS-provider-API", "httpStatus": 404, "outcome": "ABSENT", "dataAbsent": True}


def checked_key(ctx):
    status, document = api(ctx, ctx["root"], "GET", "/v1/transit/keys/"+ctx["key"])
    data = document.get("data", {})
    require(status == 200 and data.get("type") == "ecdsa-p256" and data.get("exportable") is False
            and data.get("allow_plaintext_backup") is False and data.get("latest_version") == 1
            and isinstance(data.get("keys"), dict) and isinstance(data["keys"].get("1", {}).get("public_key"), str)
            and bool(data["keys"]["1"]["public_key"]),
            "OWNED_KEY_METADATA_CHANGED")
    return hashlib.sha256(json.dumps(data.get("keys", {}), sort_keys=True).encode()).hexdigest()


def update_journal(ctx, journal):
    file = ctx["output"]/"custody.json"
    if file.exists():
        require(not file.is_symlink() and file.read_bytes() == ctx["journalBytes"], "CUSTODY_CHANGED")
    next_file = ctx["output"]/"custody.next"
    durable_new(next_file, journal)
    data = next_file.read_bytes()
    os.replace(next_file, file)
    ctx["journalBytes"] = data


def capabilities(ctx, token):
    key = ctx["key"]
    allowed = {"transit/keys/"+key: ["read"], "transit/sign/"+key: ["update"]}
    if ctx["config"]["scenario"] == "D02":
        allowed["transit/keys/"+key+"-unpublished"] = ["read"]
    denied = ["transit/keys/managed-unrelated", "transit/export/signing-key/"+key, "sys/mounts"]
    if ctx["config"]["scenario"] == "D10":
        denied.append("transit/keys/"+key+"-unpublished")
    status, result = api(ctx, ctx["root"], "POST", "/v1/sys/capabilities", {"token": token.decode(), "paths": list(allowed)+denied})
    actual = result.get("data", {})
    require(status == 200 and all(actual.get(k) == v for k, v in allowed.items())
            and all(actual.get(k) == ["deny"] for k in denied), "SCOPED_CAPABILITIES_CHANGED")
    return {k: actual[k] for k in list(allowed)+denied}


def observe_grant(ctx, accessor):
    status, response = api(ctx, ctx["root"], "POST", "/v1/auth/token/lookup-accessor", {"accessor": accessor})
    observed_at = datetime.now(timezone.utc).isoformat()
    private_response = {"observedAtUtc": observed_at, "httpStatus": status, "response": response}
    require(len(encoded(private_response)) <= 65536, "GRANT_LOOKUP_RESPONSE_TOO_LARGE")
    durable_new(ctx["output"]/"grant-lookup.private.json", private_response)
    data = response.get("data", {})
    require(status == 200 and data.get("accessor") == accessor and data.get("policies") == [ctx["key"]]
            and data.get("orphan") is True and data.get("renewable") is False
            and type(data.get("ttl")) is int and 0 < data["ttl"] <= MAX_TTL,
            "GRANT_LOOKUP_NOT_READY")
    return {"observedAtUtc": observed_at, "ttlSeconds": data["ttl"], "accessorMatched": True,
            "policies": data["policies"], "orphan": True, "renewable": False,
            "lookupHttpStatus": status, "lookupResponseSha256": hashlib.sha256(encoded(private_response)).hexdigest()}


def provision(ctx, guard=native_guard):
    config, output, key = ctx["config"], ctx["output"], ctx["key"]
    output.mkdir(mode=0o700)
    before = guard(config, protect_output=output)
    durable_new(output/"runtime-before.json", before)
    check_cluster(ctx)
    require_absent(ctx, "/v1/transit/keys/"+key)
    require_absent(ctx, "/v1/sys/policies/acl/"+key)
    journal = {"schema": SCHEMA, "runId": config["runId"], "scenario": config["scenario"], "sourceSha256": config["sourceSha256"],
               "clusterId": ctx["phase"]["clusterId"], "key": key, "policy": key,
               "policyCreated": False, "accessor": None, "mintState": "NOT_DISPATCHED", "tokenRevoked": False, "policyDeleted": False}
    update_journal(ctx, journal)
    try:
        journal["pending"] = "KEY_CREATE"; update_journal(ctx, journal)
        status, _ = api(ctx, ctx["root"], "POST", "/v1/transit/keys/"+key,
                        {"type": "ecdsa-p256", "exportable": False, "allow_plaintext_backup": False})
        require(status in (200, 204), "KEY_CREATE_UNKNOWN")
        fingerprint = checked_key(ctx)
        absence = require_absent(ctx, "/v1/transit/keys/"+key+"-unpublished") if config["scenario"] == "D02" else None
        journal["pending"] = "POLICY_WRITE"; journal["policyCreated"] = True; update_journal(ctx, journal)
        status, _ = api(ctx, ctx["root"], "PUT", "/v1/sys/policies/acl/"+key, {"policy": policy_text(key)})
        require(status in (200, 204), "POLICY_WRITE_UNKNOWN")
        journal["pending"] = "TOKEN_MINT"; journal["mintState"] = "UNKNOWN_UNTIL_OBSERVED"; update_journal(ctx, journal)
        status, result = api(ctx, ctx["root"], "POST", "/v1/auth/token/create-orphan",
                             {"policies": [key], "no_default_policy": True, "ttl": "1h", "explicit_max_ttl": "1h", "renewable": False,
                              "display_name": config["scenario"]+" beta scoped external-transit fixture"})
        mint_response = {"httpStatus": status, "response": result}
        durable_new(output/"mint-response.private.json", mint_response)
        journal["mintResponseSha256"] = hashlib.sha256(encoded(mint_response)).hexdigest()
        update_journal(ctx, journal)
        auth = result.get("auth", {})
        token, accessor = auth.get("client_token"), auth.get("accessor")
        require(status in (200, 201) and isinstance(token, str) and 16 <= len(token) <= 4096
                and isinstance(accessor, str) and 8 <= len(accessor) <= 4096
                and token.isascii() and accessor.isascii()
                and not any(char in token+accessor for char in "\r\n\x00"), "TOKEN_MINT_UNKNOWN")
        # Bearer/accessor custody is durable before capability or other postconditions.
        journal["accessor"] = accessor; journal["mintState"] = "OBSERVED"
        journal["tokenSha256"] = hashlib.sha256(token.encode()).hexdigest()
        update_journal(ctx, journal)
        durable_new(output/"token.txt", token.encode())
        require(auth.get("policies") == [key] and auth.get("renewable") is False
                and type(auth.get("lease_duration")) is int and 0 < auth["lease_duration"] <= MAX_TTL,
                "TOKEN_SCOPE_OR_TTL_CHANGED")
        token_bytes = token.encode()
        caps = capabilities(ctx, token_bytes)
        if config["scenario"] == "D02":
            # Explicit 404 through the actual scoped credential with read capability,
            # after the real B key is readable, distinguishes absence from denial.
            status, known = api(ctx, token_bytes, "GET", "/v1/transit/keys/"+key)
            require(status == 200 and known.get("data", {}).get("type") == "ecdsa-p256", "SCOPED_KEY_READ_FAILED")
            absence = require_absent(ctx, "/v1/transit/keys/"+key+"-unpublished", token_bytes)
        after = guard(config)
        require(before == after, "CURRENT_NATIVE_RUNTIME_CHANGED")
        durable_new(output/"runtime-after.json", after)
        grant = observe_grant(ctx, accessor)
        if config["scenario"] == "D02":
            environment = {"D02_SAME_BACKEND_FIXTURE": "1", "D02_EXTERNAL_TRANSIT_ENDPOINT": "https://openbao:8200",
                           "D02_EXTERNAL_TRANSIT_CA_FILE": "/run/secrets/openbao_tls_ca_cert", "D02_EXTERNAL_TRANSIT_KEY": key,
                           "D02_EXTERNAL_TRANSIT_TOKEN": token}
        else:
            environment = {"DEMO_D10_KMS_URL": "https://openbao:8200", "DEMO_D10_KMS_MOUNT": "transit", "DEMO_D10_KMS_NAMESPACE": "",
                           "DEMO_D10_KMS_KEY_REFERENCE": key, "DEMO_D10_KMS_TOKEN_FILE": str(output/"token.txt"),
                           "DEMO_D10_KMS_CA_CERT_FILE": "/run/secrets/openbao_tls_ca_cert"}
        journal["pending"] = None
        journal["environmentSha256"] = hashlib.sha256(encoded(environment)).hexdigest()
        update_journal(ctx, journal)
        durable_new(output/"environment.json", environment)
        receipt = {"state": "SCOPED_EXTERNAL_TRANSIT_CUSTODY_READY", "scenario": config["scenario"], "runId": config["runId"],
                   "key": key, "policySha256": hashlib.sha256(policy_text(key).encode()).hexdigest(), "capabilities": caps,
                   "freshUnpublishedKeyControl": absence, **grant, "mintLeaseSeconds": auth["lease_duration"],
                   "keyPublicMetadataSha256": fingerprint,
                   "privateKeyExported": False, "keyExportable": False, "plaintextBackupAllowed": False,
                   "rootAuthorityCustody": "existing hash-bound recovery credential in operator memory; never argv/env/log output",
                   "providerBootstrap": False, "functionalOnly": True, "demoQualified": False, "releaseQualified": False}
        durable_new(output/"result.json", receipt)
        return receipt
    except BaseException:
        # Unknown create/mint never becomes a successful fixture or blind retry.
        # Retain intent/accessor/token files for the exact revoke operation.
        raise


def clear_token(file):
    require(file.is_file() and not file.is_symlink(), "TOKEN_CUSTODY_CHANGED")
    with file.open("r+b") as stream:
        stream.write(b"0"*file.stat().st_size); stream.truncate(); stream.flush(); os.fsync(stream.fileno())


def revoke(ctx, guard=native_guard):
    config, output, key = ctx["config"], ctx["output"], ctx["key"]
    file = output/"custody.json"
    require(file.is_file() and not file.is_symlink(), "CUSTODY_REQUIRED")
    raw = file.read_bytes(); journal = json.loads(raw); ctx["journalBytes"] = raw
    require(journal.get("schema") == SCHEMA and journal.get("runId") == config["runId"]
            and journal.get("sourceSha256") == config["sourceSha256"] and journal.get("scenario") == config["scenario"]
            and journal.get("key") == key and journal.get("policy") == key
            and journal.get("clusterId") == ctx["phase"]["clusterId"], "EXACT_CUSTODY_REQUIRED")
    require(not (output/"revoked.json").exists(), "CUSTODY_ALREADY_RETIRED")
    before = guard(config, protect_output=output); check_cluster(ctx)
    require(journal.get("accessor") and journal.get("mintState") == "OBSERVED", "UNKNOWN_MINT_REQUIRES_RECONCILIATION")
    mint_response_file = output/"mint-response.private.json"
    require(mint_response_file.is_file() and not mint_response_file.is_symlink(), "MINT_CUSTODY_CHANGED")
    mint_raw = mint_response_file.read_bytes()
    require(hashlib.sha256(mint_raw).hexdigest() == journal.get("mintResponseSha256"), "MINT_CUSTODY_CHANGED")
    token_file = output/"token.txt"
    require(not token_file.is_symlink(), "TOKEN_CUSTODY_CHANGED")
    token_present = token_file.exists()
    if token_present:
        require(token_file.is_file(), "TOKEN_CUSTODY_CHANGED")
        token = token_file.read_bytes()
    else:
        # Publication can fail after exact accessor custody became durable. Use
        # only that already-bound response, never recreate a bearer file or
        # adopt an UNKNOWN mint or a replaced existing token.txt.
        response = json.loads(mint_raw)
        auth = response.get("response", {}).get("auth", {})
        candidate = auth.get("client_token")
        require(response.get("httpStatus") in (200, 201) and isinstance(candidate, str)
                and candidate.isascii() and 16 <= len(candidate) <= 4096
                and not any(char in candidate for char in "\r\n\x00")
                and auth.get("accessor") == journal["accessor"]
                and auth.get("policies") == [key]
                and scenario_for_key(key) == config["scenario"], "MINT_CUSTODY_CHANGED")
        token = candidate.encode()
    require(hashlib.sha256(token).hexdigest() == journal.get("tokenSha256"), "TOKEN_CUSTODY_CHANGED")
    environment_file = output/"environment.json"
    if environment_file.exists():
        require(not environment_file.is_symlink() and sha(environment_file) == journal.get("environmentSha256"),
                "ENVIRONMENT_CUSTODY_CHANGED")
    journal["pending"] = "TOKEN_REVOKE"; update_journal(ctx, journal)
    if not journal.get("tokenRevoked"):
        status, _ = api(ctx, ctx["root"], "POST", "/v1/auth/token/revoke-accessor", {"accessor": journal["accessor"]})
        require(status in (200, 204), "TOKEN_REVOKE_UNKNOWN")
    status, _ = api(ctx, token, "GET", "/v1/transit/keys/"+key)
    require(status == 403, "OLD_SCOPED_TOKEN_NOT_DENIED")
    journal["tokenRevoked"] = True; journal["pending"] = "POLICY_DELETE"; update_journal(ctx, journal)
    if not journal.get("policyDeleted"):
        status, _ = api(ctx, ctx["root"], "DELETE", "/v1/sys/policies/acl/"+key)
        require(status in (200, 204), "POLICY_DELETE_UNKNOWN")
    require_absent(ctx, "/v1/sys/policies/acl/"+key)
    journal["policyDeleted"] = True; journal["pending"] = None; update_journal(ctx, journal)
    after = guard(config); require(before == after, "CURRENT_NATIVE_RUNTIME_CHANGED")
    environment_file = output/"environment.json"
    if environment_file.exists():
        require(not environment_file.is_symlink() and sha(environment_file) == journal.get("environmentSha256"),
                "ENVIRONMENT_CUSTODY_CHANGED")
        environment = json.loads(environment_file.read_bytes()); environment.pop("D02_EXTERNAL_TRANSIT_TOKEN", None)
        retired_file = output/"environment.retired.json"
        if retired_file.exists():
            require(not retired_file.is_symlink() and retired_file.read_bytes() == encoded(environment), "ENVIRONMENT_CUSTODY_CHANGED")
        else:
            durable_new(retired_file, environment)
        clear_token(environment_file)
    if token_present:
        require(not token_file.is_symlink() and sha(token_file) == journal["tokenSha256"], "TOKEN_CUSTODY_CHANGED")
        clear_token(token_file)
    else:
        require(not token_file.exists() and not token_file.is_symlink(), "TOKEN_CUSTODY_CHANGED")
    require(not mint_response_file.is_symlink() and sha(mint_response_file) == journal["mintResponseSha256"],
            "MINT_CUSTODY_CHANGED")
    clear_token(mint_response_file)
    proof = {"state": "TOKEN_REVOKED_POLICY_DELETED", "runId": config["runId"], "scenario": config["scenario"],
             "key": key, "tokenRevoked": True, "policyDeleted": True, "oldScopedTokenDenied": True,
             "nonexportableKeyRetained": True, "functionalOnly": True, "demoQualified": False, "releaseQualified": False}
    durable_new(output/"revoked.json", proof)
    return proof


def safe_failure(error):
    code = str(error) if isinstance(error, FixtureError) else "EXTERNAL_TRANSIT_OPERATION_FAILED"
    return {"state": "FAILED", "code": code, "errorClass": type(error).__name__, "qualification": "NONE"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--action", choices=("provision", "revoke"), required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    config = load({"path": str(args.input), "sha256": args.sha256})
    if args.check:
        # Exercise the same input/source/authority guards, without native/API calls.
        checked = dict(config, executeAuthorized=True)
        inputs(checked, args.action)
        print(json.dumps({"state": "EXTERNAL_TRANSIT_SOURCE_GUARDS_PASS", "runtimeCalls": 0}))
        return 0
    require_job(config)
    ctx = inputs(config, args.action)
    try:
        result = provision(ctx) if args.action == "provision" else revoke(ctx)
    except Exception as error:
        # Child stdout is suppressed by the genuine supervisor. Persist only a
        # fixed diagnostic code/class, never provider bodies or credentials.
        if ctx["output"].is_dir() and not ctx["output"].is_symlink():
            failure = ctx["output"]/(args.action+"-failure.json")
            if not failure.exists():
                durable_new(failure, safe_failure(error))
        raise
    print(json.dumps({"state": result["state"], "scenario": config["scenario"], "runId": config["runId"], "qualification": "CUSTODY_ONLY"}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps(safe_failure(error)))
        raise SystemExit(1)
