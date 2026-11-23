"""Authenticate a private signed release authorization against protected main."""
import base64
from datetime import datetime, timezone
from functools import lru_cache
import hashlib
import json
import re
import sys
import ssl
import urllib.request

PUBLIC = "ElevenID/marty-ui"
PUBLIC_ID = 1140864197
PRIVATE_ID = 1207411806
WORKFLOW = ".github/workflows/production-ui-release.yml"
MODE = "qualify-local-signer"
DIRECTORY = "docs/restructuring/website-release-approvals"
JOB_FOR_MODE = {MODE: MODE, "standalone-website": "standalone-website", "combined": "release",
                "compose": "compose"}
COMPOSITION_INPUTS = {"website_run_id", "website_run_attempt", "application_run_id",
                      "application_run_attempt"}
MODE_INPUTS = {MODE: set(), "standalone-website": {"website_source_sha"},
               "combined": {"stack_release_tag"}, "compose": COMPOSITION_INPUTS}
INPUTS = {"mode", "ui_source_sha"}.union(*MODE_INPUTS.values())


def require(ok, message):
    if not ok:
        raise ValueError(message)


def inputs_from(values):
    require(isinstance(values, dict) and values.keys() <= INPUTS and
            all(isinstance(v, str) for v in values.values()), "unknown dispatch inputs")
    inputs = {key: value for key, value in values.items() if value != ""}
    mode = inputs.get("mode")
    require(mode in MODE_INPUTS and set(inputs) == {"mode", "ui_source_sha"} | MODE_INPUTS[mode],
            "wrong inputs for this release mode")
    require(re.fullmatch(r"[0-9a-f]{40}", inputs["ui_source_sha"]), "expected exact public source")
    if mode == "standalone-website":
        require(re.fullmatch(r"[0-9a-f]{40}", inputs["website_source_sha"]), "expected exact website source")
    if mode == "combined":
        require(re.fullmatch(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)",
                             inputs["stack_release_tag"]), "expected a stable backend release tag")
    if mode == "compose":
        require(all(re.fullmatch(r"[1-9][0-9]*", inputs[key]) for key in COMPOSITION_INPUTS) and
                inputs["website_run_id"] != inputs["application_run_id"],
                "expected distinct original website and application runs and exact attempts")
    return inputs


def authorization(raw):
    require(0 < len(raw) <= 4096, "invalid authorization length")
    a = json.loads(raw)
    require(raw == (json.dumps(a, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii"),
            "expected canonical authorization bytes")
    fields = {"schema", "nonce", "repository_id", "workflow", "source", "ref", "inputs",
              "run", "attempt", "job", "runner_id", "runner_name", "expires"}
    require(isinstance(a, dict) and a.keys() == fields and
            a["schema"] == "elevenid.private-run-approval/v1" and
            a["repository_id"] == PRIVATE_ID and a["workflow"] == WORKFLOW and
            a["ref"] == "refs/heads/main" and re.fullmatch(r"[0-9a-f]{40}", a["source"])
            and re.fullmatch(r"[0-9a-f]{64}", a["nonce"]), "unexpected authorization")
    require(all(type(a[k]) is int and a[k] > 0 for k in ("run", "attempt", "job", "runner_id", "expires")),
            "expected exact invocation and registration")
    require(a["runner_name"] == f"elevenid-release-{a['run']}-{a['attempt']}" and
            a["inputs"] == inputs_from(a["inputs"]), "runner or input mismatch")
    return a


def public_context():
    """Use system trust without consulting inherited SSL_CERT_* overrides."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if sys.platform == "win32":
        for store in ("CA", "ROOT"):
            for certificate, encoding, trust in ssl.enum_certificates(store):
                if encoding == "x509_asn" and (trust is True or ssl.Purpose.SERVER_AUTH.oid in trust):
                    context.load_verify_locations(cadata=ssl.DER_cert_to_PEM_cert(certificate))
    else:
        context.load_verify_locations(cafile="/etc/ssl/certs/ca-certificates.crt")
    require(context.cert_store_stats()["x509_ca"] > 0, "system TLS authority unavailable")
    return context


@lru_cache(maxsize=128)
def public_json(path):
    request = urllib.request.Request("https://api.github.com/repos/" + PUBLIC + path,
                                     headers={"Accept": "application/vnd.github+json",
                                              "User-Agent": "ElevenID-release-verifier"})
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    context = public_context()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                         urllib.request.HTTPSHandler(context=context))
    with opener.open(request, timeout=15) as response:
        require(response.geturl() == request.full_url and response.status == 200,
                "public authority must have its expected identity")
        body = response.read(256 * 1024 + 1)
    require(len(body) <= 256 * 1024, "oversized public authority response")
    return json.loads(body)


def verify_approval(raw, read=public_json, *, at=None, before=None):
    a = authorization(raw)
    now = int(datetime.now(timezone.utc).timestamp()) if at is None else at
    require(now < a["expires"], "authorization has expired")
    repo = read("")
    require(repo.get("id") == PUBLIC_ID and repo.get("full_name") == PUBLIC and
            repo.get("private") is False, "wrong approval repository")
    branch = read("/branches/main")
    head = branch["commit"]["sha"]
    require(branch.get("name") == "main" and branch.get("protected") is True and
            re.fullmatch(r"[0-9a-f]{40}", head), "approval requires protected public main")
    digest = hashlib.sha256(raw).hexdigest()
    path = f"{DIRECTORY}/{digest}.sha256"
    blob = read(f"/contents/{path}?ref={head}")
    require(blob.get("type") == "file" and blob.get("path") == path and
            blob.get("size") == 65 and blob.get("encoding") == "base64" and
            base64.b64decode("".join(blob["content"].splitlines()), validate=True) == (digest + "\n").encode(),
            "missing or mismatched protected approval digest")
    if before is not None:
        require(isinstance(before, datetime) and before.utcoffset() is not None,
                "expected an original job start with timezone")
        history = read(f"/commits?sha={head}&path={path}&per_page=1")
        require(isinstance(history, list) and len(history) == 1,
                "approval introduction missing")
        introduction = history[0]["sha"]
        require(re.fullmatch(r"[0-9a-f]{40}", introduction), "invalid approval commit")
        prs = read(f"/commits/{introduction}/pulls")
        require(isinstance(prs, list), "approval pull request history missing")
        merged = [pr for pr in prs if pr.get("merge_commit_sha") == introduction
                  and pr.get("base", {}).get("ref") == "main"
                  and pr.get("base", {}).get("repo", {}).get("id") == PUBLIC_ID
                  and pr.get("merged_at")]
        require(len(merged) == 1, "approval requires its original merged main pull request")
        approved = datetime.fromisoformat(merged[0]["merged_at"].replace("Z", "+00:00"))
        require(approved.utcoffset() is not None and approved <= before,
                "protected approval must precede the original job start")
    return a, head



def verified_authorization(result, producer, role, *, read=public_json):
    """Consume only gh's cryptographically verified statement and timestamps.

    The caller still verifies the original certificate identity and Cosign proof.
    Approval expiry applies at authenticated signing time, never runtime replay.
    """
    require(role in {"website", "application", "composition"}
            and producer["repository"] == "ElevenID/marty-subscriptions",
            "local signing is limited to the explicit private release roles")
    try:
        signed = result["verificationResult"]
        statement = signed["statement"]
        require(statement["predicateType"] == "https://slsa.dev/provenance/v1",
                "expected verified SLSA provenance")
        definition = statement["predicate"]["buildDefinition"]
        raw = definition["externalParameters"]["elevenidReleaseAuthorization"].encode("ascii")
        a = authorization(raw)
        require(a["source"] == producer["source_sha"] and a["run"] == int(producer["run_id"])
                and a["attempt"] == int(producer["run_attempt"])
                and a["workflow"] == producer["workflow"] and a["ref"] == producer["ref"],
                "signed approval differs from original producer")
        mode = {"website": "standalone-website", "application": "combined", "composition": "compose"}[role]
        require(a["inputs"]["mode"] == mode, "approval has another release role")
        stamps = signed["verifiedTimestamps"]
        require(isinstance(stamps, list) and len(stamps) == 1
                and stamps[0]["type"] == "TimestampAuthority"
                and stamps[0]["uri"] == "timestamp.githubapp.com",
                "original private signed timestamp required")
        at = datetime.fromisoformat(stamps[0]["timestamp"].replace("Z", "+00:00"))
        require(at.utcoffset() is not None, "timestamp requires timezone")
        require(definition["buildType"] == "https://actions.github.io/buildtypes/workflow/v1"
                and definition["internalParameters"]["github"]["runner_environment"] == "self-hosted"
                and str(definition["internalParameters"]["github"]["repository_id"]) == str(PRIVATE_ID)
                and definition["externalParameters"]["workflow"] == {
                    "ref": a["ref"], "repository": "https://github.com/ElevenID/marty-subscriptions",
                    "path": WORKFLOW}, "original GitHub build claims differ")
        verify_approval(raw, read, at=int(at.timestamp()), before=at)
        return a
    except (KeyError, TypeError, AttributeError, UnicodeError, OverflowError):
        raise ValueError("private signed release authorization is invalid") from None


def check_assignment(a, value, *, completed, read=public_json):
    """Bind GitHub's original-attempt job census to the signed authorization."""
    require(isinstance(value, dict) and isinstance(value.get("jobs"), list)
            and len(value["jobs"]) == value.get("total_count") and 0 < len(value["jobs"]) <= 100,
            "original job inventory incomplete")
    items = value["jobs"]
    matches = [j for j in items if j.get("name") == JOB_FOR_MODE[a["inputs"]["mode"]]]
    require(len(matches) == 1, "original approved job missing or ambiguous")
    job = matches[0]
    require(job.get("id") == a["job"] and job.get("run_id") == a["run"]
            and job.get("head_sha") == a["source"] and job.get("runner_id") == a["runner_id"]
            and job.get("runner_name") == a["runner_name"]
            and set(x.lower() for x in job.get("labels", [])) == {
                "self-hosted", "linux", "x64", a["runner_name"]}
            and all(j is job or (j.get("status") == "completed" and j.get("conclusion") == "skipped"
                                and not j.get("runner_id")) for j in items),
            "original runner assignment differs from signed approval")
    require(job.get("status") == ("completed" if completed else "in_progress")
            and job.get("conclusion") == ("success" if completed else None),
            "original approved job has not reached the required phase")
    started = datetime.fromisoformat(job["started_at"].replace("Z", "+00:00"))
    require(started.utcoffset() is not None and started.timestamp() < a["expires"],
            "job began after authorization expired")
    if completed:
        ended = datetime.fromisoformat(job["completed_at"].replace("Z", "+00:00"))
        require(ended.utcoffset() is not None and started <= ended
                and ended.timestamp() < a["expires"], "job completed outside authorization")
    else:
        ended = started
    raw = (json.dumps(a, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    verify_approval(raw, read, at=int(ended.timestamp()), before=started)
    return job
