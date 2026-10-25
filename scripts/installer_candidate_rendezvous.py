"""Bounded GitHub draft transport; no acceptance, signing, or guest execution.

Controller uploader identity authenticates its guest/disk/Engine assertions, not
physical observations by this signer. Guest preflight independently checks Engine.
The external durable nonce ledger is never replaced by this mutable transport.
Caller supplies its already-authenticated, exclusively staged authorization and
inventory. This helper does not verify their signatures; its independent inputs
bind the active harness invocation, not arbitrary grant provenance.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import installer_release as release
from installer_candidate_authorize import read_record, write_exclusive

REPO = "/repos/ElevenID/marty-ui"
MAX_BYTES = 65536
RECEIPT = "installer-controller-consumption.json"
SCHEMA = "elevenid.installer-candidate-rendezvous/v1"
RESERVE = 120
SHARED_ACTIONS_BOT = 41898282


def positive_id(value):
    release.positive(value)
    return value


def controller_id(value):
    positive_id(value)
    release.require(value != SHARED_ACTIONS_BOT, "shared Actions bot is not a controller")
    return value


def json_bytes(raw):
    release.require(len(raw) <= MAX_BYTES, "transport response exceeds bound")
    def pairs(items):
        result = {}
        for key, value in items:
            release.require(key not in result, "duplicate transport field")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Client:
    """Fixed GitHub API with no proxies; bearer never follows asset redirects."""
    def __init__(self, token):
        release.require(isinstance(token, str) and token and all(32 < ord(c) < 127 for c in token),
                        "GitHub authentication unavailable")
        self.token = token
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def _read(self, url, *, method="GET", body=None, binary=False, authenticated=True, maximum=MAX_BYTES):
        headers = {"Accept": "application/octet-stream" if binary else "application/vnd.github+json",
                   "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "marty-installer-candidate"}
        if authenticated:
            headers["Authorization"] = "Bearer " + self.token
        if body is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=20) as response:
                chunks, length, deadline = [], 0, time.monotonic() + 60
                while True:
                    release.require(time.monotonic() < deadline, "transport response timed out")
                    chunk = response.read1(min(8192, maximum + 1 - length))
                    if not chunk:
                        return b"".join(chunks)
                    chunks.append(chunk)
                    length += len(chunk)
                    release.require(length <= maximum, "transport response exceeds bound")
        except urllib.error.HTTPError as error:
            if binary and error.code in (301, 302, 303, 307, 308) and authenticated:
                target = error.headers.get("Location", "")
                parsed = urllib.parse.urlsplit(target)
                release.require(parsed.scheme == "https" and parsed.hostname == "release-assets.githubusercontent.com"
                                and parsed.port in (None, 443) and not parsed.username and not parsed.password
                                and not parsed.fragment, "untrusted asset redirect")
                return self._read(target, binary=True, authenticated=False, maximum=maximum)
            raise ValueError("GitHub transport request failed") from None
        except (OSError, urllib.error.URLError):
            raise ValueError("GitHub transport request failed") from None

    def request(self, method, path, body=None):
        run = re.fullmatch(re.escape(REPO) + r"/actions/runs/([1-9][0-9]{0,15})", path)
        artifacts = re.fullmatch(re.escape(REPO) + r"/actions/runs/([1-9][0-9]{0,15})/artifacts\?per_page=100", path)
        artifact = re.fullmatch(re.escape(REPO) + r"/actions/artifacts/([1-9][0-9]{0,15})", path)
        if run or artifacts or artifact:
            positive_id(int((run or artifacts or artifact).group(1)))
            release.require(method == "GET" and body is None, "Actions observation is read-only")
        else:
            release.require(path.startswith(REPO + "/releases") and not any(c in path for c in "#\r\n"),
                            "invalid transport API path")
        data = None if body is None else release.encode(body)
        return json_bytes(self._read("https://api.github.com" + path, method=method, body=data))

    def download(self, asset_id, size):
        positive_id(asset_id)
        release.require(type(size) is int and 0 < size <= MAX_BYTES, "invalid receipt size")
        raw = self._read(f"https://api.github.com{REPO}/releases/assets/{asset_id}", binary=True, maximum=size)
        release.require(len(raw) == size, "receipt size changed")
        return raw

    def whoami(self):
        return json_bytes(self._read("https://api.github.com/user"))

    def upload_receipt(self, release_id, raw):
        positive_id(release_id)
        release.require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES, "invalid receipt bytes")
        url = (f"https://uploads.github.com{REPO}/releases/{release_id}/assets?"
               + urllib.parse.urlencode({"name": RECEIPT}))
        request = urllib.request.Request(url, data=raw, method="POST", headers={
            "Accept": "application/vnd.github+json", "Content-Type": "application/octet-stream",
            "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "marty-installer-candidate",
            "Authorization": "Bearer " + self.token})
        try:
            with self.opener.open(request, timeout=20) as response:
                release.require(response.status == 201, "GitHub receipt upload status differs")
                answer = response.read(MAX_BYTES + 1)
        except (urllib.error.HTTPError, OSError, urllib.error.URLError):
            raise ValueError("GitHub receipt upload failed or is uncertain") from None
        return json_bytes(answer)


def inputs(authorization, inventory, *, harness_source_sha, run_id, run_attempt, now):
    a, i = read_record(authorization), read_record(inventory)
    record = release.decode(a)
    expected = {key: record.get(key) for key in release.CONTEXT_FIELDS}
    expected.update(harness_source_sha=harness_source_sha, run_id=run_id, run_attempt=run_attempt)
    release.bind_candidate_authorization(a, i, expected=expected, now=now)
    release.require(record["phase"] in ("staged", "published"), "candidate transport phase invalid")
    return a, i, expected, record


def identity(record, release_id, author_id):
    return dict(id=positive_id(release_id), author_id=positive_id(author_id),
                tag_name=f"installer-candidate-{record['run_id']}-{record['run_attempt']}-{record['nonce']}",
                target_commitish=record["harness_source_sha"], draft=True, prerelease=True,
                name=f"Installer candidate transport {record['run_id']}/{record['run_attempt']}",
                body="Acceptance-only transport; never publish. Nonce: " + record["nonce"])


def check_release(remote, expected):
    release.require(isinstance(remote, dict) and isinstance(remote.get("author"), dict), "invalid draft release")
    release.require(all(type(remote.get(k)) is type(v) and remote.get(k) == v
                        for k, v in expected.items() if k != "author_id")
                    and remote["author"].get("id") == expected["author_id"], "draft transport identity changed")


def bound_descriptor(descriptor, a, i, context, record, approved):
    d = release.decode(read_record(descriptor))
    release.exact(d, {"schema", "authorization_sha256", "inventory_sha256", "context_sha256", "controller_user_id",
                     "nonce", "run_id", "run_attempt", "harness_source_sha", "release"}, "transport descriptor")
    release.require(d["schema"] == SCHEMA and d["authorization_sha256"] == release.digest(a)
                    and d["inventory_sha256"] == release.digest(i)
                    and d["context_sha256"] == release.candidate_context_sha256(context)
                    and d["controller_user_id"] == approved
                    and all(d[k] == record[k] for k in ("nonce", "run_id", "run_attempt", "harness_source_sha")),
                    "transport descriptor binding differs")
    release.require(isinstance(d["release"], dict), "invalid release binding")
    owned = identity(record, d["release"].get("id"), d["release"].get("author_id"))
    release.require(d["release"] == owned, "transport release binding differs")
    return owned


def prepare(*, client, authorization, inventory, harness_source_sha, run_id, run_attempt,
            controller_user_id, descriptor_output, clock=time.time):
    a, i, context, record = inputs(authorization, inventory, harness_source_sha=harness_source_sha,
                                 run_id=run_id, run_attempt=run_attempt, now=int(clock()))
    controller_id(controller_user_id)
    release.require(record["expires_at"] - int(clock()) > RESERVE, "grant expires too soon")
    base = dict(schema=SCHEMA, authorization_sha256=release.digest(a), inventory_sha256=release.digest(i),
                context_sha256=release.candidate_context_sha256(context), controller_user_id=controller_user_id,
                nonce=record["nonce"], run_id=run_id, run_attempt=run_attempt,
                harness_source_sha=harness_source_sha)
    # Burn this local attempt before remote mutation; failed create is not retried.
    write_exclusive(Path(str(descriptor_output) + ".intent.json"), release.encode(base))
    wanted = identity(record, 1, 1)
    body = {key: value for key, value in wanted.items() if key not in {"id", "author_id"}}
    remote = client.request("POST", REPO + "/releases", body)
    release.require(isinstance(remote, dict) and isinstance(remote.get("author"), dict), "invalid draft creation")
    owned = identity(record, remote.get("id"), remote["author"].get("id"))
    check_release(remote, owned)
    result = dict(base, release=owned)
    write_exclusive(descriptor_output, release.encode(result))
    return result


def receipt_asset(items, approved):
    release.require(isinstance(items, list) and len(items) <= 1, "unexpected transport assets")
    if not items:
        return None
    item = items[0]
    release.require(isinstance(item, dict) and isinstance(item.get("uploader"), dict), "invalid receipt metadata")
    uploader = item["uploader"]
    release.require(type(uploader.get("id")) is int and uploader["id"] == approved
                    and uploader.get("type") == "User" and uploader.get("login") != "github-actions[bot]",
                    "unapproved controller uploader")
    positive_id(item.get("id"))
    size = item.get("size")
    release.require(item.get("name") == RECEIPT and item.get("state") == "uploaded"
                    and type(size) is int and 0 < size <= MAX_BYTES
                    and isinstance(item.get("digest"), str)
                    and re.fullmatch(r"sha256:[0-9a-f]{64}", item["digest"]), "invalid receipt metadata")
    return {key: item.get(key) for key in ("id", "name", "state", "size", "digest", "uploader", "created_at", "updated_at")}


def receive(*, client, authorization, inventory, harness_source_sha, run_id, run_attempt,
            controller_user_id, descriptor, receipt_output, clock=time.time, sleep=time.sleep):
    a, i, context, record = inputs(authorization, inventory, harness_source_sha=harness_source_sha,
                                 run_id=run_id, run_attempt=run_attempt, now=int(clock()))
    approved = controller_id(controller_user_id)
    owned = bound_descriptor(descriptor, a, i, context, record, approved)
    endpoint = f"{REPO}/releases/{owned['id']}"
    deadline = min(int(clock()) + 900, record["expires_at"] - RESERVE)
    while int(clock()) < deadline:
        check_release(client.request("GET", endpoint), owned)
        asset = receipt_asset(client.request("GET", endpoint + "/assets?per_page=100"), approved)
        if asset is None:
            sleep(min(5, max(0, deadline - int(clock()))))
            continue
        raw = client.download(asset["id"], asset["size"])
        release.require(release.digest(raw) == asset["digest"][7:], "receipt digest differs")
        check_release(client.request("GET", endpoint), owned)
        release.require(receipt_asset(client.request("GET", endpoint + "/assets?per_page=100"), approved) == asset,
                        "receipt asset changed during download")
        # The approved controller attests Engine identity; the signer cannot observe it.
        claimed = release.decode(raw)
        release.bind_controller_consumption(raw, a, i, expected=context,
            expected_engine=claimed.get("engine_id"), now=int(clock()))
        release.require(int(clock()) < deadline, "transport deadline expired")
        evidence = dict(schema="elevenid.installer-candidate-receipt-transport/v1",
                        release=owned, controller_user_id=approved,
                        authorization_sha256=release.digest(a), inventory_sha256=release.digest(i),
                        context_sha256=release.candidate_context_sha256(context),
                        receipt_sha256=release.digest(raw), verified_at=int(clock()),
                        asset={key: asset[key] for key in
                               ("id", "name", "state", "size", "digest", "created_at", "updated_at")})
        evidence["asset"]["uploader_id"] = approved
        # Archive the authenticated API observation before exposing bytes to signing.
        # A failed receipt write leaves this exclusive evidence and forbids replay.
        write_exclusive(Path(str(receipt_output) + ".transport.json"), release.encode(evidence))
        write_exclusive(receipt_output, raw)
        return claimed
    raise ValueError("controller receipt deadline expired")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("prepare", "receive"))
    for flag in ("authorization", "inventory", "output"):
        parser.add_argument("--" + flag, type=Path, required=True)
    parser.add_argument("--descriptor", type=Path)
    parser.add_argument("--harness-source-sha", required=True)
    for flag in ("run-id", "run-attempt", "controller-user-id"):
        parser.add_argument("--" + flag, type=int, required=True)
    args = vars(parser.parse_args(argv))
    phase, output, descriptor = args.pop("phase"), args.pop("output"), args.pop("descriptor")
    try:
        args["client"] = Client(os.environ.get("GH_TOKEN"))
        if phase == "prepare":
            release.require(descriptor is None, "prepare does not accept a descriptor")
            prepare(**args, descriptor_output=output)
        else:
            release.require(descriptor is not None, "receive requires descriptor")
            receive(**args, descriptor=descriptor, receipt_output=output)
    except (ValueError, OSError, TypeError, KeyError):
        parser.exit(1, "Candidate transport refused or uncertain; preserve ledger, descriptor and remote transport.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
