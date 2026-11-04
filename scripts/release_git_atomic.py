#!/usr/bin/env python3
"""Two explicit Git ref commands over bounded, non-retrying smart HTTPS.

This transport has no release authority of its own. The native operator admits
the source, review, workflow, checkpoint and cryptographic gates before calling
it. Its isolated worker receives the existing job token only over private stdin.
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import re
import ssl
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

HOST = "github.com"
BASE = "/ElevenID/marty-ui.git"
DISCOVERY_PATH = BASE + "/info/refs?service=git-receive-pack"
RECEIVE_PATH = BASE + "/git-receive-pack"
TRANSPORT = "git-smart-https-receive-pack/v1"
CAPABILITIES = ("atomic", "report-status", "side-band-64k")
SHA = re.compile(r"[0-9a-f]{40}\Z")
TAG = re.compile(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
CAP_TAG = re.compile(r"v-release-capability-([1-9][0-9]*)-1\Z")
OPERATION = re.compile(r"(capability-negative|capability-positive|release-tag)-([1-9][0-9]*)-1\Z")
ZERO = "0" * 40
MAX_DISCOVERY = 1024 * 1024
MAX_STATUS = 256 * 1024
MAX_DIAGNOSTIC = 64 * 1024
MAX_WORKER_INPUT = 4096
MAX_WORKER_OUTPUT = 2 * 1024 * 1024
MAX_PACKET = 65520
SAFE_HEADERS = frozenset({"content-type", "content-length", "transfer-encoding", "content-encoding",
                          "x-github-request-id", "date"})


class AtomicGitError(ValueError):
    """A protocol or custody condition refused without a mutation retry."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AtomicGitError(message)


def encoded(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def strict_json(raw: bytes, maximum: int) -> object:
    require(0 < len(raw) <= maximum, "Bounded transport JSON is unavailable")

    def unique(pairs: list[tuple[str, object]]) -> dict:
        out = {}
        for key, value in pairs:
            require(key not in out, "Duplicate transport JSON key")
            out[key] = value
        return out

    def invalid(_: str) -> None:
        raise AtomicGitError("Non-finite transport JSON")

    try:
        return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise AtomicGitError("Malformed transport JSON") from error


def unbase64(value: object, maximum: int) -> bytes:
    require(isinstance(value, str) and len(value) <= 4 * ((maximum + 2) // 3),
            "Transport encoding exceeds its bound")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, UnicodeError) as error:
        raise AtomicGitError("Malformed transport encoding") from error
    require(len(raw) <= maximum and base64.b64encode(raw).decode() == value,
            "Transport encoding is not canonical")
    return raw


def pkt(payload: bytes) -> bytes:
    require(0 < len(payload) <= MAX_PACKET - 4, "Packet length exceeds its bound")
    return f"{len(payload) + 4:04x}".encode() + payload


def packets(raw: bytes, maximum: int) -> list[bytes | None]:
    require(0 < len(raw) <= maximum, "Packet stream exceeds its bound")
    result: list[bytes | None] = []
    offset = 0
    while offset < len(raw):
        header = raw[offset:offset + 4]
        require(len(header) == 4 and re.fullmatch(rb"[0-9a-f]{4}", header) is not None,
                "Packet length is malformed")
        length = int(header, 16)
        offset += 4
        if length == 0:
            result.append(None)
        else:
            require(4 < length <= MAX_PACKET and offset + length - 4 <= len(raw),
                    "Packet is truncated, empty or unsupported")
            result.append(raw[offset:offset + length - 4])
            offset += length - 4
        require(len(result) <= 20000, "Packet count exceeds its bound")
    return result


def text_line(raw: bytes) -> str:
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    require(raw and all(32 <= value <= 126 for value in raw), "Protocol line is not printable ASCII")
    return raw.decode("ascii")


def ref_name(value: str) -> bool:
    if value == "HEAD":
        return True
    if value.endswith("^{}"):
        if not value.startswith("refs/tags/"):
            return False
        value = value[:-3]
    return (value.startswith("refs/") and len(value) <= 1024 and not value.endswith(("/", "."))
            and not any(part in value for part in ("..", "//", "@{"))
            and not any(character in value for character in " ~^:?*[\\")
            and all(part and not part.startswith(".") and not part.endswith(".lock") for part in value.split("/")))


def transaction_spec(before: str, main: str, tag: str, obj: str, operation: str) -> dict:
    require(all(isinstance(value, str) and SHA.fullmatch(value) and value != ZERO
                for value in (before, main, obj)), "Atomic object identity is malformed")
    match = OPERATION.fullmatch(operation) if isinstance(operation, str) else None
    cap_tag = CAP_TAG.fullmatch(tag) if isinstance(tag, str) else None
    require(match is not None and 0 < int(match[2]) < 2**53, "Atomic operation identity is malformed")
    assert match is not None
    if match[1] == "release-tag":
        require(TAG.fullmatch(tag) is not None and before == main, "Release requires a no-op main assertion")
    else:
        require(cap_tag is not None and cap_tag[1] == match[2], "Capability tag and operator differ")
        require((before != main) == (match[1] == "capability-negative"), "Capability main assertion differs")
    return {"operation_id": operation, "commands": [
        {"ref": "refs/heads/main", "old_oid": before, "new_oid": main},
        {"ref": f"refs/tags/{tag}", "old_oid": ZERO, "new_oid": obj},
    ]}


def validate_spec(value: object) -> dict:
    require(isinstance(value, dict) and set(value) == {"operation_id", "commands"}, "Atomic request shape differs")
    commands = value["commands"]
    require(isinstance(commands, list) and len(commands) == 2
            and all(isinstance(item, dict) and set(item) == {"ref", "old_oid", "new_oid"} for item in commands),
            "Atomic command shape differs")
    require(commands[0]["ref"] == "refs/heads/main" and isinstance(commands[1]["ref"], str)
            and commands[1]["ref"].startswith("refs/tags/") and commands[1]["old_oid"] == ZERO,
            "Atomic request must assert main and create an absent tag")
    expected = transaction_spec(commands[0]["old_oid"], commands[0]["new_oid"],
                                commands[1]["ref"][10:], commands[1]["new_oid"], value["operation_id"])
    require(value == expected, "Atomic request differs from its canonical identity")
    return expected


def parse_advertisement(raw: bytes, spec: dict) -> dict:
    spec = validate_spec(spec)
    frames = packets(raw, MAX_DISCOVERY)
    require(len(frames) >= 4 and frames[0] == b"# service=git-receive-pack\n"
            and frames[1] is None and frames[-1] is None
            and all(frame is not None for frame in frames[2:-1]), "Smart Git advertisement framing differs")
    first = frames[2]
    assert first is not None
    require(first.count(b"\0") == 1, "Git advertisement lacks unique capabilities")
    initial, capabilities_raw = first.split(b"\0")
    capabilities = text_line(capabilities_raw).split(" ")
    require(all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./:=+-]*", item) for item in capabilities)
            and len(capabilities) == len(set(capabilities)) and len(capabilities) <= 64,
            "Git capabilities are malformed or duplicated")
    names = [value.split("=", 1)[0] for value in capabilities]
    require(len(names) == len(set(names)) and set(CAPABILITIES) <= set(capabilities),
            "Atomic Git capability is not advertised")
    formats = [value for value in capabilities if value.startswith("object-format=")]
    require(not formats or formats == ["object-format=sha1"], "Unsupported Git object format")
    refs: dict[str, str] = {}
    for frame in [initial, *frames[3:-1]]:
        assert frame is not None
        require(b"\0" not in frame, "Unexpected capability suffix")
        parts = text_line(frame).split(" ")
        require(len(parts) == 2 and SHA.fullmatch(parts[0]) is not None and parts[0] != ZERO
                and ref_name(parts[1]) and parts[1] not in refs, "Git ref advertisement is malformed or duplicated")
        refs[parts[1]] = parts[0]
    main, tag = spec["commands"]
    require(refs.get(main["ref"]) == main["new_oid"], "Advertised main differs from the admitted main")
    require(tag["ref"] not in refs and tag["ref"] + "^{}" not in refs, "Advertised tag already exists")
    return {"capabilities": capabilities, "object_format": "sha1", "main_oid": main["new_oid"],
            "tag_absent": True, "ref_count": len(refs), "body_sha256": digest(raw)}


def request_bytes(spec: dict) -> bytes:
    spec = validate_spec(spec)
    commands = spec["commands"]
    rows = [f"{row['old_oid']} {row['new_oid']} {row['ref']}".encode() for row in commands]
    rows[0] += b"\0" + " ".join(CAPABILITIES).encode()
    pack = b"PACK" + struct.pack(">II", 2, 0)
    pack += hashlib.sha1(pack).digest()  # Git's empty SHA-1 pack, not a content-authentication substitute.
    return b"".join(pkt(row + b"\n") for row in rows) + b"0000" + pack


def parse_report(raw: bytes, spec: dict) -> dict:
    spec = validate_spec(spec)
    outer = packets(raw, MAX_STATUS)
    require(outer[-1] is None and all(frame is not None for frame in outer[:-1]), "Sideband stream is incomplete")
    status = bytearray()
    diagnostic = bytearray()
    for frame in outer[:-1]:
        assert frame is not None
        require(len(frame) > 1 and frame[0] in {1, 2}, "Fatal or unsupported sideband channel")
        target = status if frame[0] == 1 else diagnostic
        target.extend(frame[1:])
        require(len(target) <= MAX_DIAGNOSTIC, "Sideband channel exceeds its bound")
    inner = packets(bytes(status), MAX_DIAGNOSTIC)
    require(len(inner) == 4 and inner[-1] is None and all(frame is not None for frame in inner[:-1]),
            "Report must contain unpack and exactly two ref outcomes")
    require(text_line(inner[0]) == "unpack ok", "Git pack was not accepted")
    reports = []
    for frame, command in zip(inner[1:3], spec["commands"]):
        assert frame is not None
        line = text_line(frame)
        if line == "ok " + command["ref"]:
            reports.append({"ref": command["ref"], "status": "ok", "reason": None})
        else:
            prefix = "ng " + command["ref"] + " "
            require(line.startswith(prefix) and 0 < len(line[len(prefix):]) <= 2048,
                    "Ref status is missing, reordered, duplicated or foreign")
            reports.append({"ref": command["ref"], "status": "ng", "reason": line[len(prefix):]})
    require(all(value in {9, 10, 13} or 32 <= value <= 126 for value in diagnostic),
            "Git diagnostic is not bounded printable text")
    return {"unpack": "ok", "refs": reports, "diagnostic": diagnostic.decode("ascii"),
            "body_sha256": digest(raw)}


def admit_report(spec: dict, report: dict) -> str:
    spec = validate_spec(spec)
    if spec["operation_id"].startswith("capability-negative-"):
        require(all(row["status"] == "ng" and row["reason"] == "atomic transaction failed"
                    for row in report["refs"]), "Negative transaction was not wholly refused at the atomic commit")
        main = spec["commands"][0]
        expected = ("cannot lock ref 'refs/heads/main': is at " + main["new_oid"]
                    + " but expected " + main["old_oid"])
        lines = report["diagnostic"].splitlines()
        require(len(lines) == 1 and lines[0] in {expected, "error: " + expected},
                "Negative transaction lacks unambiguous exact stale-main evidence")
        return "confirmed_stale_main_refusal"
    require(all(row["status"] == "ok" for row in report["refs"]), "Atomic ref transaction did not wholly succeed")
    require(re.search(r"(?im)(?:^|\b)(?:error|fatal|bypass(?:ed|ing)?)(?:\b|:)", report["diagnostic"]) is None,
            "Git reported an error or protection bypass despite successful ref statuses")
    return "confirmed_success"


def validate_http(value: object, *, method: str) -> tuple[dict, bytes]:
    maximum = MAX_DISCOVERY if method == "GET" else MAX_STATUS
    require(isinstance(value, dict) and set(value) == {"http_status", "headers", "body_base64"}
            and type(value["http_status"]) is int and 100 <= value["http_status"] <= 599,
            "Git HTTPS response shape is invalid")
    headers = value["headers"]
    require(isinstance(headers, dict) and set(headers) <= SAFE_HEADERS
            and all(isinstance(key, str) and isinstance(item, str) and len(item) <= 8192
                    and all(32 <= ord(c) <= 126 for c in item) for key, item in headers.items()),
            "Git HTTPS headers are invalid")
    raw = unbase64(value["body_base64"], maximum)
    content_type = "application/x-git-receive-pack-" + ("advertisement" if method == "GET" else "result")
    require(value["http_status"] == 200 and headers.get("content-type") == content_type,
            "Git HTTPS did not return its exact protocol response")
    require(headers.get("content-encoding", "identity") == "identity", "Encoded Git HTTP body is unsupported")
    length = headers.get("content-length")
    transfer = headers.get("transfer-encoding")
    require(transfer in {None, "chunked"} and not (length is not None and transfer is not None),
            "Ambiguous Git HTTP framing")
    if length is not None:
        require(re.fullmatch(r"0|[1-9][0-9]*", length) is not None and int(length) == len(raw),
                "Git HTTP length differs")
    return value, raw


class NativeGit:
    """One supervised operator's consumed attempts; not a distributed retry ledger."""

    def __init__(self, *, runner: Callable, deadline: Callable[[], datetime | None],
                 persist: Callable[[], None], http: Callable | None = None) -> None:
        self.runner = runner
        self.deadline = deadline
        self.not_after = deadline()
        self.persist = persist
        self.http = http or self._https
        self.transactions: list[dict] = []
        self.used: set[str] = set()
        self.poisoned = False

    def _remaining(self) -> float:
        deadline = self.deadline()
        require(isinstance(deadline, datetime) and deadline.tzinfo is not None
                and isinstance(self.not_after, datetime) and self.not_after.tzinfo is not None,
                "Absolute Git deadline is required")
        self.not_after = min(self.not_after, deadline)
        timeout = min(30.0, (self.not_after - datetime.now(timezone.utc)).total_seconds())
        require(timeout > 0, "Git transport deadline expired")
        return timeout

    def _https(self, method: str, body: bytes | None) -> dict:
        timeout = self._remaining()
        token = os.environ.get("GH_TOKEN", "")
        require(re.fullmatch(r"[A-Za-z0-9_.-]{20,2048}", token) is not None, "Existing workflow token is unavailable")
        request = {"method": method, "path": DISCOVERY_PATH if method == "GET" else RECEIVE_PATH,
                   "body_base64": base64.b64encode(body or b"").decode(), "token": token,
                   "timeout_seconds": timeout}
        raw_input = encoded(request)
        require(len(raw_input) <= MAX_WORKER_INPUT, "Git worker input exceeds its bound")
        code, raw = self.runner([sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve()), "--https-worker"],
                                input_bytes=raw_input, maximum=MAX_WORKER_OUTPUT, timeout=timeout,
                                cwd=Path(__file__).resolve().parent,
                                environment={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"})
        require(code == 0, "Git HTTPS failed; mutation outcome must not be replayed")
        require(token.encode() not in raw and base64.b64encode(("x-access-token:" + token).encode()) not in raw,
                "Git HTTPS output failed credential redaction")
        value = strict_json(raw, MAX_WORKER_OUTPUT)
        require(isinstance(value, dict), "Git HTTPS worker result is invalid")
        return value

    def exchange(self, spec: dict) -> dict:
        spec = validate_spec(spec)
        require(not self.poisoned and spec["operation_id"] not in self.used,
                "Consumed or uncertain Git mutation cannot be replayed")
        self._remaining()
        self.used.add(spec["operation_id"])
        self.poisoned = True
        observation = {"schema": "marty.native-git-atomic-transaction/v1", "transport": TRANSPORT,
                       "not_after": self.not_after.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                       "request": spec, "discovery": None, "mutation": None, "decision": "unadmitted"}
        self.transactions.append(observation)
        self.persist()
        self._remaining()
        discovery_http = self.http("GET", None)
        observation["discovery"] = {"https": discovery_http}
        _, advertisement = validate_http(discovery_http, method="GET")
        observation["discovery"]["admitted"] = parse_advertisement(advertisement, spec)
        body = request_bytes(spec)
        observation["mutation"] = {"method": "POST", "path": RECEIVE_PATH, "requested_at": utc_now(),
                                   "body_sha256": digest(body), "body_bytes": len(body),
                                   "body_base64": base64.b64encode(body).decode(), "outcome": "unknown", "https": None}
        # The caller durably records this consumed intent before the only POST.
        self.persist()
        self._remaining()
        response_http = self.http("POST", body)
        observation["mutation"]["https"] = response_http
        _, raw = validate_http(response_http, method="POST")
        report = parse_report(raw, spec)
        decision = admit_report(spec, report)
        observation["mutation"].update(report=report, outcome=decision)
        observation["decision"] = decision
        self.persist()
        self._remaining()
        self.poisoned = False
        return observation


def https_once(request: object) -> dict:
    """Private worker: a single TLS-verified canonical request, no redirects/retry."""
    require(isinstance(request, dict) and set(request) == {"method", "path", "body_base64", "token", "timeout_seconds"},
            "Worker request differs")
    method, path = request["method"], request["path"]
    require((method, path) in {("GET", DISCOVERY_PATH), ("POST", RECEIVE_PATH)}, "Worker endpoint differs")
    token = request["token"]
    require(isinstance(token, str) and re.fullmatch(r"[A-Za-z0-9_.-]{20,2048}", token) is not None,
            "Worker credential is unavailable")
    timeout = request["timeout_seconds"]
    require(type(timeout) in {int, float} and 0 < timeout <= 30, "Worker timeout differs")
    body = unbase64(request["body_base64"], 2048)
    require((method == "GET" and not body) or (method == "POST" and body), "Worker body differs")
    maximum = MAX_DISCOVERY if method == "GET" else MAX_STATUS
    # Header parsing and per-read waits are bounded here; the parent's monotonic
    # process-group watchdog additionally bounds DNS, TLS and trickled reads.
    http.client._MAXLINE = 8192
    http.client._MAXHEADERS = 64
    authorization = base64.b64encode(("x-access-token:" + token).encode()).decode()
    connection = http.client.HTTPSConnection(HOST, 443, timeout=min(timeout, 5.0), context=ssl.create_default_context())
    response = None
    try:
        connection.connect()
        headers = {"Authorization": "Basic " + authorization, "User-Agent": "elevenid-release-atomic-git/1",
                   "Accept": "application/x-git-receive-pack-" + ("advertisement" if method == "GET" else "result"),
                   "Accept-Encoding": "identity", "Connection": "close"}
        if method == "POST":
            headers["Content-Type"] = "application/x-git-receive-pack-request"
        connection.request(method, path, body=body if method == "POST" else None, headers=headers)
        response = connection.getresponse()
        require(type(response.status) is int and 100 <= response.status <= 599, "Worker HTTP status differs")
        pairs = response.getheaders()
        require(len(pairs) <= 64 and sum(len(k) + len(v) + 4 for k, v in pairs) <= 32768,
                "Worker HTTP headers exceed their bound")
        safe: dict[str, str] = {}
        for key, value in pairs:
            require(re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key) is not None
                    and all(32 <= ord(c) <= 126 for c in value)
                    and token not in value and authorization not in value, "Worker header is unsafe")
            key = key.lower()
            if key in SAFE_HEADERS:
                require(key not in safe, "Duplicate protocol HTTP header")
                safe[key] = value
        require(safe.get("content-encoding", "identity") == "identity", "Encoded HTTP response refused")
        length, transfer = safe.get("content-length"), safe.get("transfer-encoding")
        require(transfer in {None, "chunked"} and not (length is not None and transfer is not None), "HTTP framing differs")
        if length is not None:
            require(re.fullmatch(r"0|[1-9][0-9]*", length) is not None and int(length) <= maximum, "HTTP body is oversized")
        raw = response.read(maximum + 1)
        require(len(raw) <= maximum and token.encode() not in raw and authorization.encode() not in raw,
                "Worker body is unsafe")
        if length is not None:
            require(len(raw) == int(length), "Worker HTTP body is incomplete")
        return {"http_status": response.status, "headers": safe, "body_base64": base64.b64encode(raw).decode()}
    finally:
        if response is not None:
            response.close()
        connection.close()


def worker_main() -> int:
    try:
        require(sys.argv[1:] == ["--https-worker"], "This module has no public mutation CLI")
        request = strict_json(sys.stdin.buffer.read(MAX_WORKER_INPUT + 1), MAX_WORKER_INPUT)
        sys.stdout.buffer.write(encoded(https_once(request)))
        return 0
    except Exception:
        # Never print an exception, URL, header, body, environment or credential.
        sys.stdout.buffer.write(b'{"status":"transport_refused"}\n')
        return 1


if __name__ == "__main__":
    raise SystemExit(worker_main())
