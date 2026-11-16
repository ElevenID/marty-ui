"""Synthetic HTTP responses exercise transport bounds without remote requests."""
import io
from pathlib import Path
import sys
import urllib.error

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_candidate_rendezvous as transport


DEFAULT_LIMIT = 65536
RELEASE_LIMIT = 4 * 1024 * 1024
RELEASE_PATH = transport.REPO + "/releases/tags/v1.2.3-nightly.20261116.1"


def json_payload(size):
    prefix, suffix = b'{"body":"', b'"}'
    return prefix + b"x" * (size - len(prefix) - len(suffix)) + suffix


class Response(io.BytesIO):
    status = 201

    def __init__(self, raw):
        super().__init__(raw)
        self.bytes_read = 0

    def read(self, size=-1):
        raw = super().read(size)
        self.bytes_read += len(raw)
        return raw

    def read1(self, size):
        return self.read(size)


class Opener:
    def __init__(self, raw):
        self.response = Response(raw)
        self.requests = []

    def open(self, request, timeout):
        assert timeout == 20
        self.requests.append(request)
        return self.response


def client_with_response(raw):
    client = transport.Client("synthetic-token")
    client.opener = Opener(raw)
    return client


@pytest.mark.parametrize("size", [DEFAULT_LIMIT + 1, RELEASE_LIMIT])
def test_release_by_tag_get_accepts_metadata_up_to_four_mib(size):
    raw = json_payload(size)
    client = client_with_response(raw)
    value = client.request("GET", RELEASE_PATH)
    assert value == {"body": "x" * (size - len(b'{"body":""}'))}
    assert client.opener.response.bytes_read == size
    request, = client.opener.requests
    assert request.full_url == "https://api.github.com" + RELEASE_PATH
    assert request.get_method() == "GET" and request.data is None
    assert request.get_header("Authorization") == "Bearer synthetic-token"


def test_release_by_tag_get_stops_at_the_four_mib_limit():
    client = client_with_response(json_payload(RELEASE_LIMIT + 10000))
    with pytest.raises(ValueError, match="transport response exceeds bound"):
        client.request("GET", RELEASE_PATH)
    assert client.opener.response.bytes_read == RELEASE_LIMIT + 1


@pytest.mark.parametrize("method,path,body", [
    ("GET", "/releases", None),
    ("GET", "/releases/123", None),
    ("GET", "/releases/123/assets?per_page=100", None),
    ("GET", "/releases/tags/v1.2.3?per_page=100", None),
    ("GET", "/releases/tags/v1.2.3/", None),
    ("GET", "/releases/tags/v1.2.3/assets", None),
    ("GET", "/releases/tags/v1.2.3%2Fextra", None),
    ("GET", "/releases/tag/v1.2.3", None),
    ("GET", "/actions/runs/123", None),
    ("GET", "/actions/runs/123/artifacts?per_page=100", None),
    ("GET", "/actions/artifacts/123", None),
    ("GET", "/git/ref/tags/v1.2.3", None),
    ("GET", "/git/tags/" + "a" * 40, None),
    ("POST", "/releases", {"draft": True}),
    ("PATCH", "/releases/123", {"draft": True}),
    ("DELETE", "/releases/123", None),
])
def test_other_api_responses_retain_the_64_kib_stream_limit(method, path, body):
    client = client_with_response(json_payload(DEFAULT_LIMIT + 10000))
    with pytest.raises(ValueError, match="transport response exceeds bound"):
        client.request(method, transport.REPO + path, body)
    assert client.opener.response.bytes_read == DEFAULT_LIMIT + 1


@pytest.mark.parametrize("method,body", [
    ("POST", None), ("PATCH", None), ("DELETE", None), ("HEAD", None),
    ("GET", {}),
])
def test_release_by_tag_observation_refuses_mutations_and_get_bodies(method, body):
    client = client_with_response(b"{}")
    with pytest.raises(ValueError, match="read-only"):
        client.request(method, RELEASE_PATH, body)
    assert client.opener.requests == []


def test_release_by_tag_bound_does_not_allow_another_repository():
    client = client_with_response(b"{}")
    with pytest.raises(ValueError, match="invalid transport API path"):
        client.request("GET", RELEASE_PATH.replace("ElevenID/marty-ui", "other/repository"))
    assert client.opener.requests == []


@pytest.mark.parametrize("raw", [
    b"", b"{", b'{"body":"\xff"}', b'{"assets":[],"assets":[]}',
    b'{"assets":[{"name":"first","name":"second"}]}',
    b'{"number":NaN}', b'{"number":Infinity}', b'{"number":-Infinity}',
])
def test_release_by_tag_metadata_rejects_malformed_duplicate_and_nonfinite_json(raw):
    client = client_with_response(raw)
    with pytest.raises(ValueError):
        client.request("GET", RELEASE_PATH)


def test_release_by_tag_metadata_never_follows_a_redirect():
    client = client_with_response(b"{}")
    requests = []

    def redirect(request, timeout):
        requests.append(request)
        raise urllib.error.HTTPError(request.full_url, 302, "redirect", {
            "Location": "https://release-assets.githubusercontent.com/synthetic"
        }, None)

    client.opener.open = redirect
    with pytest.raises(ValueError, match="GitHub transport request failed"):
        client.request("GET", RELEASE_PATH)
    assert len(requests) == 1


def test_release_by_tag_response_deadline_is_unchanged(monkeypatch):
    client = client_with_response(b"{}")
    moments = iter([0, 60])
    monkeypatch.setattr(transport.time, "monotonic", lambda: next(moments))
    with pytest.raises(ValueError, match="transport response timed out"):
        client.request("GET", RELEASE_PATH)
    assert client.opener.response.bytes_read == 0


@pytest.mark.parametrize("operation", ["whoami", "receipt-upload-response"])
def test_identity_and_receipt_upload_responses_keep_64_kib(operation):
    client = client_with_response(json_payload(DEFAULT_LIMIT + 1))
    with pytest.raises(ValueError, match="transport response exceeds bound"):
        if operation == "whoami":
            client.whoami()
        else:
            client.upload_receipt(123, b"{}")


@pytest.mark.parametrize("operation", ["release-by-id", "whoami", "receipt-upload-response"])
def test_default_json_boundary_accepts_exactly_64_kib(operation):
    client = client_with_response(json_payload(DEFAULT_LIMIT))
    if operation == "release-by-id":
        value = client.request("GET", transport.REPO + "/releases/123")
    elif operation == "whoami":
        value = client.whoami()
    else:
        value = client.upload_receipt(123, b"{}")
    assert value == {"body": "x" * (DEFAULT_LIMIT - len(b'{"body":""}'))}


@pytest.mark.parametrize("operation", ["download", "upload"])
def test_receipt_transfer_inputs_cannot_use_the_release_metadata_allowance(operation):
    client = client_with_response(b"{}")
    with pytest.raises(ValueError, match="invalid receipt"):
        if operation == "download":
            client.download(123, DEFAULT_LIMIT + 1)
        else:
            client.upload_receipt(123, b"x" * (DEFAULT_LIMIT + 1))
    assert client.opener.requests == []
