"""Keep dependency retries bounded without weakening the theme test inputs."""
import hashlib
import io
import ssl
import urllib.error
import urllib.request

import pytest

from tests import keycloak_freemarker as dependency

VALID = b"synthetic FreeMarker bytes for acquisition guards"
LOGIN_OVERRIDE = "KEYCLOAK_LOGIN_FREEMARKER_JAR"
EMAIL_OVERRIDE = "KEYCLOAK_EMAIL_FREEMARKER_JAR"


class Response(io.BytesIO):
    def __init__(self, data, url, status=200):
        super().__init__(data)
        self.url = url
        self.status = status
        self.read_limits = []

    def read(self, limit):
        self.read_limits.append(limit)
        return super().read(limit)


@pytest.fixture
def network(monkeypatch):
    monkeypatch.delenv(LOGIN_OVERRIDE, raising=False)
    monkeypatch.delenv(EMAIL_OVERRIDE, raising=False)
    monkeypatch.setattr(dependency, "JAR_SHA256", hashlib.sha256(VALID).hexdigest())

    class Opener:
        def __init__(self, outcomes):
            self.outcomes = list(outcomes)
            self.calls = []
            self.handlers = []
            self.sleeps = []

        def open(self, url, timeout):
            self.calls.append((url, timeout))
            outcome = self.outcomes.pop(0)
            if isinstance(outcome, BaseException):
                raise outcome
            if callable(outcome):
                return outcome(self, url)
            return outcome if isinstance(outcome, Response) else Response(outcome, url)

    def configure(*outcomes):
        opener = Opener(outcomes)

        def build_opener(handler):
            opener.handlers.append(handler)
            return opener

        monkeypatch.setattr(urllib.request, "build_opener", build_opener)
        monkeypatch.setattr(dependency.time, "sleep", opener.sleeps.append)
        return opener

    return configure


def http_error(code):
    return urllib.error.HTTPError(dependency.JAR_URL, code, "synthetic response", {}, None)


def test_artifact_identity_and_acquisition_budget_stay_pinned():
    primary = "https://repo.maven.apache.org/maven2/org/freemarker/freemarker/2.3.35/freemarker-2.3.35.jar"
    alternate = "https://repo1.maven.org/maven2/org/freemarker/freemarker/2.3.35/freemarker-2.3.35.jar"
    assert dependency.JAR_ATTEMPTS == (primary, alternate, primary)
    assert dependency.JAR_SHA256 == "0fac87dddd78f1223139e8ef88e819c7f483c0a3835cdf5982ad5e4576d1d896"
    assert dependency.MAX_JAR_BYTES == 4 * 1024 * 1024
    assert dependency.REQUEST_TIMEOUT_SECONDS == 30


def test_primary_success_reads_bounded_bytes_once(network):
    response = Response(VALID, dependency.JAR_URL)
    opener = network(response)
    assert dependency.load_freemarker_jar() == VALID
    assert opener.calls == [(dependency.JAR_URL, 30)]
    assert response.read_limits == [dependency.MAX_JAR_BYTES + 1]
    assert len(opener.handlers) == 1 and isinstance(opener.handlers[0], dependency.NoRedirect)
    assert opener.sleeps == []


@pytest.mark.parametrize("error", [
    http_error(code) for code in (404, 408, 429, 500, 502, 503, 504, 599)
] + [TimeoutError(), ConnectionResetError(), urllib.error.URLError(TimeoutError())])
def test_acquisition_failure_uses_only_the_official_alternate(network, error):
    opener = network(error, VALID)
    assert dependency.load_freemarker_jar() == VALID
    assert opener.calls == [(dependency.JAR_URL, 30), (dependency.JAR_FALLBACK_URL, 30)]
    assert opener.sleeps == [1]


def test_acquisition_exhaustion_stops_after_three_attempts(network):
    final_error = http_error(404)
    opener = network(http_error(404), TimeoutError(), final_error, VALID)
    with pytest.raises(urllib.error.HTTPError) as raised:
        dependency.load_freemarker_jar()
    assert raised.value is final_error
    assert opener.calls == [(url, 30) for url in dependency.JAR_ATTEMPTS]
    assert opener.sleeps == [1, 2]
    assert opener.outcomes == [VALID]


@pytest.mark.parametrize("error", [
    http_error(code) for code in (301, 302, 307, 308, 400, 401, 403)
] + [urllib.error.URLError(ssl.SSLCertVerificationError(1, "invalid certificate")),
     urllib.error.URLError("unclassified failure")])
def test_nonretryable_failures_stop_before_another_request(network, error):
    opener = network(error, VALID)
    with pytest.raises(type(error)) as raised:
        dependency.load_freemarker_jar()
    assert raised.value is error
    assert len(opener.calls) == 1
    assert opener.sleeps == []


def test_redirect_handler_refuses_redirect_without_fallback(network):
    def redirect(opener, url):
        return opener.handlers[0].redirect_request(
            urllib.request.Request(url), None, 302, "Found", {}, dependency.JAR_FALLBACK_URL)

    opener = network(redirect, VALID)
    with pytest.raises(ValueError, match="must not redirect"):
        dependency.load_freemarker_jar()
    assert len(opener.calls) == 1
    assert opener.sleeps == []


@pytest.mark.parametrize("data,url,status,message", [
    (b"corrupt bytes", dependency.JAR_URL, 200, "SHA256 mismatch"),
    (b"x" * (dependency.MAX_JAR_BYTES + 1), dependency.JAR_URL, 200, "maximum size"),
    (VALID, dependency.JAR_FALLBACK_URL, 200, "URL or status mismatch"),
    (VALID, dependency.JAR_URL, 206, "URL or status mismatch"),
])
def test_integrity_failures_are_fatal_without_fallback(network, data, url, status, message):
    opener = network(Response(data, url, status), VALID)
    with pytest.raises(ValueError, match=message):
        dependency.load_freemarker_jar()
    assert len(opener.calls) == 1
    assert opener.sleeps == []


def test_corrupt_alternate_cannot_be_hidden_by_a_third_download(network):
    opener = network(http_error(404), Response(b"corrupt", dependency.JAR_FALLBACK_URL), VALID)
    with pytest.raises(ValueError, match="SHA256 mismatch"):
        dependency.load_freemarker_jar()
    assert opener.calls == [(dependency.JAR_URL, 30), (dependency.JAR_FALLBACK_URL, 30)]
    assert opener.sleeps == [1]
    assert opener.outcomes == [VALID]


def test_login_override_takes_precedence_without_network(network, monkeypatch, tmp_path):
    opener = network()
    login = tmp_path / "login.jar"
    login.write_bytes(VALID)
    monkeypatch.setenv(LOGIN_OVERRIDE, str(login))
    monkeypatch.setenv(EMAIL_OVERRIDE, str(tmp_path / "missing-email.jar"))
    assert dependency.load_freemarker_jar(LOGIN_OVERRIDE, EMAIL_OVERRIDE) == VALID
    assert opener.handlers == [] and opener.calls == []


@pytest.mark.parametrize("login_value", [None, ""])
def test_email_override_is_used_when_login_override_is_empty(network, monkeypatch, tmp_path, login_value):
    opener = network()
    email = tmp_path / "email.jar"
    email.write_bytes(VALID)
    if login_value is not None:
        monkeypatch.setenv(LOGIN_OVERRIDE, login_value)
    monkeypatch.setenv(EMAIL_OVERRIDE, str(email))
    assert dependency.load_freemarker_jar(LOGIN_OVERRIDE, EMAIL_OVERRIDE) == VALID
    assert dependency.load_freemarker_jar(EMAIL_OVERRIDE) == VALID
    assert opener.handlers == [] and opener.calls == []


@pytest.mark.parametrize("invalid", ["missing", "digest", "size"])
def test_invalid_first_override_never_uses_email_or_network(network, monkeypatch, tmp_path, invalid):
    opener = network()
    login = tmp_path / "invalid-login.jar"
    email = tmp_path / "email.jar"
    email.write_bytes(VALID)
    if invalid != "missing":
        login.write_bytes(b"corrupt" if invalid == "digest" else b"x" * (dependency.MAX_JAR_BYTES + 1))
    monkeypatch.setenv(LOGIN_OVERRIDE, str(login))
    monkeypatch.setenv(EMAIL_OVERRIDE, str(email))
    with pytest.raises(FileNotFoundError if invalid == "missing" else ValueError):
        dependency.load_freemarker_jar(LOGIN_OVERRIDE, EMAIL_OVERRIDE)
    assert opener.handlers == [] and opener.calls == []
