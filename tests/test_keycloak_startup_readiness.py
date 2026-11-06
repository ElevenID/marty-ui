"""Cold-start polling stays within one budget and never accepts late discovery."""
from pathlib import Path
import subprocess
import sys
from urllib.error import HTTPError, URLError

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import probe_keycloak_remote_rs256 as probe  # noqa: E402


class Clock:
    now = 0.0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        assert seconds > 0
        self.now += seconds


@pytest.fixture
def clock(monkeypatch):
    clock = Clock()
    monkeypatch.setattr(probe.time, 'monotonic', clock.monotonic)
    monkeypatch.setattr(probe.time, 'sleep', clock.sleep)
    return clock


def running(*_args, **kwargs):
    assert 0 < kwargs['timeout'] <= 5
    return subprocess.CompletedProcess([], 0, 'true\n', '')


def test_default_budget_accepts_cold_start_after_old_35_second_limit(monkeypatch, clock):
    calls = []

    def discovery(url, *, timeout):
        assert url == 'http://127.0.0.1:8180/realms/master/.well-known/openid-configuration'
        assert 0 < timeout <= 5
        calls.append(clock.now)
        clock.now += timeout
        if clock.now < 45:
            raise ConnectionResetError('synthetic private detail')
        return {}

    inspected = []

    def inspect(args, **kwargs):
        inspected.append(args)
        return running(args, **kwargs)

    monkeypatch.setattr(probe, 'http_json', discovery)
    monkeypatch.setattr(probe.subprocess, 'run', inspect)
    probe.wait_for_keycloak('http://127.0.0.1:8180', 'owned-keycloak')
    assert 35 < clock.now < 180
    assert len(calls) > 1
    assert all(args == ['docker', 'inspect', '-f', '{{.State.Running}}', 'owned-keycloak'] for args in inspected)


@pytest.mark.parametrize('error', [
    ConnectionResetError('synthetic-private'),
    URLError('synthetic-private'),
    HTTPError('http://synthetic-private', 503, 'synthetic-private', {}, None),
])
def test_exhaustion_caps_requests_and_does_not_expose_errors(monkeypatch, clock, error):
    timeouts = []

    def unavailable(_url, *, timeout):
        assert 0 < timeout <= 5
        timeouts.append(timeout)
        clock.now += timeout
        raise error

    monkeypatch.setattr(probe, 'http_json', unavailable)
    monkeypatch.setattr(probe.subprocess, 'run', running)
    with pytest.raises(RuntimeError, match='OIDC discovery did not become ready') as observed:
        probe.wait_for_keycloak('http://127.0.0.1:8180', 'owned-keycloak', seconds=7)
    assert clock.now == pytest.approx(7)
    assert timeouts[-1] < 5
    assert 'synthetic-private' not in str(observed.value)


def test_discovery_success_after_deadline_is_refused(monkeypatch, clock):
    def late(_url, *, timeout):
        assert timeout == 2
        clock.now += 3
        return {}

    monkeypatch.setattr(probe, 'http_json', late)
    monkeypatch.setattr(probe.subprocess, 'run', lambda *_args, **_kwargs: pytest.fail('Late success must not inspect or retry'))
    with pytest.raises(RuntimeError, match='OIDC discovery did not become ready'):
        probe.wait_for_keycloak('http://127.0.0.1:8180', 'owned-keycloak', seconds=2)


def test_inspection_and_sleep_use_remaining_budget(monkeypatch, clock):
    def unavailable(_url, *, timeout):
        assert timeout == 2
        clock.now += 1.8
        raise ConnectionResetError()

    def inspect(_args, **kwargs):
        assert kwargs['timeout'] == pytest.approx(.2)
        clock.now += .1
        return subprocess.CompletedProcess([], 0, 'true\n', '')

    monkeypatch.setattr(probe, 'http_json', unavailable)
    monkeypatch.setattr(probe.subprocess, 'run', inspect)
    with pytest.raises(RuntimeError, match='OIDC discovery did not become ready'):
        probe.wait_for_keycloak('http://127.0.0.1:8180', 'owned-keycloak', seconds=2)
    assert clock.now == pytest.approx(2)


def test_exited_container_refuses_without_another_request(monkeypatch, clock):
    def unavailable(_url, **_kwargs):
        raise ConnectionResetError()

    monkeypatch.setattr(probe, 'http_json', unavailable)
    monkeypatch.setattr(probe.subprocess, 'run', lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, 'false\n', ''))
    with pytest.raises(RuntimeError, match='Keycloak exited before OIDC discovery'):
        probe.wait_for_keycloak('http://127.0.0.1:8180', 'owned-keycloak')
    assert clock.now == 0


@pytest.mark.parametrize('failure', [subprocess.TimeoutExpired(['synthetic-private'], 1), OSError('synthetic-private')])
def test_inspection_failure_has_fixed_safe_diagnostics(monkeypatch, clock, failure):
    def unavailable(_url, **_kwargs):
        raise ConnectionResetError()

    def inspect(*_args, **_kwargs):
        raise failure

    monkeypatch.setattr(probe, 'http_json', unavailable)
    monkeypatch.setattr(probe.subprocess, 'run', inspect)
    with pytest.raises(RuntimeError, match='Keycloak container state unavailable') as observed:
        probe.wait_for_keycloak('http://127.0.0.1:8180', 'owned-keycloak')
    assert 'synthetic-private' not in str(observed.value)
    assert observed.value.__suppress_context__


@pytest.mark.parametrize('seconds', [0, -1, 181, float('inf'), float('nan'), True, '180'])
def test_invalid_or_unbounded_budget_is_refused(clock, seconds):
    with pytest.raises(ValueError, match='Invalid Keycloak startup budget'):
        probe.wait_for_keycloak('http://127.0.0.1:8180', 'owned-keycloak', seconds=seconds)
