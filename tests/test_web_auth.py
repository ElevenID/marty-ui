"""Private access is explicit and scoped; credentials never select trust/code."""
from __future__ import annotations

import base64
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import ui_release as ui
import web_auth as auth

TOKEN = "ghs_" + "a" * 36
ENCODED = base64.b64encode(("operator:" + TOKEN).encode()).decode()


@pytest.fixture
def registry(tmp_path):
    tmp_path.chmod(0o700)
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"auths": {"ghcr.io": {"auth": ENCODED}}}))
    path.chmod(0o600)
    return path


def test_only_selected_registry_auth_reaches_private_children(registry, monkeypatch):
    original = {"auths": {"ghcr.io": {"auth": ENCODED}, "elsewhere.invalid": {"auth": "other-secret"}},
                "credsStore": "must-not-run", "credHelpers": {"ghcr.io": "must-not-run"},
                "HttpHeaders": {"Authorization": "never-copy"}, "proxies": {"default": {"httpsProxy": "never-copy"}}}
    registry.write_text(json.dumps(original))
    before = registry.read_bytes()
    injected = ("GH_TOKEN", "GITHUB_TOKEN", "DOCKER_CONFIG", "REGISTRY_AUTH_FILE", "DOCKER_AUTH_CONFIG",
                "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE",
                "COSIGN_REPOSITORY", "COSIGN_DOCKER_MEDIA_TYPES", "PATH")
    for name in injected:
        monkeypatch.setenv(name, "must-not-inherit")
    locations = []
    def execute(args, *, env, directory, **kwargs):
        locations.append(directory)
        assert env["DOCKER_CONFIG"] == directory == env["HOME"]
        assert env["GH_HOST"] == "github.com"
        assert set(env).isdisjoint(set(injected) - {"DOCKER_CONFIG"})
        held = Path(directory) / "config.json"
        assert held.stat().st_mode & 0o777 == 0o600
        assert held.parent.stat().st_mode & 0o777 == 0o700
        assert json.loads(held.read_bytes()) == {"auths": {"ghcr.io": {"auth": ENCODED}}}
        assert TOKEN not in " ".join(args) and ENCODED not in " ".join(args)
        return b"verified"
    monkeypatch.setattr(auth, "command", execute)
    assert auth.registry_command(["/verified/gh", "attestation", "verify"], config=registry) == "verified"
    assert registry.read_bytes() == before
    assert all(not Path(path).exists() for path in locations)


@pytest.mark.parametrize("value", [
    {}, {"auths": {}}, {"auths": {"https://ghcr.io": {"auth": ENCODED}}},
    {"auths": {"ghcr.io": {"identitytoken": TOKEN}}},
    {"auths": {"ghcr.io": {"auth": ENCODED, "password": TOKEN}}},
    {"auths": {"ghcr.io": {"auth": "invalid!"}}},
    {"auths": {"ghcr.io": {"auth": base64.b64encode(b"operator:").decode()}}},
    {"auths": {"ghcr.io": {"auth": base64.b64encode(("operator:"+TOKEN+"\n").encode()).decode()}}},
])
def test_missing_malformed_or_ambiguous_credentials_fail_closed(registry, value):
    registry.write_text(json.dumps(value))
    with pytest.raises(ValueError):
        auth.registry_auth(registry)


@pytest.mark.parametrize("username", ["operator", "github-actions[bot]", "dependabot[bot]"])
def test_actions_bot_actor_and_opaque_token_are_supported(registry, username):
    value = base64.b64encode((username + ":opaque.token:/+~").encode()).decode()
    registry.write_text(json.dumps({"auths": {"ghcr.io": {"auth": value}}}))
    assert json.loads(auth.registry_auth(registry)) == {"auths": {"ghcr.io": {"auth": value}}}


@pytest.mark.parametrize("fault", ["symlink", "public-file", "public-directory", "duplicate", "oversize"])
def test_secret_file_ownership_shape_and_bounds(registry, fault):
    if fault == "symlink":
        target = registry.with_name("link.json")
        target.symlink_to(registry)
        registry = target
    elif fault == "public-file":
        registry.chmod(0o644)
    elif fault == "public-directory":
        registry.parent.chmod(0o755)
    elif fault == "duplicate":
        registry.write_text('{"auths":{},"auths":{}}')
    else:
        registry.write_bytes(b"x" * (auth.CONFIG_LIMIT + 1))
    with pytest.raises(ValueError):
        auth.registry_auth(registry)


def reader(tmp_path, monkeypatch, **changes):
    gh = tmp_path / "gh"
    gh.write_bytes(b"pinned tool fixture, never executed")
    monkeypatch.setenv("GH_TOKEN", TOKEN)
    values = dict(gh=gh, repository=ui.REPOSITORY, run_id="21", attempt="2", kind="website", token_env="GH_TOKEN")
    values.update(changes)
    return auth.GitHubReader(**values)


def test_api_metadata_and_zip_share_one_explicit_token_without_registry_auth(tmp_path, monkeypatch):
    selected = reader(tmp_path, monkeypatch)
    monkeypatch.setenv("GH_TOKEN", "ghs_" + "b" * 36)
    for name in ("DOCKER_CONFIG", "REGISTRY_AUTH_FILE", "HTTPS_PROXY", "GH_HOST", "GH_ENTERPRISE_TOKEN"):
        monkeypatch.setenv(name, "must-not-inherit")
    calls = []
    def execute(args, *, env, directory, maximum, **_kwargs):
        calls.append((args, maximum))
        assert env["GH_TOKEN"] == TOKEN and env["GH_HOST"] == "github.com"
        assert not {"DOCKER_CONFIG", "REGISTRY_AUTH_FILE", "HTTPS_PROXY", "GH_ENTERPRISE_TOKEN"}.intersection(env)
        assert args[1:6] == ["api", "--hostname", "github.com", "--method", "GET"]
        assert TOKEN not in " ".join(args)
        return b"zip" if args[-1].endswith("/zip") else b"{}"
    monkeypatch.setattr(auth, "command", execute)
    assert selected.attempt() == "{}"
    assert selected.artifacts() == "{}"
    assert selected.archive(55, maximum=3) == b"zip"
    assert calls[0][0][-1].endswith("/runs/21/attempts/2")
    assert calls[1][0][-1].endswith("/runs/21/artifacts?name=web-website-21-2&per_page=100")
    assert calls[2][0][-1].endswith("/artifacts/55/zip") and calls[2][1] == 3


def test_default_api_token_is_only_gh_token_and_alternate_requires_selection(tmp_path, monkeypatch):
    gh = tmp_path / "gh"
    gh.write_bytes(b"pinned tool fixture, never executed")
    values = dict(gh=gh, repository=ui.REPOSITORY, run_id="21", attempt="2", kind="website")
    other = "ghs_" + "b" * 36
    monkeypatch.setenv("GH_TOKEN", TOKEN)
    monkeypatch.setenv("GITHUB_TOKEN", other)
    selected = auth.GitHubReader(**values)
    calls = []
    def execute(args, *, env, **kwargs):
        calls.append(env)
        assert "GITHUB_TOKEN" not in env
        return b"{}"
    monkeypatch.setattr(auth, "command", execute)
    monkeypatch.delenv("GH_TOKEN")
    assert selected.attempt() == "{}"
    assert calls[-1]["GH_TOKEN"] == TOKEN
    with pytest.raises(ValueError, match="token is missing"):
        auth.GitHubReader(**values)
    alternate = auth.GitHubReader(**values, token_env="GITHUB_TOKEN")
    assert alternate.attempt() == "{}"
    assert calls[-1]["GH_TOKEN"] == other


@pytest.mark.parametrize("changes", [
    {"token_env": None}, {"token_env": "AWS_SECRET_ACCESS_KEY"}, {"repository": "Elsewhere/repo"},
    {"run_id": "0"}, {"run_id": "21/../../secrets"}, {"attempt": "main"}, {"kind": "backend"},
])
def test_api_selection_is_closed(tmp_path, monkeypatch, changes):
    with pytest.raises(ValueError):
        reader(tmp_path, monkeypatch, **changes)


@pytest.mark.parametrize("endpoint", [
    "https://elsewhere.invalid/repos/ElevenID/marty-ui/actions/runs/21/attempts/2",
    "repos/Elsewhere/repo/actions/artifacts/55/zip", "repos/ElevenID/marty-ui/actions/runs/22/attempts/2",
    "repos/ElevenID/marty-ui/actions/runs/21/artifacts?name=other&per_page=100",
    "repos/ElevenID/marty-ui/actions/artifacts/0/zip", "repos/ElevenID/marty-ui/actions/artifacts/55/zip?other=1",
    "repos/ElevenID/marty-ui/actions/runs/21/attempts/2 --method POST",
])
def test_api_rejects_any_other_endpoint_before_execution(tmp_path, monkeypatch, endpoint):
    selected = reader(tmp_path, monkeypatch)
    monkeypatch.setattr(auth, "command", lambda *_args, **_kwargs: pytest.fail("unexpected transport"))
    with pytest.raises(ValueError):
        selected._read(endpoint, maximum=auth.verifier.MAX_OUTPUT)


@pytest.mark.parametrize("source,maximum,expected", [
    ("import os; os.write(1,b'x'*1024)", 16, "output limit"),
    ("import os; os.write(2,b'x'*100000)", 16, "output limit"),
    ("import sys; sys.stderr.write('UNAUTHORIZED secret-value https://private.invalid'); sys.exit(1)", 16, "authentication"),
])
def test_real_child_output_is_bounded_and_errors_are_redacted(tmp_path, source, maximum, expected):
    with pytest.raises(ValueError, match=expected) as result:
        auth.command([sys.executable, "-c", source], env=auth.environment(str(tmp_path)),
                     directory=str(tmp_path), maximum=maximum, label="test transport", timeout=5)
    assert "secret-value" not in str(result.value) and "private.invalid" not in str(result.value)
