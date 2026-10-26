"""Public operator lifecycle and isolation at the installed machine boundary."""

import asyncio
import json
import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import run_selfhost_machine_journey as wrapper

ORG = "11111111-1111-4111-8111-111111111111"
KEY_ID = "22222222-2222-4222-8222-222222222222"
KEY = "mk_test_private-lifecycle-fixture"


def test_real_child_receives_private_key_without_bootstrap_credentials(tmp_path):
    checkout = tmp_path / "integration"
    journey = checkout / wrapper.JOURNEY
    journey.parent.mkdir(parents=True)
    journey.write_text(
        "import os\nfrom pathlib import Path\n"
        "def test_child_boundary():\n"
        "    assert 'SELFHOST_TEST_PASSWORD' not in os.environ\n"
        "    assert 'MARTY_API_KEY' not in os.environ\n"
        "    assert 'PYTEST_ADDOPTS' not in os.environ\n"
        "    assert Path(os.environ['SELFHOST_OPERATOR_API_KEY_FILE']).read_text().startswith('mk_test_')\n",
        encoding="utf-8",
    )
    wrapper.component(checkout, {**os.environ, "SELFHOST_TEST_PASSWORD": "private",
                                  "MARTY_API_KEY": "other-key", "PYTEST_ADDOPTS": "--showlocals"}, KEY)


@pytest.mark.parametrize("child_failure", [False, True])
def test_component_has_only_private_key_and_public_inputs(monkeypatch, tmp_path, child_failure):
    observed = []
    environment = {name: "public-fixture" for name in wrapper.PUBLIC_INPUTS}
    environment.update({"PATH": os.environ.get("PATH", ""), "SELFHOST_TEST_PASSWORD": "private",
                        "TEST_PASSWORD": "private", "MARTY_API_KEY": "other-key",
                        "HTTP_PROXY": "http://private.invalid", "PYTEST_ADDOPTS": "--showlocals"})

    def run(argv, **kwargs):
        child_env = kwargs["env"]
        assert set(child_env) == {"PATH", *wrapper.PUBLIC_INPUTS,
                                  "SELFHOST_OPERATOR_API_KEY_FILE", "PYTHONDONTWRITEBYTECODE",
                                  "PYTEST_DISABLE_PLUGIN_AUTOLOAD"}
        path = Path(child_env["SELFHOST_OPERATOR_API_KEY_FILE"])
        observed.append(path)
        assert path.read_text(encoding="ascii") == KEY
        if os.name == "posix":
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
            assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
        assert argv[-1] == wrapper.JOURNEY
        assert kwargs["cwd"] == tmp_path and kwargs["timeout"] == 900
        assert "-p" in argv and "pytest_asyncio.plugin" in argv
        return SimpleNamespace(returncode=int(child_failure), stdout=KEY, stderr=KEY)

    monkeypatch.setattr(wrapper.subprocess, "run", run)
    if child_failure:
        with pytest.raises(ValueError, match="component failed") as failure:
            wrapper.component(tmp_path, environment, KEY)
        assert KEY not in str(failure.value)
    else:
        wrapper.component(tmp_path, environment, KEY)
    assert len(observed) == 1 and not observed[0].parent.exists()


@pytest.mark.parametrize("fault", [None, "component", "scopes", "expiry", "key", "delete", "still_active"])
def test_public_operator_is_retired_on_success_and_failure(monkeypatch, tmp_path, fault):
    calls = []
    executed = []
    environment = {"SELFHOST_GATEWAY_URL": "https://gateway.example.invalid",
                   "SELFHOST_ORG_ID": ORG}
    receipt = tmp_path / "operator-lifecycle.json"

    def handle(request):
        calls.append((request.method, request.url.path))
        assert request.url.params["organization_id"] == ORG
        if request.method == "POST":
            assert request.headers["cookie"] == "sessionId=private-session"
            assert "x-api-key" not in request.headers
            requested = json.loads(request.content)
            assert requested["scopes"] == ["admin:full"] and requested["is_test"] is True
            return httpx.Response(201, json={
                "id": KEY_ID, "organization_id": ORG, "key": KEY if fault != "key" else None,
                "scopes": requested["scopes"] if fault != "scopes" else ["credentials:read"],
                "enabled": True, "expires_at": requested["expires_at"] if fault != "expiry" else None,
            })
        if request.method == "DELETE":
            assert request.url.path.endswith(KEY_ID)
            assert request.headers["cookie"] == "sessionId=private-session"
            return httpx.Response(503 if fault == "delete" else 200, json={"success": True})
        assert "cookie" not in request.headers and "authorization" not in request.headers
        assert request.headers["x-api-key"] == KEY
        return httpx.Response(200 if fault == "still_active" else 401)

    def child(*args):
        executed.append(args)
        if fault == "component":
            raise ValueError("public machine journey component failed")

    monkeypatch.setattr(wrapper, "component", child)
    real_client = httpx.AsyncClient
    transport = httpx.MockTransport(handle)

    def isolated_probe(**kwargs):
        assert kwargs["trust_env"] is False and kwargs["follow_redirects"] is False
        return real_client(**kwargs, transport=transport)

    monkeypatch.setattr(wrapper.httpx, "AsyncClient", isolated_probe)

    async def exercise():
        async with real_client(base_url=environment["SELFHOST_GATEWAY_URL"], transport=transport,
                               cookies={"sessionId": "private-session"}) as client:
            await wrapper.exercise(client, tmp_path, environment, receipt)

    if fault:
        with pytest.raises((TypeError, ValueError, httpx.HTTPError)):
            asyncio.run(exercise())
    else:
        asyncio.run(exercise())
    assert calls[:2] == [("POST", "/v1/api-keys"), ("DELETE", "/v1/api-keys/" + KEY_ID)]
    record = json.loads(receipt.read_text(encoding="utf-8"))
    assert record["key_id"] == KEY_ID and record["organization_id"] == ORG
    assert KEY not in receipt.read_text(encoding="utf-8")
    assert record["component"] == ("passed" if fault in (None, "delete", "still_active") else "not_run")
    assert record["retirement"] == ("not_confirmed" if fault == "delete" else
                                      "revoked" if fault in ("key", "still_active") else
                                      "revoked_and_rejected")
    assert len(executed) == (0 if fault in ("scopes", "expiry", "key") else 1)
