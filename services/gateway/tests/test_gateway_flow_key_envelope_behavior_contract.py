"""Run flow-key envelope behavior fixtures against the Python baseline."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from fastapi import HTTPException
from gateway.routes import signing_keys


CONTRACT = json.loads(
    (
        Path(__file__).parents[3]
        / "contracts"
        / "gateway-flow-key-envelope-behavior.json"
    ).read_text(encoding="utf-8")
)


@pytest.mark.asyncio
async def test_python_flow_envelope_matches_shared_contract(monkeypatch) -> None:
    monkeypatch.setenv("SIGNING_KEYS_INTERNAL_API_KEY", "test-internal-key")
    stored: dict[str, bytes] = {}

    async def fake_openbao(path, payload):
        if "/encrypt/" in path:
            stored[CONTRACT["ciphertext"]] = base64.b64decode(payload["plaintext"])
            return {"data": {"ciphertext": CONTRACT["ciphertext"]}}
        return {
            "data": {
                "plaintext": base64.b64encode(stored[payload["ciphertext"]]).decode()
            }
        }

    monkeypatch.setattr(signing_keys, "_openbao_post_json", fake_openbao)
    wrapped = await signing_keys.internal_wrap_flow_key(
        body={
            "flow_instance_id": CONTRACT["flow_instance_id"],
            "plaintext_b64": CONTRACT["plaintext_b64"],
        },
        organization_id=CONTRACT["organization_id"],
        x_api_key="test-internal-key",
    )
    assert json.loads(wrapped.body) == CONTRACT["wrap_response"]

    unwrapped = await signing_keys.internal_unwrap_flow_key(
        body={
            "flow_instance_id": CONTRACT["flow_instance_id"],
            "ciphertext": CONTRACT["ciphertext"],
        },
        organization_id=CONTRACT["organization_id"],
        x_api_key="test-internal-key",
    )
    assert json.loads(unwrapped.body) == CONTRACT["unwrap_response"]

    with pytest.raises(HTTPException) as exc_info:
        await signing_keys.internal_unwrap_flow_key(
            body={"flow_instance_id": "other-flow", "ciphertext": CONTRACT["ciphertext"]},
            organization_id=CONTRACT["organization_id"],
            x_api_key="test-internal-key",
        )
    assert exc_info.value.status_code == CONTRACT["binding_mismatch_status"]
