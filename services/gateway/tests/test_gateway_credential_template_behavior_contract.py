from __future__ import annotations
import json
from pathlib import Path
from fastapi.responses import JSONResponse
from gateway.models import ClaimDefinitionModel, CredentialTemplateCreate
from gateway.routes import credentials

CONTRACT = json.loads((Path(__file__).parents[3] / "contracts" / "gateway-credential-template-behavior.json").read_text(encoding="utf-8"))

def test_legacy_gateway_executes_shared_credential_template_contract() -> None:
    assert CONTRACT["schema_version"] == 1
    create = CredentialTemplateCreate.model_validate(CONTRACT["create_input"])
    create_internal = create.model_dump(exclude_none=True)
    create_internal["claims"] = credentials._claims_for_credential_template_service(create.claims)
    assert create_internal == CONTRACT["expected_create_internal"]
    claims = [ClaimDefinitionModel.model_validate(claim) for claim in CONTRACT["public_claims"]]
    assert credentials._claims_for_credential_template_service(claims) == CONTRACT["expected_internal_claims"]
    response = credentials._sanitize_credential_template_response(JSONResponse(CONTRACT["internal_response"]))
    assert json.loads(response.body) == CONTRACT["expected_public_response"]
