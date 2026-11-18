use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug)]
pub struct DidcommContractError;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DeliverRequest {
    organization_id: String,
    transaction_id: String,
    holder_did: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct DeliveryResponse {
    transaction_id: String,
    credential_id: String,
    holder_did: String,
    service_endpoint: String,
    didcomm_message_id: String,
    status: String,
    #[serde(default)]
    error: Option<String>,
}

pub fn canonicalize_request(
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<Option<Vec<u8>>, DidcommContractError> {
    if method != "POST" || path != "/v1/issuance/didcomm/deliver" {
        return Ok(None);
    }
    let request: DeliverRequest = serde_json::from_slice(body).map_err(|_| DidcommContractError)?;
    if request.organization_id.is_empty()
        || request.transaction_id.is_empty()
        || !request.holder_did.starts_with("did:")
    {
        return Err(DidcommContractError);
    }
    serde_json::to_vec(&request)
        .map(Some)
        .map_err(|_| DidcommContractError)
}

pub fn request_organization(body: &[u8]) -> Option<String> {
    serde_json::from_slice::<Value>(body)
        .ok()?
        .get("organization_id")?
        .as_str()
        .map(str::to_owned)
}

pub fn project_response(value: Value) -> Result<Value, DidcommContractError> {
    let response: DeliveryResponse =
        serde_json::from_value(value).map_err(|_| DidcommContractError)?;
    serde_json::to_value(response).map_err(|_| DidcommContractError)
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Deserialize)]
    struct Contract {
        schema_version: u32,
        valid_request: Value,
        expected_request: Value,
        invalid_requests: Vec<Value>,
        internal_response: Value,
        expected_response: Value,
        invalid_responses: Vec<Value>,
    }

    #[test]
    fn language_neutral_didcomm_delivery_contract() {
        let contract: Contract = serde_json::from_str(include_str!(
            "../../../../contracts/gateway-didcomm-delivery-behavior.json"
        ))
        .expect("DIDComm contract");
        assert_eq!(contract.schema_version, 1);
        let canonical = canonicalize_request(
            "POST",
            "/v1/issuance/didcomm/deliver",
            &serde_json::to_vec(&contract.valid_request).unwrap(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&canonical).unwrap(),
            contract.expected_request
        );
        for invalid in contract.invalid_requests {
            assert!(canonicalize_request(
                "POST",
                "/v1/issuance/didcomm/deliver",
                &serde_json::to_vec(&invalid).unwrap(),
            )
            .is_err());
        }
        assert_eq!(
            project_response(contract.internal_response).unwrap(),
            contract.expected_response
        );
        for invalid in contract.invalid_responses {
            assert!(project_response(invalid).is_err());
        }
    }
}
