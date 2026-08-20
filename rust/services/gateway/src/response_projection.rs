use mmf_platform::{GatewayResponse, HttpMethod};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Debug)]
pub struct ProjectionError;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IssuanceResponse {
    id: String,
    organization_id: String,
    credential_template_id: String,
    status: IssuanceStatus,
    credential_offer_uri: String,
    credential_offer_uris: Value,
    credential_offer_labels: Value,
    expires_at: String,
}

impl PublicModel for IssuanceResponse {
    const FIELDS: &'static [&'static str] = &[
        "id",
        "organization_id",
        "credential_template_id",
        "status",
        "credential_offer_uri",
        "credential_offer_uris",
        "credential_offer_labels",
        "expires_at",
    ];
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IssuanceTransactionResponse {
    id: String,
    organization_id: String,
    credential_template_id: String,
    #[serde(default)]
    applicant_id: Option<String>,
    #[serde(default)]
    application_id: Option<String>,
    #[serde(default)]
    subject_did: Option<String>,
    status: IssuanceStatus,
    created_at: String,
    #[serde(default)]
    expires_at: Option<String>,
    #[serde(default)]
    issued_at: Option<String>,
    #[serde(default)]
    revoked_at: Option<String>,
    #[serde(default)]
    revocation_reason: Option<String>,
}

impl PublicModel for IssuanceTransactionResponse {
    const FIELDS: &'static [&'static str] = &[
        "id",
        "organization_id",
        "credential_template_id",
        "applicant_id",
        "application_id",
        "subject_did",
        "status",
        "created_at",
        "expires_at",
        "issued_at",
        "revoked_at",
        "revocation_reason",
    ];
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum IssuanceStatus {
    Pending,
    Authorized,
    Signing,
    Issued,
    Failed,
    Expired,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IssuedCredentialRecordResponse {
    id: String,
    organization_id: String,
    credential_id: String,
    credential_type: String,
    credential_format: CredentialFormat,
    flow_execution_id: String,
    credential_template_id: String,
    #[serde(default)]
    application_id: Option<String>,
    #[serde(default)]
    revocation_profile_id: Option<String>,
    #[serde(default)]
    renewed_from_credential_id: Option<String>,
    #[serde(default)]
    renewed_to_credential_id: Option<String>,
    #[serde(default)]
    renewable: bool,
    #[serde(default)]
    renewal_eligible_at: Option<String>,
    #[serde(default)]
    can_renew: bool,
    subject_id: String,
    #[serde(default)]
    subject_claims_hash: Option<String>,
    issued_at: String,
    #[serde(default)]
    valid_from: Option<String>,
    #[serde(default)]
    valid_until: Option<String>,
    status: CredentialStatus,
    status_list_entries: Vec<Value>,
    #[serde(default)]
    credential_hash: Option<String>,
    #[serde(default)]
    revoked_at: Option<String>,
    #[serde(default)]
    revocation_reason: Option<String>,
    #[serde(default)]
    issuer_did: Option<String>,
    #[serde(default)]
    revoked_by: Option<String>,
    created_at: String,
    #[serde(default)]
    updated_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CredentialRenewalOfferResponse {
    source_credential_id: String,
    transaction_id: String,
    credential_offer_uri: String,
    credential_offer_uris: Value,
    credential_offer_labels: Value,
    expires_at: String,
}

impl PublicModel for CredentialRenewalOfferResponse {
    const FIELDS: &'static [&'static str] = &[
        "source_credential_id",
        "transaction_id",
        "credential_offer_uri",
        "credential_offer_uris",
        "credential_offer_labels",
        "expires_at",
    ];
}

impl PublicModel for IssuedCredentialRecordResponse {
    const FIELDS: &'static [&'static str] = &[
        "id",
        "organization_id",
        "credential_id",
        "credential_type",
        "credential_format",
        "flow_execution_id",
        "credential_template_id",
        "application_id",
        "revocation_profile_id",
        "renewed_from_credential_id",
        "renewed_to_credential_id",
        "renewable",
        "renewal_eligible_at",
        "can_renew",
        "subject_id",
        "subject_claims_hash",
        "issued_at",
        "valid_from",
        "valid_until",
        "status",
        "status_list_entries",
        "credential_hash",
        "revoked_at",
        "revocation_reason",
        "issuer_did",
        "revoked_by",
        "created_at",
        "updated_at",
    ];
}

#[derive(Clone, Debug, Deserialize, Serialize)]
enum CredentialFormat {
    #[serde(rename = "MDOC")]
    Mdoc,
    #[serde(rename = "SD_JWT_VC")]
    SdJwtVc,
    #[serde(rename = "VC_JWT")]
    VcJwt,
    #[serde(rename = "JSON_LD")]
    JsonLd,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
enum CredentialStatus {
    #[serde(rename = "ACTIVE")]
    Active,
    #[serde(rename = "SUSPENDED")]
    Suspended,
    #[serde(rename = "REVOKED")]
    Revoked,
    #[serde(rename = "EXPIRED")]
    Expired,
}

enum Projection {
    Issuance,
    Transaction,
    Transactions,
    Credential,
    Credentials,
    Renewal,
}

trait PublicModel: DeserializeOwned + Serialize {
    const FIELDS: &'static [&'static str];
}

pub fn project(
    method: HttpMethod,
    path: &str,
    mut response: GatewayResponse,
) -> Result<GatewayResponse, ProjectionError> {
    if response.status_code >= 400 || response.status_code == 204 {
        return Ok(response);
    }
    let Some(kind) = projection_for(method, path) else {
        return Ok(response);
    };
    let Some(body) = response.body.as_deref() else {
        return Ok(response);
    };
    if body.is_empty() {
        return Ok(response);
    }
    let raw: Value = serde_json::from_slice(body).map_err(|_| ProjectionError)?;
    let public = match kind {
        Projection::Issuance => project_one::<IssuanceResponse>(raw)?,
        Projection::Transaction => project_one::<IssuanceTransactionResponse>(raw)?,
        Projection::Transactions => project_many::<IssuanceTransactionResponse>(raw)?,
        Projection::Credential => project_one::<IssuedCredentialRecordResponse>(raw)?,
        Projection::Credentials => project_many::<IssuedCredentialRecordResponse>(raw)?,
        Projection::Renewal => project_one::<CredentialRenewalOfferResponse>(raw)?,
    };
    response.body = Some(serde_json::to_vec(&public).map_err(|_| ProjectionError)?);
    response
        .headers
        .insert("content-type".into(), "application/json".into());
    response.headers.remove("content-length");
    Ok(response)
}

fn projection_for(method: HttpMethod, path: &str) -> Option<Projection> {
    if method == HttpMethod::Post && path == "/v1/issuance" {
        return Some(Projection::Issuance);
    }
    if method == HttpMethod::Get && path == "/v1/issuance" {
        return Some(Projection::Transactions);
    }
    if method == HttpMethod::Get
        && path
            .strip_prefix("/v1/issuance/")
            .is_some_and(|tail| !tail.is_empty() && !tail.contains('/'))
    {
        return Some(Projection::Transaction);
    }
    if method == HttpMethod::Get && path == "/v1/issued-credentials" {
        return Some(Projection::Credentials);
    }
    if method == HttpMethod::Get
        && path
            .strip_prefix("/v1/issued-credentials/")
            .is_some_and(|tail| !tail.is_empty() && !tail.contains('/') && tail != "mine")
    {
        return Some(Projection::Credential);
    }
    if method == HttpMethod::Post {
        let segments = path.trim_matches('/').split('/').collect::<Vec<_>>();
        match segments.as_slice() {
            ["v1", "issued-credentials", _, "revoke" | "suspend" | "reinstate"] => {
                return Some(Projection::Credential);
            }
            ["v1", "issued-credentials", _, "renew"] => return Some(Projection::Renewal),
            _ => {}
        }
    }
    None
}

fn project_one<T>(value: Value) -> Result<Value, ProjectionError>
where
    T: PublicModel,
{
    let object = value.as_object().ok_or(ProjectionError)?;
    let projected = object
        .iter()
        .filter(|(key, _)| T::FIELDS.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<Map<_, _>>();
    let parsed: T =
        serde_json::from_value(Value::Object(projected)).map_err(|_| ProjectionError)?;
    serde_json::to_value(parsed).map_err(|_| ProjectionError)
}

fn project_many<T>(value: Value) -> Result<Value, ProjectionError>
where
    T: PublicModel,
{
    value
        .as_array()
        .ok_or(ProjectionError)?
        .iter()
        .cloned()
        .map(project_one::<T>)
        .collect::<Result<Vec<_>, _>>()
        .map(Value::Array)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde::Deserialize;

    use super::*;

    #[derive(Deserialize)]
    struct Contract {
        schema_version: u32,
        cases: Vec<Case>,
        invalid_cases: Vec<InvalidCase>,
    }

    #[derive(Deserialize)]
    struct Case {
        name: String,
        method: HttpMethod,
        path: String,
        input: Value,
        expected: Value,
    }

    #[derive(Deserialize)]
    struct InvalidCase {
        name: String,
        method: HttpMethod,
        path: String,
        input: Value,
    }

    fn response(value: &Value) -> GatewayResponse {
        GatewayResponse {
            status_code: 200,
            headers: BTreeMap::from([
                ("content-type".into(), "application/json".into()),
                ("content-length".into(), "999".into()),
            ]),
            body: Some(serde_json::to_vec(value).expect("fixture JSON")),
            response_time_ms: None,
            upstream_service: Some("issuance".into()),
        }
    }

    #[test]
    fn language_neutral_issuance_response_projection_contract() {
        let contract: Contract = serde_json::from_str(include_str!(
            "../../../../contracts/gateway-issuance-response-projection.json"
        ))
        .expect("projection contract");
        assert_eq!(contract.schema_version, 1);
        for case in contract.cases {
            let projected = project(case.method, &case.path, response(&case.input))
                .unwrap_or_else(|_| panic!("valid projection: {}", case.name));
            let body: Value = serde_json::from_slice(projected.body.as_deref().expect("body"))
                .expect("projected JSON");
            assert_eq!(body, case.expected, "{}", case.name);
            assert!(!projected.headers.contains_key("content-length"));
        }
        for case in contract.invalid_cases {
            assert!(
                project(case.method, &case.path, response(&case.input)).is_err(),
                "{}",
                case.name
            );
        }
    }
}
