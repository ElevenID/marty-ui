use marty_verification::governance::canonical_digest_json;
use serde::Serialize;
use serde_json::Value;

use crate::{FrozenOid4vpRequestV1, Oid4vpContractError, WalletSubmissionV1};

pub const QUERY_DOCUMENT_DIGEST_DOMAIN: &str = "marty.oid4vp/query-document/v1";
pub const FROZEN_REQUEST_DIGEST_DOMAIN: &str = "marty.oid4vp/frozen-request/v1";
pub const WALLET_SUBMISSION_DIGEST_DOMAIN: &str = "marty.oid4vp/wallet-submission/v1";
pub const RESPONSE_ITEM_DIGEST_DOMAIN: &str = "marty.oid4vp/response-item/v1";
pub const NONCE_DIGEST_DOMAIN: &str = "marty.oid4vp/nonce/v1";
pub const AUDIENCE_DIGEST_DOMAIN: &str = "marty.oid4vp/audience/v1";
pub const REPLAY_KEY_DIGEST_DOMAIN: &str = "marty.oid4vp/replay-key/v1";

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct DigestEnvelope<'a, T: ?Sized> {
    domain: &'static str,
    value: &'a T,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ReplayKey<'a> {
    request_digest: &'a str,
    response_digest: &'a str,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ResponseItem<'a> {
    query_id: &'a str,
    selector: &'a str,
    token: &'a str,
}

pub fn digest_domain_json<T: Serialize + ?Sized>(
    domain: &'static str,
    value: &T,
) -> Result<String, Oid4vpContractError> {
    let envelope = DigestEnvelope { domain, value };
    let value = serde_json::to_string(&envelope).map_err(|_| Oid4vpContractError::Serialization)?;
    canonical_digest_json(&value).map_err(|_| Oid4vpContractError::Serialization)
}

pub fn digest_query_document(value: &Value) -> Result<String, Oid4vpContractError> {
    digest_domain_json(QUERY_DOCUMENT_DIGEST_DOMAIN, value)
}

pub fn digest_frozen_request(value: &FrozenOid4vpRequestV1) -> Result<String, Oid4vpContractError> {
    digest_domain_json(FROZEN_REQUEST_DIGEST_DOMAIN, value)
}

pub fn digest_wallet_submission(value: &WalletSubmissionV1) -> Result<String, Oid4vpContractError> {
    digest_domain_json(WALLET_SUBMISSION_DIGEST_DOMAIN, value)
}

pub fn digest_response_item(
    token: &str,
    query_id: &str,
    selector: &str,
) -> Result<String, Oid4vpContractError> {
    digest_domain_json(
        RESPONSE_ITEM_DIGEST_DOMAIN,
        &ResponseItem {
            query_id,
            selector,
            token,
        },
    )
}

pub fn digest_nonce(value: &str) -> Result<String, Oid4vpContractError> {
    digest_domain_json(NONCE_DIGEST_DOMAIN, value)
}

pub fn digest_audience(value: &str) -> Result<String, Oid4vpContractError> {
    digest_domain_json(AUDIENCE_DIGEST_DOMAIN, value)
}

pub fn digest_replay_key(
    request_digest: &str,
    response_digest: &str,
) -> Result<String, Oid4vpContractError> {
    digest_domain_json(
        REPLAY_KEY_DIGEST_DOMAIN,
        &ReplayKey {
            request_digest,
            response_digest,
        },
    )
}
