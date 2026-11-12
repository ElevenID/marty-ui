//! Exact containment of a known newly returned renewal token, never old tokens.
use super::{Bao, Method, Value};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::error::Error;

pub(super) struct NewToken(String);

impl NewToken {
    pub(super) fn capture(response: &Value, authority: &str) -> Result<Self, Box<dyn Error>> {
        let value = response
            .get("auth")
            .and_then(|v| v.get("client_token"))
            .and_then(Value::as_str)
            .filter(|v| {
                (20..=1024).contains(&v.len())
                    && v.is_ascii()
                    && v.bytes().all(|b| b.is_ascii_graphic())
                    && *v != authority
            })
            .ok_or("new renewal token could not be identified; preserve mint intent")?;
        Ok(Self(value.to_owned()))
    }
    pub(super) fn value(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Operation {
    RevokeSelfAsNewToken,
    RevokeExactAsAuthority,
    LookupExactAsAuthority,
    ReadKeyAsNewToken,
}

#[derive(Clone, Copy, Debug)]
struct TokenResponse {
    http_status: u16,
    exact_bad_token_lookup: bool,
}

// OpenBao 2.5.5 handleLookup returns 403/errors:["bad token"] for no target.
// Only the exact authority lookup operation may carry that absence evidence.
fn token_response(operation: Operation, status: u16, body: &Value) -> TokenResponse {
    let exact_bad_token_lookup = operation == Operation::LookupExactAsAuthority
        && status == 403
        && matches!(body.get("errors").and_then(Value::as_array),
            Some(errors) if errors.len() == 1 && errors[0].as_str() == Some("bad token"));
    TokenResponse {
        http_status: status,
        exact_bad_token_lookup,
    }
}

// A closed four-operation port inside this producer permits focused fault tests.
// It cannot select an endpoint, arbitrary path, policy or other credential.
trait TokenAuthority {
    async fn status(
        &self,
        operation: Operation,
        token: &NewToken,
        key: &str,
    ) -> Result<TokenResponse, Box<dyn Error>>;
}

impl TokenAuthority for Bao {
    async fn status(
        &self,
        operation: Operation,
        token: &NewToken,
        key: &str,
    ) -> Result<TokenResponse, Box<dyn Error>> {
        let (method, path, body, auth) = match operation {
            Operation::RevokeSelfAsNewToken => (
                Method::POST,
                "auth/token/revoke-self".to_owned(),
                None,
                Some(token.value()),
            ),
            Operation::RevokeExactAsAuthority => (
                Method::POST,
                "auth/token/revoke".to_owned(),
                Some(json!({"token":token.value()})),
                None,
            ),
            Operation::LookupExactAsAuthority => (
                Method::POST,
                "auth/token/lookup".to_owned(),
                Some(json!({"token":token.value()})),
                None,
            ),
            Operation::ReadKeyAsNewToken => (
                Method::GET,
                format!("transit/keys/{key}"),
                None,
                Some(token.value()),
            ),
        };
        let (status, body) = self.request(method, &path, body, auth).await?;
        Ok(token_response(operation, status.as_u16(), &body))
    }
}

#[derive(Debug, Serialize)]
pub(super) struct Attempt {
    pub http_status: Option<u16>,
    pub exact_bad_token_lookup: bool,
    pub error_sha256: Option<String>,
}

impl Attempt {
    fn result(result: Result<TokenResponse, Box<dyn Error>>) -> Self {
        match result {
            Ok(response) => Self {
                http_status: Some(response.http_status),
                exact_bad_token_lookup: response.exact_bad_token_lookup,
                error_sha256: None,
            },
            Err(error) => Self {
                http_status: None,
                exact_bad_token_lookup: false,
                error_sha256: Some(format!(
                    "{:x}",
                    Sha256::digest(error.to_string().as_bytes())
                )),
            },
        }
    }
    fn acknowledged(&self) -> bool {
        self.http_status.is_some_and(|s| (200..300).contains(&s))
    }
}

#[derive(Debug, Serialize)]
pub(super) struct Containment {
    pub revoke_self_as_new_token: Attempt,
    pub revoke_exact_as_authority: Option<Attempt>,
    pub authority_lookup: Attempt,
    pub new_token_key_read: Attempt,
    pub confirmed: bool,
}

async fn contain(api: &impl TokenAuthority, token: &NewToken, key: &str) -> Containment {
    let revoke_self_as_new_token = Attempt::result(
        api.status(Operation::RevokeSelfAsNewToken, token, key)
            .await,
    );
    let revoke_exact_as_authority = if revoke_self_as_new_token.acknowledged() {
        None
    } else {
        Some(Attempt::result(
            api.status(Operation::RevokeExactAsAuthority, token, key)
                .await,
        ))
    };
    let authority_lookup = Attempt::result(
        api.status(Operation::LookupExactAsAuthority, token, key)
            .await,
    );
    let new_token_key_read =
        Attempt::result(api.status(Operation::ReadKeyAsNewToken, token, key).await);
    let action_acknowledged = revoke_self_as_new_token.acknowledged()
        || revoke_exact_as_authority
            .as_ref()
            .is_some_and(Attempt::acknowledged);
    let confirmed = action_acknowledged
        && (matches!(authority_lookup.http_status, Some(400 | 404))
            || authority_lookup.http_status == Some(403)
                && authority_lookup.exact_bad_token_lookup)
        && new_token_key_read.http_status == Some(403);
    Containment {
        revoke_self_as_new_token,
        revoke_exact_as_authority,
        authority_lookup,
        new_token_key_read,
        confirmed,
    }
}

pub(super) async fn contain_new_token(bao: &Bao, token: &NewToken, key: &str) -> Containment {
    contain(bao, token, key).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::VecDeque, sync::Mutex};
    struct Script {
        replies: Mutex<VecDeque<Result<(u16, Value), &'static str>>>,
        calls: Mutex<Vec<Operation>>,
    }
    impl TokenAuthority for Script {
        async fn status(
            &self,
            operation: Operation,
            _: &NewToken,
            _: &str,
        ) -> Result<TokenResponse, Box<dyn Error>> {
            self.calls.lock().unwrap().push(operation);
            self.replies
                .lock()
                .unwrap()
                .pop_front()
                .unwrap()
                .map(|(status, body)| token_response(operation, status, &body))
                .map_err(Into::into)
        }
    }
    fn token() -> NewToken {
        NewToken::capture(
            &json!({"auth":{"client_token":"synthetic-new-token-xxxxxxxx"}}),
            "synthetic-root-token-xxxxxxxx",
        )
        .unwrap()
    }
    fn script(replies: Vec<Result<u16, &'static str>>) -> Script {
        response_script(
            replies
                .into_iter()
                .map(|r| r.map(|s| (s, json!({}))))
                .collect(),
        )
    }
    fn response_script(replies: Vec<Result<(u16, Value), &'static str>>) -> Script {
        Script {
            replies: Mutex::new(replies.into()),
            calls: Mutex::new(vec![]),
        }
    }
    #[tokio::test]
    async fn existing_key_renew_fault_leaf403_root_exact200_lookup404_key403_is_confirmed() {
        let api = script(vec![Ok(403), Ok(200), Ok(404), Ok(403)]);
        let result = contain(&api, &token(), "owned-key").await;
        assert!(result.confirmed);
        assert_eq!(
            *api.calls.lock().unwrap(),
            vec![
                Operation::RevokeSelfAsNewToken,
                Operation::RevokeExactAsAuthority,
                Operation::LookupExactAsAuthority,
                Operation::ReadKeyAsNewToken
            ]
        );
    }
    #[tokio::test]
    async fn existing_key_renew_fault_unconfirmed_fallback_or_denial_never_claims_revoked() {
        for replies in [
            vec![Ok(403), Ok(500), Ok(404), Ok(403)],
            vec![Ok(403), Ok(200), Ok(200), Ok(403)],
            vec![
                Ok(403),
                Ok(200),
                Ok(404),
                Err("private error must not be reported"),
            ],
        ] {
            let result = contain(&script(replies), &token(), "owned-key").await;
            assert!(!result.confirmed);
            assert!(!serde_json::to_string(&result)
                .unwrap()
                .contains("private error"));
        }
    }
    #[tokio::test]
    async fn existing_key_renew_fault_self_revoke_success_still_requires_lookup_and_read_denial() {
        let api = script(vec![Ok(204), Ok(404), Ok(403)]);
        let result = contain(&api, &token(), "owned-key").await;
        assert!(result.confirmed);
        assert!(result.revoke_exact_as_authority.is_none());
        assert_eq!(api.calls.lock().unwrap().len(), 3);
    }
    #[test]
    fn existing_key_renew_fault_never_admits_root_or_unknown_response_as_new_token() {
        let root = "synthetic-root-token-xxxxxxxx";
        assert!(NewToken::capture(&json!({"auth":{"client_token":root}}), root).is_err());
        assert!(NewToken::capture(&json!({"auth":{}}), root).is_err());
    }
    #[tokio::test]
    async fn existing_key_renew_fault_exact_bad_token_lookup403_is_absent_but_generic403_is_not() {
        // Actual OpenBao 2.5.5 expired-target response; no server or credentials.
        for (body, absent) in [
            (json!({"errors":["bad token"]}), true),
            (json!({"errors":["permission denied"]}), false),
            (json!({"errors":["bad token","permission denied"]}), false),
            (json!({"errors":"bad token"}), false),
            (json!({}), false),
        ] {
            let api = response_script(vec![
                Ok((403, json!({}))),
                Ok((204, json!({}))),
                Ok((403, body)),
                Ok((403, json!({}))),
            ]);
            let result = contain(&api, &token(), "owned-key").await;
            assert_eq!(result.confirmed, absent);
            assert_eq!(result.authority_lookup.exact_bad_token_lookup, absent);
            let safe = serde_json::to_string(&result).unwrap();
            assert!(!safe.contains("bad token") && !safe.contains("permission denied"));
        }
        // Exact absence cannot replace an acknowledged revoke action.
        let api = response_script(vec![
            Ok((403, json!({}))),
            Ok((500, json!({}))),
            Ok((403, json!({"errors":["bad token"]}))),
            Ok((403, json!({}))),
        ]);
        assert!(!contain(&api, &token(), "owned-key").await.confirmed);
    }

    #[test]
    fn existing_key_renew_fault_bad_token_evidence_is_exact_authority_lookup_only() {
        let body = json!({"errors":["bad token"]});
        for operation in [
            Operation::RevokeSelfAsNewToken,
            Operation::RevokeExactAsAuthority,
            Operation::ReadKeyAsNewToken,
        ] {
            assert!(!token_response(operation, 403, &body).exact_bad_token_lookup);
        }
        assert!(
            !token_response(Operation::LookupExactAsAuthority, 500, &body).exact_bad_token_lookup
        );
    }
}
