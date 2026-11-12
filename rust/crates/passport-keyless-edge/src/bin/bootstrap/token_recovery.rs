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

// A closed four-operation port inside this producer permits focused fault tests.
// It cannot select an endpoint, arbitrary path, policy or other credential.
trait TokenAuthority {
    async fn status(
        &self,
        operation: Operation,
        token: &NewToken,
        key: &str,
    ) -> Result<u16, Box<dyn Error>>;
}

impl TokenAuthority for Bao {
    async fn status(
        &self,
        operation: Operation,
        token: &NewToken,
        key: &str,
    ) -> Result<u16, Box<dyn Error>> {
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
        Ok(self.request(method, &path, body, auth).await?.0.as_u16())
    }
}

#[derive(Debug, Serialize)]
pub(super) struct Attempt {
    pub http_status: Option<u16>,
    pub error_sha256: Option<String>,
}

impl Attempt {
    fn result(result: Result<u16, Box<dyn Error>>) -> Self {
        match result {
            Ok(status) => Self {
                http_status: Some(status),
                error_sha256: None,
            },
            Err(error) => Self {
                http_status: None,
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
        && matches!(authority_lookup.http_status, Some(400 | 404))
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
        replies: Mutex<VecDeque<Result<u16, &'static str>>>,
        calls: Mutex<Vec<Operation>>,
    }
    impl TokenAuthority for Script {
        async fn status(
            &self,
            operation: Operation,
            _: &NewToken,
            _: &str,
        ) -> Result<u16, Box<dyn Error>> {
            self.calls.lock().unwrap().push(operation);
            self.replies
                .lock()
                .unwrap()
                .pop_front()
                .unwrap()
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
}
