//! Synthetic certificate-authenticated servers exercise transport boundaries.
//! Their JWS-shaped bytes deliberately carry no cryptographic trust claim.
mod support;

use axum::http::{HeaderValue, StatusCode};
use marty_delegated_use_client::*;
use serde_json::{json, Value};
use std::time::Duration;
use support::*;
use uuid::Uuid;

#[test]
fn retained_commands_reconstruct_exact_bytes_and_recovery_uses_original_intent() {
    let prepared = start();
    let original: Value = serde_json::from_slice(prepared.bytes()).unwrap();
    let restored = PreparedStart::new(
        prepared.command_id(),
        serde_json::from_value(original["grant"].clone()).unwrap(),
        serde_json::from_value(original["operation"].clone()).unwrap(),
    )
    .unwrap();
    assert_eq!(prepared.bytes(), restored.bytes());
    assert_eq!(prepared.command_digest(), digest(prepared.bytes()));
    assert!(std::str::from_utf8(prepared.bytes())
        .unwrap()
        .starts_with("{\"command\":\"START_USE\",\"command_id\":"));
    assert_eq!(
        serde_json::from_slice::<Value>(&restored.recovery_bytes()).unwrap(),
        json!({"profile":COMMAND_PROFILE,"command":"RECOVER_RESULT","original_command_id":prepared.command_id(),"expected_command_digest":prepared.command_digest()})
    );
    let finalize = finalize();
    let restored_final =
        PreparedFinalize::new(finalize.command_id(), id(CHALLENGE), id(SUBMISSION)).unwrap();
    assert_eq!(finalize.bytes(), restored_final.bytes());
    assert_eq!(finalize.recovery_bytes(), restored_final.recovery_bytes());
}

#[test]
fn invalid_original_command_inputs_cannot_be_prepared() {
    let original: Value = serde_json::from_slice(start().bytes()).unwrap();
    for revision in [0, 9_007_199_254_740_992, u64::MAX] {
        let mut grant: GrantReference = serde_json::from_value(original["grant"].clone()).unwrap();
        grant.revision = revision;
        assert!(matches!(
            PreparedStart::new(
                Uuid::new_v4(),
                grant,
                serde_json::from_value(original["operation"].clone()).unwrap()
            ),
            Err(ClientError::InvalidCommand)
        ));
    }
    for uri in [
        "relative",
        "https://",
        "https://example.test/%xx",
        "urn:example: white",
        "https://example.test/\\path",
        "urn:example:☃",
    ] {
        let mut operation: Operation =
            serde_json::from_value(original["operation"].clone()).unwrap();
        operation.action = uri.into();
        assert!(
            matches!(
                PreparedStart::new(
                    Uuid::new_v4(),
                    serde_json::from_value(original["grant"].clone()).unwrap(),
                    operation
                ),
                Err(ClientError::InvalidCommand)
            ),
            "{uri}"
        );
    }
    assert!(matches!(
        PreparedFinalize::new(Uuid::nil(), id(CHALLENGE), id(SUBMISSION)),
        Err(ClientError::InvalidCommand)
    ));
    assert!(matches!(
        PreparedFinalize::new(Uuid::new_v4(), Uuid::nil(), id(SUBMISSION)),
        Err(ClientError::InvalidCommand)
    ));
    assert!(matches!(
        PreparedFinalize::new(Uuid::new_v4(), id(CHALLENGE), Uuid::nil()),
        Err(ClientError::InvalidCommand)
    ));
}

#[tokio::test]
async fn configuration_rejects_ambiguous_origins_missing_roots_and_missing_client_certificate() {
    let host = Host::new().await;
    for origin in [
        "http://example.test",
        "https://example.test/",
        "https://example.test:443",
        "https://EXAMPLE.test",
        "https://user@example.test",
        "https://example.test/path",
        "https://example.test?query=secret",
        "https://example.test#fragment",
        "https://example.test\\path",
    ] {
        let mut config = host.config();
        config.origin = origin.into();
        assert!(
            matches!(
                DelegatedUseClient::new(config),
                Err(ClientError::InvalidConfiguration)
            ),
            "{origin}"
        );
    }
    let mut config = host.config();
    config.tls.roots = rustls::RootCertStore::empty();
    assert!(matches!(
        DelegatedUseClient::new(config),
        Err(ClientError::InvalidConfiguration)
    ));
    let mut config = host.config();
    config.tls = host.pki.no_certificate();
    assert!(matches!(
        DelegatedUseClient::new(config),
        Err(ClientError::InvalidConfiguration)
    ));
    for timeout in [Duration::ZERO, Duration::from_secs(301)] {
        let mut config = host.config();
        config.timeout = timeout;
        assert!(matches!(
            DelegatedUseClient::new(config),
            Err(ClientError::InvalidConfiguration)
        ));
    }
    let mut config = host.config();
    config.organization = Uuid::nil();
    assert!(matches!(
        DelegatedUseClient::new(config),
        Err(ClientError::InvalidConfiguration)
    ));
    assert!(host.seen().is_empty());
}

#[tokio::test]
async fn tls_rejects_untrusted_server_and_untrusted_client_without_http_dispatch() {
    let host = Host::new().await;
    let unrelated = Pki::new();
    let mut wrong_server = host.config();
    wrong_server.tls.roots = unrelated.roots();
    assert_eq!(
        DelegatedUseClient::new(wrong_server)
            .unwrap()
            .start(&start())
            .await
            .unwrap_err(),
        ClientError::Transport
    );
    let mut wrong_client = host.config();
    wrong_client.tls.client_certificate = unrelated.mtls().client_certificate;
    assert_eq!(
        DelegatedUseClient::new(wrong_client)
            .unwrap()
            .start(&start())
            .await
            .unwrap_err(),
        ClientError::Transport
    );
    assert!(host.seen().is_empty());
}

#[tokio::test]
async fn advertised_request_direct_post_finalize_and_historical_recovery_preserve_original_evidence(
) {
    let host = Host::new().await;
    let client = host.client();
    let command = start();
    let final_command = finalize();
    host.started_reply(&command, false);
    let started = client.start(&command).await.unwrap();
    assert_eq!(
        started.request_uri(),
        format!("{}/v1/flows/instances/{CHALLENGE}/request", host.origin)
    );
    host.push(Reply::raw("application/oauth-authz-req+jwt", COMPACT));
    assert_eq!(
        client.fetch_request(&started).await.unwrap().compact_jws(),
        COMPACT
    );
    host.push(Reply::json(submission(COMPACT)));
    let submission = client
        .submit_direct_post(&started, &host.verified(), COMPACT)
        .await
        .unwrap();
    assert_eq!(submission.challenge_id, id(CHALLENGE));
    host.push(Reply::json(final_result(&final_command, false)));
    let finalized = client.finalize(&final_command).await.unwrap();
    assert!(!finalized.response().recovered);
    host.push(Reply::json(final_result(&final_command, true)));
    assert!(
        client
            .recover_final(&final_command)
            .await
            .unwrap()
            .response()
            .recovered
    );
    host.push(Reply::json(receipt(&final_command)));
    let artifact = client.recover_receipt(&final_command).await.unwrap();
    assert_eq!(artifact.compact_jws(), COMPACT);
    assert_eq!(artifact.receipt_digest(), digest(COMPACT.as_bytes()));
    assert_eq!(artifact.semantics(), EVIDENCE_SEMANTICS);
    assert_eq!(
        serde_json::to_value(artifact.original_response()).unwrap(),
        final_result(&final_command, true)
    );
    host.started_reply(&command, true);
    assert!(
        client
            .recover_start(&command)
            .await
            .unwrap()
            .response()
            .recovered
    );
    let seen = host.seen();
    assert_eq!(seen.len(), 7);
    assert_eq!(seen[0].bytes, command.bytes());
    assert_eq!(
        seen[0].path,
        format!("/v1/organizations/{ORGANIZATION}/delegated-use-commands")
    );
    assert_eq!(seen[1].method, "GET");
    assert_eq!(
        seen[1].path,
        format!("/v1/flows/instances/{CHALLENGE}/request")
    );
    assert!(seen[1].bytes.is_empty());
    assert_eq!(
        seen[2].headers["content-type"],
        "application/x-www-form-urlencoded"
    );
    let fields = url::form_urlencoded::parse(&seen[2].bytes)
        .into_owned()
        .collect::<Vec<_>>();
    assert_eq!(fields.len(), 2);
    assert_eq!(fields[0], ("state".into(), CHALLENGE.into()));
    assert_eq!(
        serde_json::from_str::<Value>(&fields[1].1).unwrap(),
        json!({"selected_machine":[COMPACT]})
    );
    assert_eq!(seen[3].bytes, final_command.bytes());
    assert_eq!(seen[4].bytes, final_command.recovery_bytes());
    assert_eq!(seen[5].bytes, final_command.recovery_bytes());
    assert_eq!(seen[6].bytes, command.recovery_bytes());
}

#[tokio::test]
async fn redirects_and_retryable_http_errors_are_single_attempts() {
    let host = Host::new().await;
    let destination = Host::new().await;
    let client = host.client();
    for status in [
        StatusCode::TEMPORARY_REDIRECT,
        StatusCode::TOO_MANY_REQUESTS,
        StatusCode::SERVICE_UNAVAILABLE,
    ] {
        let mut reply = Reply::raw("text/plain", "secret upstream diagnostic");
        reply.status = status;
        reply.headers.insert(
            "location",
            HeaderValue::from_str(&format!("{}/redirect-target", destination.origin)).unwrap(),
        );
        reply
            .headers
            .insert("retry-after", HeaderValue::from_static("0"));
        host.push(reply);
        let error = client.start(&start()).await.unwrap_err();
        assert_eq!(error, ClientError::Http(status.as_u16()));
        assert!(!format!("{error:?} {error}").contains("secret"));
    }
    assert_eq!(host.seen().len(), 3);
    assert!(destination.seen().is_empty());
}

#[tokio::test]
async fn lost_response_recovers_only_explicit_original_command_without_automatic_reexecution() {
    let host = Host::new().await;
    let command = finalize();
    let mut config = host.config();
    config.timeout = Duration::from_millis(80);
    let client = DelegatedUseClient::new(config).unwrap();
    let mut reply = Reply::json(final_result(&command, false));
    reply.delay = Duration::from_millis(250);
    host.push(reply);
    assert_eq!(
        client.finalize(&command).await.unwrap_err(),
        ClientError::Transport
    );
    assert_eq!(host.seen().len(), 1);
    host.push(Reply::json(final_result(&command, true)));
    assert!(
        client
            .recover_final(&command)
            .await
            .unwrap()
            .response()
            .recovered
    );
    let seen = host.seen();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].bytes, command.bytes());
    assert_eq!(seen[1].bytes, command.recovery_bytes());
}

#[tokio::test]
async fn started_response_must_match_independently_prepared_id_digest_grant_and_operation() {
    let host = Host::new().await;
    let client = host.client();
    let command = start();
    for (path, value) in [
        ("/profile", json!("different")),
        ("/original_command_id", json!(SUBMISSION)),
        ("/command_digest", json!(digest(b"different command"))),
        ("/result/grant/id", json!(SUBMISSION)),
        ("/result/grant/revision", json!(4)),
        (
            "/result/grant/terms_digest",
            json!(digest(b"changed terms")),
        ),
        (
            "/result/operation/request_digest",
            json!(digest(b"another operation")),
        ),
        ("/result/created_at", json!(EXPIRES)),
    ] {
        let mut body = challenge(&command, false);
        *body.pointer_mut(path).unwrap() = value;
        host.push(Reply::json(body).link(&host.origin));
        assert_eq!(
            client.start(&command).await.unwrap_err(),
            ClientError::CorrelationMismatch,
            "{path}"
        );
    }
    host.started_reply(&command, false);
    assert_eq!(
        client.recover_start(&command).await.unwrap_err(),
        ClientError::CorrelationMismatch
    );
}

#[tokio::test]
async fn advertised_link_rejects_cross_origin_wrong_challenge_and_ambiguous_destinations() {
    let host = Host::new().await;
    let client = host.client();
    let command = start();
    for target in [
        format!("https://elsewhere.example/v1/flows/instances/{CHALLENGE}/request"),
        format!("{}/v1/flows/instances/{SUBMISSION}/request", host.origin),
        format!("{}/v1/flows/instances/{CHALLENGE}/request?x=1", host.origin),
        format!("{}/v1/flows/instances/{CHALLENGE}/request#x", host.origin),
        format!("{}/v1/flows/instances/{CHALLENGE}/%72equest", host.origin),
    ] {
        let mut reply = Reply::json(challenge(&command, false));
        reply.headers.insert(
            "link",
            HeaderValue::from_str(&format!("<{target}>; rel=\"{REQUEST_LINK_RELATION}\"")).unwrap(),
        );
        host.push(reply);
        assert_eq!(
            client.start(&command).await.unwrap_err(),
            ClientError::InvalidDestination
        );
    }
    let mut reply = Reply::json(challenge(&command, false)).link(&host.origin);
    let extra = reply.headers["link"].clone();
    reply.headers.append("link", extra);
    host.push(reply);
    assert_eq!(
        client.start(&command).await.unwrap_err(),
        ClientError::InvalidResponse
    );
    host.push(Reply::json(challenge(&command, false)));
    assert_eq!(
        client.start(&command).await.unwrap_err(),
        ClientError::InvalidResponse
    );
}

#[tokio::test]
async fn wrappers_and_verified_request_fields_cannot_send_proof_to_another_tenant_origin_or_challenge(
) {
    let host = Host::new().await;
    let other = Host::new().await;
    let client = host.client();
    let command = start();
    host.started_reply(&command, false);
    let started = client.start(&command).await.unwrap();
    assert_eq!(
        other.client().fetch_request(&started).await.unwrap_err(),
        ClientError::InvalidDestination
    );
    let mut config = host.config();
    config.organization = id(SUBMISSION);
    assert_eq!(
        DelegatedUseClient::new(config)
            .unwrap()
            .fetch_request(&started)
            .await
            .unwrap_err(),
        ClientError::InvalidDestination
    );
    for (uri, state, query) in [
        (
            format!("{}/v1/flows/instances/{CHALLENGE}/submit", other.origin),
            CHALLENGE,
            "selected_machine",
        ),
        (
            format!("{}/v1/flows/instances/{SUBMISSION}/submit", host.origin),
            CHALLENGE,
            "selected_machine",
        ),
        (host.verified().response_uri, SUBMISSION, "selected_machine"),
        (host.verified().response_uri, CHALLENGE, "bad query"),
    ] {
        assert_eq!(
            client
                .submit_direct_post(
                    &started,
                    &CallerVerifiedRequest {
                        response_uri: uri,
                        state: state.into(),
                        query_id: query.into()
                    },
                    COMPACT
                )
                .await
                .unwrap_err(),
            ClientError::InvalidDestination
        );
    }
    assert_eq!(host.seen().len(), 1);
    assert!(other.seen().is_empty());
}

#[tokio::test]
async fn malformed_and_oversized_proofs_are_rejected_before_network() {
    let host = Host::new().await;
    let client = host.client();
    let command = start();
    host.started_reply(&command, false);
    let started = client.start(&command).await.unwrap();
    for proof in ["", "a.b", "a.b.c.d", "a..c", "a.b.c=", "a.b.c\n"] {
        assert_eq!(
            client
                .submit_direct_post(&started, &host.verified(), proof)
                .await
                .unwrap_err(),
            ClientError::InvalidCommand
        );
    }
    assert_eq!(
        client
            .submit_direct_post(&started, &host.verified(), &"x".repeat(MAX_PROOF_BYTES + 1))
            .await
            .unwrap_err(),
        ClientError::TooLarge
    );
    assert_eq!(host.seen().len(), 1);
}

#[tokio::test]
async fn proof_retention_must_bind_original_challenge_exact_bytes_and_original_lifetime() {
    let host = Host::new().await;
    let client = host.client();
    let command = start();
    host.started_reply(&command, false);
    let started = client.start(&command).await.unwrap();
    for (key, value) in [
        ("challenge_id", json!(SUBMISSION)),
        ("proof_digest", json!(digest(b"substituted proof"))),
        ("received_at", json!("2026-11-21T14:59:59Z")),
        ("received_at", json!(EXPIRES)),
    ] {
        let mut body = submission(COMPACT);
        body[key] = value;
        host.push(Reply::json(body));
        assert_eq!(
            client
                .submit_direct_post(&started, &host.verified(), COMPACT)
                .await
                .unwrap_err(),
            ClientError::CorrelationMismatch
        );
    }
}

#[tokio::test]
async fn final_response_cannot_replace_original_identity_challenge_decision_or_evidence_semantics()
{
    let host = Host::new().await;
    let client = host.client();
    let command = finalize();
    for (path, value) in [
        ("/original_command_id", json!(SUBMISSION)),
        ("/command_digest", json!(digest(b"wrong command"))),
        ("/result/challenge_id", json!(SUBMISSION)),
        ("/result/decision", json!("ALLOW")),
        (
            "/result/receipt_ref",
            json!("https://attacker.example/receipt"),
        ),
        ("/result/receipt_digest", json!("sha256:not-digest")),
        ("/result/authorization_expires_at", json!(RECEIVED)),
        ("/result/semantics", json!("EXECUTION_AUTHORIZED")),
    ] {
        let mut body = final_result(&command, false);
        *body.pointer_mut(path).unwrap() = value;
        host.push(Reply::json(body));
        assert_eq!(
            client.finalize(&command).await.unwrap_err(),
            ClientError::CorrelationMismatch,
            "{path}"
        );
    }
    host.push(Reply::json(final_result(&command, false)));
    assert_eq!(
        client.recover_final(&command).await.unwrap_err(),
        ClientError::CorrelationMismatch
    );
    let mut denied = final_result(&command, false);
    denied["result"]["decision"] = json!("DENY");
    host.push(Reply::json(denied));
    assert!(
        matches!(&client.finalize(&command).await.unwrap().response().result,CommandResult::FinalUse{decision,..} if decision=="DENY")
    );
}

#[tokio::test]
async fn recovered_receipt_binds_original_command_and_exact_retained_bytes() {
    let host = Host::new().await;
    let client = host.client();
    let command = finalize();
    for (path, value) in [
        ("/original_response/original_command_id", json!(SUBMISSION)),
        ("/original_response/recovered", json!(false)),
        (
            "/receipt_ref",
            json!(format!("urn:marty:delegated-receipt:{CHALLENGE}")),
        ),
        ("/receipt_digest", json!(digest(b"different"))),
        ("/compact_jws", json!("e30.e30.ZGlmZmVyZW50")),
        ("/semantics", json!("RENEWED_AUTHORIZATION")),
    ] {
        let mut body = receipt(&command);
        *body.pointer_mut(path).unwrap() = value;
        host.push(Reply::json(body));
        assert_eq!(
            client.recover_receipt(&command).await.unwrap_err(),
            ClientError::CorrelationMismatch,
            "{path}"
        );
    }
    let mut old = receipt(&command);
    old["original_response"]["result"]["recorded_at"] = json!("2020-01-01T00:00:00Z");
    old["original_response"]["result"]["authorization_expires_at"] = json!("2020-01-01T00:00:01Z");
    host.push(Reply::json(old));
    assert_eq!(
        client
            .recover_receipt(&command)
            .await
            .unwrap()
            .compact_jws(),
        COMPACT
    );
}

#[tokio::test]
async fn strict_wire_rejects_duplicates_unknown_fields_noncanonical_ids_and_times() {
    let host = Host::new().await;
    let client = host.client();
    let command = start();
    let valid = challenge(&command, false).to_string();
    for body in [
        valid.replacen('{', "{\"recovered\":false,", 1),
        valid.replace(
            "\"operation\":{",
            "\"operation\":{\"action\":\"urn:other\",",
        ),
        valid.replacen('{', "{\"unknown\":true,", 1),
        valid.replace(CHALLENGE, "22222222222242228222222222222222"),
        valid.replace(CREATED, "2026-11-21T15:00:00+00:00"),
        valid.replace(CREATED, "2026-11-21T15:00:00.000Z"),
        valid.replace("\"revision\":3", "\"revision\":3.0"),
    ] {
        host.push(Reply::raw("application/json", body).link(&host.origin));
        assert_eq!(
            client.start(&command).await.unwrap_err(),
            ClientError::InvalidResponse
        );
    }
}

#[tokio::test]
async fn protected_headers_and_body_limits_are_enforced_before_artifacts_escape() {
    let host = Host::new().await;
    let client = host.client();
    let command = start();
    for key in [
        "cache-control",
        "pragma",
        "x-content-type-options",
        "content-type",
    ] {
        let mut reply = Reply::json(challenge(&command, false)).link(&host.origin);
        reply.headers.remove(key);
        host.push(reply);
        assert_eq!(
            client.start(&command).await.unwrap_err(),
            ClientError::InvalidResponse,
            "{key}"
        );
    }
    let mut reply = Reply::json(challenge(&command, false)).link(&host.origin);
    reply
        .headers
        .append("cache-control", HeaderValue::from_static("no-store"));
    host.push(reply);
    assert_eq!(
        client.start(&command).await.unwrap_err(),
        ClientError::InvalidResponse
    );
    let mut reply = Reply::json(challenge(&command, false)).link(&host.origin);
    reply
        .headers
        .insert("content-encoding", HeaderValue::from_static("gzip"));
    host.push(reply);
    assert_eq!(
        client.start(&command).await.unwrap_err(),
        ClientError::InvalidResponse
    );
    host.started_reply(&command, false);
    let started = client.start(&command).await.unwrap();
    host.push(Reply::raw(
        "application/oauth-authz-req+jwt",
        vec![b'x'; MAX_REQUEST_ARTIFACT_BYTES + 1],
    ));
    assert_eq!(
        client.fetch_request(&started).await.unwrap_err(),
        ClientError::TooLarge
    );
    host.push(Reply::raw(
        "application/oauth-authz-req+jwt",
        "invalid opaque bytes",
    ));
    assert_eq!(
        client.fetch_request(&started).await.unwrap_err(),
        ClientError::InvalidResponse
    );
    let mut body = receipt(&finalize());
    body["compact_jws"] = json!("x".repeat(MAX_COMPACT_RECEIPT_BYTES + 1));
    host.push(Reply::json(body));
    assert_eq!(
        client.recover_receipt(&finalize()).await.unwrap_err(),
        ClientError::TooLarge
    );
}

#[test]
fn diagnostics_do_not_expose_retained_commands_proofs_or_signer_configuration() {
    let command = start();
    let finalize = finalize();
    for debug in [
        format!("{command:?}"),
        format!("{finalize:?}"),
        format!(
            "{:?}",
            CallerVerifiedRequest {
                response_uri: "https://secret.example/submit".into(),
                state: "secret-state".into(),
                query_id: "secret-query".into()
            }
        ),
    ] {
        assert!(!debug.contains("secret"));
        assert!(!debug.contains("original terms"));
        assert!(!debug.contains(command.command_digest()));
    }
    for error in [
        ClientError::Transport,
        ClientError::InvalidResponse,
        ClientError::CorrelationMismatch,
        ClientError::Http(503),
    ] {
        let text = format!("{error:?}: {error}");
        assert!(!text.contains(COMPACT));
        assert!(!text.contains(command.command_digest()));
    }
}
