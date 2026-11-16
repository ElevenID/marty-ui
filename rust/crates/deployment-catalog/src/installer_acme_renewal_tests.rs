//! Uses candidates admitted by the real in-memory enrolment fixture. ARI uses
//! the maintained protocol and a GET-only fixture; no CA or OpenBao is contacted.
use super::*;
use crate::installer_acme::tests::Fixture;
use bytes::Bytes;
use http::{Method, Request, Response};
use http_body_util::BodyExt;
use marty_acme_client::protocol::{BodyWrapper, BytesResponse};
use spki::der::{asn1::OctetString, DecodePem};
use std::{collections::VecDeque, future::Future, pin::Pin, sync::Mutex};
use x509_cert::{ext::AsExtension, serial_number::SerialNumber};

const CA: &str = "https://acme-staging-v02.api.letsencrypt.org";

#[derive(Clone)]
struct Reply {
    body: Value,
    retry_after: Option<String>,
    status: u16,
    transport_error: bool,
}
impl Reply {
    fn window(start: u64, end: u64, retry_after: Option<&str>) -> Self {
        Self {
            body: json!({"suggestedWindow":{"start":chrono::DateTime::from_timestamp(start as i64,0).unwrap().to_rfc3339(),"end":chrono::DateTime::from_timestamp(end as i64,0).unwrap().to_rfc3339()}}),
            retry_after: retry_after.map(str::to_owned),
            status: 200,
            transport_error: false,
        }
    }
}
struct MockState {
    requests: Vec<String>,
    replies: VecDeque<Reply>,
    supports_ari: bool,
    expire_after_directory: Option<u64>,
}
#[derive(Clone)]
struct MockAri {
    state: Arc<Mutex<MockState>>,
    identifier: String,
}
impl MockAri {
    fn new(identifier: String, replies: Vec<Reply>) -> Self {
        Self {
            state: Arc::new(Mutex::new(MockState {
                requests: Vec::new(),
                replies: replies.into(),
                supports_ari: true,
                expire_after_directory: None,
            })),
            identifier,
        }
    }
    fn requests(&self) -> Vec<String> {
        self.state.lock().unwrap().requests.clone()
    }
    fn push(&self, reply: Reply) {
        self.state.lock().unwrap().replies.push_back(reply);
    }
}
impl HttpClient for MockAri {
    fn request(
        &self,
        request: Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = std::result::Result<BytesResponse, ProtocolError>> + Send>>
    {
        let mock = self.clone();
        Box::pin(async move {
            let (parts, body) = request.into_parts();
            assert_eq!(
                parts.method,
                Method::GET,
                "ARI owner must never post or request a nonce"
            );
            assert!(body.collect().await.unwrap().to_bytes().is_empty());
            assert!(!parts.headers.contains_key("Authorization"));
            assert!(!parts.headers.contains_key("X-Vault-Token"));
            assert_eq!(
                parts.uri.authority().unwrap().as_str(),
                "acme-staging-v02.api.letsencrypt.org"
            );
            let mut state = mock.state.lock().unwrap();
            state
                .requests
                .push(format!("{} {}", parts.method, parts.uri.path()));
            let reply = if parts.uri.path() == "/directory" {
                let mut body = json!({"newNonce":format!("{CA}/nonce"),"newAccount":format!("{CA}/account"),"newOrder":format!("{CA}/order"),"renewalInfo":format!("{CA}/renewal"),"meta":{"termsOfService":"https://letsencrypt.org/documents/changed-terms.pdf","profiles":{"shortlived":"fixture"}}});
                if !state.supports_ari {
                    body.as_object_mut().unwrap().remove("renewalInfo");
                }
                if let Some(expiry) = state.expire_after_directory {
                    TEST_TIME.with(|value| value.set(Some(expiry)));
                }
                Reply {
                    body,
                    retry_after: None,
                    status: 200,
                    transport_error: false,
                }
            } else {
                assert_eq!(parts.uri.path(), format!("/renewal/{}", mock.identifier));
                state
                    .replies
                    .pop_front()
                    .expect("unexpected extra ARI request")
            };
            if reply.transport_error {
                return Err(ProtocolError::Str("ACME HTTPS request failed"));
            }
            let mut response = Response::builder().status(reply.status);
            if let Some(retry) = reply.retry_after {
                response = response.header("Retry-After", retry);
            }
            Ok(BytesResponse::from(
                response
                    .body(BodyWrapper::from(serde_json::to_vec(&reply.body).unwrap()))
                    .unwrap(),
            ))
        })
    }
}

struct CandidateFixture {
    enrolment: Fixture,
    candidate: AcmeCandidate,
}
impl CandidateFixture {
    fn new() -> Self {
        Self::with_certificate_lifetime(8)
    }
    fn with_certificate_lifetime(lifetime_hours: u64) -> Self {
        let enrolment = Fixture::with_certificate_lifetime(lifetime_hours);
        let candidate = enrolment.finish().candidate.unwrap();
        TEST_TIME.with(|value| {
            value.set(Some(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            ))
        });
        Self {
            enrolment,
            candidate,
        }
    }
    fn binding(&self) -> Binding {
        let state = LockedInspection::open(self.enrolment.installation()).unwrap();
        Binding::from_candidate(&state, &self.candidate).unwrap()
    }
    fn mock(&self, replies: Vec<Reply>) -> MockAri {
        MockAri::new(self.binding().certificate_identifier.unwrap(), replies)
    }
    fn ensure(&self) -> Result<RenewalSchedule> {
        let mut state = LockedMaintenance::open(self.enrolment.installation())?;
        ensure_for_candidate(&mut state, &self.candidate)
    }
    fn refresh(&self, http: &MockAri) -> Result<RenewalSchedule> {
        let mut state = LockedMaintenance::open(self.enrolment.installation())?;
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(refresh_with_http(
                &mut state,
                &self.candidate,
                Box::new(http.clone()),
            ))
    }
    fn set_time(&self, observed: u64) {
        TEST_TIME.with(|value| value.set(Some(observed)));
    }
}
impl Drop for CandidateFixture {
    fn drop(&mut self) {
        TEST_TIME.with(|value| value.set(None));
    }
}

#[test]
fn returned_candidate_has_a_durable_actual_lifetime_fallback() {
    let fixture = CandidateFixture::new();
    let state = LockedInspection::open(fixture.enrolment.installation()).unwrap();
    let leaf = fixture.candidate.metadata()["leaf_der_sha256"]
        .as_str()
        .unwrap();
    let first = status(&state, AcmeEnvironment::Staging, leaf)
        .unwrap()
        .expect("enrolment completion must ensure a schedule");
    let before = fixture.candidate.metadata()["not_before"].as_u64().unwrap();
    let after = fixture.candidate.metadata()["not_after"].as_u64().unwrap();
    assert_eq!(first["fallback_renew_at"], before + (after - before) / 2);
    assert_eq!(first["automatic_renewal"], false);
    assert_eq!(first["installation_ready"], false);
    assert_eq!(first["read_only"], true);
    assert_eq!(first["sequence"], 0);
    drop(state);
    let reopened = fixture.ensure().unwrap();
    assert_eq!(reopened.digest, first["schedule_receipt_sha256"]);
    let path = fixture
        .enrolment
        .installation()
        .join("evidence")
        .join(record_name(&reopened.binding, 0));
    assert_eq!(std::fs::metadata(path).unwrap().mode() & 0o7777, 0o600);
}

#[test]
fn anonymous_ari_refresh_preserves_selected_time_and_retry_deadline_across_reopen() {
    let fixture = CandidateFixture::new();
    let observed = now().unwrap();
    let http = fixture.mock(vec![Reply::window(
        observed + 3600,
        observed + 7200,
        Some("3600"),
    )]);
    let first = fixture.refresh(&http).unwrap();
    let selected = first.state.window.as_ref().unwrap().selected_at;
    assert!((observed + 3600..observed + 7200).contains(&selected));
    assert_eq!(first.state.next_refresh_at, Some(observed + 3600));
    assert_eq!(http.requests().len(), 2);
    let second = fixture.refresh(&http).unwrap();
    assert_eq!(second.digest, first.digest);
    assert_eq!(
        http.requests().len(),
        2,
        "reboot must not skip retained Retry-After"
    );
    fixture.set_time(first.state.next_refresh_at.unwrap());
    http.push(Reply::window(
        observed + 3600,
        observed + 7200,
        Some("3600"),
    ));
    let third = fixture.refresh(&http).unwrap();
    assert_eq!(third.state.window.unwrap().selected_at, selected);
    assert_eq!(http.requests().len(), 4);
}

#[test]
fn changed_window_gets_one_selection_and_a_returned_old_window_reuses_its_selection() {
    let fixture = CandidateFixture::new();
    let observed = now().unwrap();
    let http = fixture.mock(vec![
        Reply::window(observed + 3600, observed + 7200, Some("3600")),
        Reply::window(observed + 7200, observed + 10800, Some("3600")),
        Reply::window(observed + 3600, observed + 7200, Some("3600")),
    ]);
    let first = fixture.refresh(&http).unwrap();
    let selected = first.state.window.as_ref().unwrap().selected_at;
    fixture.set_time(first.state.next_refresh_at.unwrap());
    let second = fixture.refresh(&http).unwrap();
    assert!((observed + 7200..observed + 10800)
        .contains(&second.state.window.as_ref().unwrap().selected_at));
    assert_ne!(second.state.window.as_ref().unwrap().selected_at, selected);
    fixture.set_time(second.state.next_refresh_at.unwrap());
    let third = fixture.refresh(&http).unwrap();
    assert_eq!(third.state.window.as_ref().unwrap().selected_at, selected);
    assert_eq!(third.selected_windows.len(), 2);
    assert_eq!(third.report().unwrap()["renewal_due"], true);
}

#[test]
fn invalid_or_missing_ari_retains_lifetime_fallback_and_long_error_backoff() {
    for mode in ["invalid_window", "missing_retry", "missing_endpoint"] {
        let fixture = CandidateFixture::new();
        let observed = now().unwrap();
        let reply = if mode == "invalid_window" {
            Reply::window(observed + 3600, observed + 3600, Some("3600"))
        } else {
            Reply::window(observed + 3600, observed + 7200, None)
        };
        let http = fixture.mock(vec![reply]);
        http.state.lock().unwrap().supports_ari = mode != "missing_endpoint";
        let outcome = fixture.refresh(&http).unwrap();
        assert_eq!(outcome.state.stage, ScheduleStage::Unavailable);
        assert!(outcome.state.window.is_none());
        assert_eq!(
            outcome.state.next_refresh_at,
            Some(observed + LONG_ERROR_REFRESH)
        );
        assert_eq!(
            outcome.report().unwrap()["effective_renew_at"],
            outcome.binding.fallback_renew_at
        );
        let requests = http.requests();
        assert_eq!(fixture.refresh(&http).unwrap().digest, outcome.digest);
        assert_eq!(http.requests(), requests);
    }
}

#[test]
fn interrupted_get_has_persisted_backoff_without_resending_on_reopen() {
    let fixture = CandidateFixture::new();
    let observed = now().unwrap();
    {
        let mut state = LockedMaintenance::open(fixture.enrolment.installation()).unwrap();
        let mut saved = ensure_for_candidate(&mut state, &fixture.candidate).unwrap();
        let mut pending = saved.state.clone();
        pending.stage = ScheduleStage::FetchPending;
        pending.failures = 1;
        pending.failure = Some("fetch_interrupted_or_pending".into());
        pending.last_attempt_at = Some(observed);
        pending.next_refresh_at = Some(observed + 75);
        saved.append(&mut state, pending, observed).unwrap();
    }
    let http = fixture.mock(vec![Reply::window(
        observed + 3600,
        observed + 7200,
        Some("3600"),
    )]);
    assert_eq!(
        fixture.refresh(&http).unwrap().state.stage,
        ScheduleStage::FetchPending
    );
    assert!(http.requests().is_empty());
    fixture.set_time(observed + 75);
    assert_eq!(
        fixture.refresh(&http).unwrap().state.stage,
        ScheduleStage::Available
    );
    assert_eq!(http.requests().len(), 2);
}

#[test]
fn expiry_before_or_during_directory_fetch_prevents_an_ari_request() {
    for during_directory in [false, true] {
        let fixture = CandidateFixture::new();
        let binding = fixture.binding();
        let http = fixture.mock(Vec::new());
        if during_directory {
            http.state.lock().unwrap().expire_after_directory = Some(binding.not_after);
        } else {
            fixture.set_time(binding.not_after);
        }
        let expired = fixture.refresh(&http).unwrap();
        assert_eq!(expired.state.stage, ScheduleStage::Expired);
        assert!(expired.state.next_refresh_at.is_none());
        assert_eq!(expired.report().unwrap()["renewal_due"], true);
        assert!(expired.is_due().unwrap());
        assert_eq!(expired.not_after(), binding.not_after);
        assert_eq!(
            http.requests(),
            if during_directory {
                vec!["GET /directory".to_owned()]
            } else {
                Vec::new()
            }
        );
        let requests = http.requests();
        fixture.set_time(binding.not_after + 3600);
        assert_eq!(fixture.refresh(&http).unwrap().digest, expired.digest);
        assert_eq!(http.requests(), requests);
    }
}

#[test]
fn partial_or_noncontiguous_schedule_is_held_before_another_request() {
    for partial in [true, false] {
        let fixture = CandidateFixture::new();
        let observed = now().unwrap();
        let http = fixture.mock(vec![Reply::window(
            observed + 3600,
            observed + 7200,
            Some("3600"),
        )]);
        let saved = fixture.refresh(&http).unwrap();
        let path = fixture
            .enrolment
            .installation()
            .join("evidence")
            .join(record_name(&saved.binding, 1));
        if partial {
            std::fs::write(&path, b"{\"schema\":").unwrap();
        } else {
            std::fs::rename(
                &path,
                fixture
                    .enrolment
                    .installation()
                    .join("retained-schedule-gap.json"),
            )
            .unwrap();
        }
        fixture.set_time(saved.state.next_refresh_at.unwrap());
        let requests = http.requests();
        assert!(fixture.refresh(&http).is_err());
        assert_eq!(http.requests(), requests);
    }
}

#[test]
fn candidate_and_environment_cannot_be_substituted_for_schedule_state() {
    let first = CandidateFixture::new();
    let second = CandidateFixture::new();
    let mut state = LockedMaintenance::open(second.enrolment.installation()).unwrap();
    assert!(ensure_for_candidate(&mut state, &first.candidate).is_err());
    assert!(status(
        state.inspection(),
        AcmeEnvironment::Production,
        first.candidate.metadata()["leaf_der_sha256"]
            .as_str()
            .unwrap()
    )
    .is_err());
}

#[test]
fn retry_after_success_and_failure_preserve_server_lower_bounds() {
    for (header, expected) in [("0", MIN_REFRESH), ("86400", 86400)] {
        let fixture = CandidateFixture::with_certificate_lifetime(72);
        let observed = now().unwrap();
        let http = fixture.mock(vec![Reply::window(
            observed + 3600,
            observed + 7200,
            Some(header),
        )]);
        let saved = fixture.refresh(&http).unwrap();
        assert_eq!(
            saved.state.next_refresh_at,
            Some((observed + expected).min(saved.binding.not_after))
        );
        if expected > 12 * 3600 {
            fixture.set_time(observed + 12 * 3600);
            let requests = http.requests();
            assert_eq!(fixture.refresh(&http).unwrap().digest, saved.digest);
            assert_eq!(http.requests(), requests);
        }
    }
    let fixture = CandidateFixture::new();
    let observed = now().unwrap();
    let mut reply = Reply::window(observed + 3600, observed + 7200, Some("7200"));
    reply.status = 503;
    reply.body = json!({"type":"urn:ietf:params:acme:error:serverInternal"});
    let http = fixture.mock(vec![reply]);
    let saved = fixture.refresh(&http).unwrap();
    assert_eq!(saved.state.failure.as_deref(), Some("temporary"));
    assert!(saved.state.next_refresh_at.unwrap() >= observed + 7200);
    let requests = http.requests();
    assert_eq!(fixture.refresh(&http).unwrap().digest, saved.digest);
    assert_eq!(http.requests(), requests);
}

#[test]
fn certificate_identifier_uses_der_integer_contents_with_leading_zero() {
    let mut leaf = Certificate::from_pem(include_bytes!(
        "../../../../tests/fixtures/selfhost_ca_issuer_public.pem"
    ))
    .unwrap();
    leaf.tbs_certificate.serial_number = SerialNumber::new(&[0x87, 0x65, 0x43, 0x21]).unwrap();
    let authority = AuthorityKeyIdentifier {
        key_identifier: Some(
            OctetString::new([
                0x69, 0x88, 0x5b, 0x6b, 0x87, 0x46, 0x40, 0x41, 0xe1, 0xb3, 0x7b, 0x84, 0x7b, 0xa0,
                0xae, 0x2c, 0xde, 0x01, 0xc8, 0xd4,
            ])
            .unwrap(),
        ),
        authority_cert_issuer: None,
        authority_cert_serial_number: None,
    };
    leaf.tbs_certificate.extensions = Some(vec![authority
        .to_extension(&leaf.tbs_certificate.subject, &[])
        .unwrap()]);
    // RFC 9773 section 4.1's public encoding vector, including its sign byte.
    assert_eq!(
        certificate_identifier(&leaf).unwrap().unwrap().to_string(),
        "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE"
    );
    leaf.tbs_certificate.extensions = None;
    assert!(certificate_identifier(&leaf).unwrap().is_none());
}

#[tokio::test]
async fn public_ari_account_view_cannot_sign_any_payload() {
    let signer = PublicReadSigner {
        public: vec![4; 65],
    };
    assert!(signer.sign(b"any account mutation").await.is_err());
}

#[test]
fn a_permitted_due_receipt_remains_valid_after_a_later_ari_schedule() {
    let fixture = CandidateFixture::new();
    let original = fixture.ensure().unwrap();
    let due_at = original.effective_renew_at();
    fixture.set_time(due_at);
    {
        let view = LockedInspection::open(fixture.enrolment.installation()).unwrap();
        require_due_evidence(&view, &fixture.candidate, original.receipt_sha256(), due_at).unwrap();
        assert!(require_due_evidence(
            &view,
            &fixture.candidate,
            original.receipt_sha256(),
            due_at - 1
        )
        .is_err());
    }
    fixture.set_time(due_at + 1);
    let http = fixture.mock(vec![Reply::window(
        due_at + 600,
        due_at + 1800,
        Some("3600"),
    )]);
    let later = fixture.refresh(&http).unwrap();
    assert_ne!(later.receipt_sha256(), original.receipt_sha256());
    let view = LockedInspection::open(fixture.enrolment.installation()).unwrap();
    require_due_evidence(&view, &fixture.candidate, original.receipt_sha256(), due_at).unwrap();
    assert!(
        require_due_evidence(&view, &fixture.candidate, later.receipt_sha256(), due_at).is_err()
    );
    assert!(require_due_evidence(&view, &fixture.candidate, &"f".repeat(64), due_at).is_err());
}
