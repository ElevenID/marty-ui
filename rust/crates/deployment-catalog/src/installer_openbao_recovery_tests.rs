use super::*;
use crate::installer_compose::ContainerIdentity;
use rustls::pki_types::{pem::PemObject, PrivateKeyDer};
use std::{os::unix::fs::PermissionsExt, process::Command};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const INSTALLATION: &str = "11111111-1111-4111-8111-111111111111";
const ATTEMPT: &str = "22222222-2222-4222-8222-222222222222";
const CLUSTER: &str = "33333333-3333-4333-8333-333333333333";
const ISSUER: &str = "44444444-4444-4444-8444-444444444444";
const NEXT: &str = "55555555-5555-4555-8555-555555555555";

struct Fixture {
    directory: tempfile::TempDir,
    authority: Authority,
    resources: ProjectResources,
    old: Inspection,
    candidate: LocalTransaction,
    now: u64,
}
fn openssl(args: &[&str]) {
    let output = Command::new("openssl").args(args).output().unwrap();
    assert!(
        output.status.success(),
        "local certificate fixture generation failed"
    );
}
fn fixture() -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = |name: &str| directory.path().join(name).to_str().unwrap().to_owned();
    let config = path("openssl.cnf");
    std::fs::write(&config, "[req]\ndistinguished_name=dn\n[dn]\n").unwrap();
    openssl(&[
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-nodes",
        "-days",
        "3650",
        "-subj",
        "/CN=Local control test CA",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
        "-config",
        &config,
        "-keyout",
        &path("ca.key"),
        "-out",
        &path("ca.pem"),
    ]);
    openssl(&[
        "req",
        "-new",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-nodes",
        "-subj",
        "/CN=openbao",
        "-config",
        &config,
        "-keyout",
        &path("node.key"),
        "-out",
        &path("node.csr"),
    ]);
    std::fs::write(path("extensions"),"subjectAltName=DNS:openbao,DNS:host.docker.internal,DNS:localhost,IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n").unwrap();
    for (name, serial) in [("old.pem", "2"), ("candidate.pem", "3")] {
        openssl(&[
            "x509",
            "-req",
            "-in",
            &path("node.csr"),
            "-CA",
            &path("ca.pem"),
            "-CAkey",
            &path("ca.key"),
            "-set_serial",
            serial,
            "-days",
            "30",
            "-extfile",
            &path("extensions"),
            "-out",
            &path(name),
        ]);
    }
    let ca = std::fs::read(path("ca.pem")).unwrap();
    let ca_cert =
        crate::installer_ingress_provision::certificate(std::str::from_utf8(&ca).unwrap()).unwrap();
    let old_pem = std::fs::read_to_string(path("old.pem")).unwrap();
    let old_cert = crate::installer_ingress_provision::certificate(&old_pem).unwrap();
    let candidate_pem = std::fs::read_to_string(path("candidate.pem")).unwrap();
    let candidate_cert = crate::installer_ingress_provision::certificate(&candidate_pem).unwrap();
    let ca_sha256 = sha256(&ca_cert.to_der().unwrap());
    let spki_sha256 = sha256(
        &old_cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .unwrap(),
    );
    let directory_binding = DirectoryBinding {
        device: 1,
        inode: 2,
        owner_uid: 0,
        owner_gid: 0,
        mode: 0o700,
    };
    let authority = Authority {
        ca,
        observation_sha256: "f".repeat(64),
        observation: ControlObservation {
            schema: "elevenid.installer-openbao-control-observation/v1".into(),
            installation_id: INSTALLATION.into(),
            engine_id: "test-engine".into(),
            container_id: "a".repeat(64),
            enrollment_container_id: "b".repeat(64),
            image: format!("sha256:{}", "c".repeat(64)),
            configuration_sha256: "d".repeat(64),
            compose_receipt_sha256: "e".repeat(64),
            socket_directory: directory_binding.clone(),
            openbao_state_directory: directory_binding,
            enrollment_pending_sha256: "c".repeat(64),
            enrollment_result_sha256: "d".repeat(64),
            root_retired: false,
            automatic_recovery_qualified: false,
            installation_ready: false,
            enrollment: EnrollmentReceipt {
                schema: "elevenid.openbao-control-enrollment-result/v1".into(),
                installation_id: INSTALLATION.into(),
                attempt_id: NEXT.into(),
                cluster_id: CLUSTER.into(),
                issuer_id: ISSUER.into(),
                ca_sha256: ca_sha256.clone(),
                spki_sha256: spki_sha256.clone(),
                policy_sha256: "a".repeat(64),
                scoped_login_verified: true,
                scoped_signing_verified: true,
                forbidden_operations_denied: true,
                verification_token_revoked: true,
                existing_ca_key_retained: true,
                node_key_preserved: true,
                root_retired: false,
            },
        },
    };
    let bao = ContainerIdentity {
        id: authority.observation.container_id.clone(),
        service: "openbao".into(),
        image: authority.observation.image.clone(),
        config_hash: "d".repeat(64),
        setup: false,
        setup_execution: None,
        health_required: true,
        cap_add: BTreeSet::new(),
        cap_drop: BTreeSet::from(["ALL".into()]),
        read_only: true,
        memory_limit: 1024 * 1024 * 1024,
    };
    let resources = ProjectResources {
        containers: BTreeMap::from([("openbao".into(), bao)]),
        networks: BTreeMap::new(),
        volumes: BTreeSet::new(),
    };
    let old = Inspection {
        schema: "elevenid.openbao-tcp-inspection/v1".into(),
        installation_id: INSTALLATION.into(),
        cluster_id: CLUSTER.into(),
        issuer_id: ISSUER.into(),
        ca_sha256: ca_sha256.clone(),
        spki_sha256: spki_sha256.clone(),
        certificate_pem: old_pem,
        certificate_sha256: sha256(&old_cert.to_der().unwrap()),
        not_before: clock(
            old_cert
                .tbs_certificate
                .validity
                .not_before
                .to_unix_duration()
                .as_secs(),
        )
        .unwrap(),
        not_after: clock(
            old_cert
                .tbs_certificate
                .validity
                .not_after
                .to_unix_duration()
                .as_secs(),
        )
        .unwrap(),
        ca_not_after: clock(
            ca_cert
                .tbs_certificate
                .validity
                .not_after
                .to_unix_duration()
                .as_secs(),
        )
        .unwrap(),
        node_key_matches: true,
        renewal_issuer_usable: true,
        transaction: None,
        transaction_sha256: None,
        completed_receipt: None,
        completed_receipt_sha256: None,
        supersession: None,
        supersession_sha256: None,
        pending_supersession: None,
        pending_supersession_sha256: None,
    };
    let candidate = LocalTransaction {
        schema: "elevenid.openbao-tcp-recovery-transaction/v1".into(),
        installation_id: INSTALLATION.into(),
        attempt_id: ATTEMPT.into(),
        cluster_id: CLUSTER.into(),
        issuer_id: ISSUER.into(),
        previous_certificate_sha256: old.certificate_sha256.clone(),
        ca_sha256,
        spki_sha256,
        phase: "candidate".into(),
        certificate_pem: candidate_pem,
        certificate_sha256: sha256(&candidate_cert.to_der().unwrap()),
        not_after: clock(
            candidate_cert
                .tbs_certificate
                .validity
                .not_after
                .to_unix_duration()
                .as_secs(),
        )
        .unwrap(),
        supersedes_attempt_id: None,
    };
    Fixture {
        directory,
        authority,
        resources,
        old,
        candidate,
        now: now().unwrap(),
    }
}
fn pending(f: &Fixture) -> Attempt {
    let bao = &f.resources.containers["openbao"];
    let intent = Intent {
        schema: "elevenid.installer-openbao-tls-recovery-intent/v1".into(),
        installation_id: f.old.installation_id.clone(),
        engine_id: "test-engine".into(),
        project: "test-project".into(),
        container_id: bao.id.clone(),
        image: bao.image.clone(),
        config_hash: bao.config_hash.clone(),
        authority_sha256: f.authority.observation_sha256.clone(),
        attempt_id: ATTEMPT.into(),
        sequence: 1,
        previous_attempt_id: None,
        previous_intent_sha256: None,
        reason: "renewal_due".into(),
        previous_certificate_sha256: f.old.certificate_sha256.clone(),
        created_at: clock(f.now).unwrap(),
        superseded_transaction: None,
        superseded_transaction_sha256: None,
    };
    Attempt {
        intent_sha256: sha256(&encode(&intent).unwrap()),
        intent,
        publication: None,
        publication_sha256: None,
        reload_intent: None,
        reload_intent_sha256: None,
        reload: None,
        reload_sha256: None,
        complete: None,
    }
}
fn published(f: &Fixture) -> Inspection {
    let mut result = f.old.clone();
    let mut transaction = f.candidate.clone();
    transaction.phase = "published".into();
    result.certificate_pem = transaction.certificate_pem.clone();
    result.certificate_sha256 = transaction.certificate_sha256.clone();
    result.not_after = transaction.not_after.clone();
    result.transaction_sha256 = Some(sha256(&encode(&transaction).unwrap()));
    result.completed_receipt = Some(transaction.receipt());
    result.completed_receipt_sha256 = Some(sha256(&encode(&transaction.receipt()).unwrap()));
    result.transaction = Some(transaction);
    result
}
fn completed(f: &Fixture) -> Attempt {
    let observed = published(f);
    let mut current = pending(f);
    let publication = Publication {
        schema: "elevenid.installer-openbao-tls-publication/v1".into(),
        intent_sha256: current.intent_sha256.clone(),
        receipt: observed.completed_receipt.unwrap(),
        receipt_sha256: observed.completed_receipt_sha256.unwrap(),
        certificate_pem: observed.certificate_pem,
    };
    let publication_sha256 = sha256(&encode(&publication).unwrap());
    let reload_intent = ReloadIntent {
        schema: "elevenid.installer-openbao-tls-reload-intent/v1".into(),
        intent_sha256: current.intent_sha256.clone(),
        publication_sha256: publication_sha256.clone(),
        container_id: current.intent.container_id.clone(),
        signal: "HUP".into(),
    };
    let reload_intent_sha256 = sha256(&encode(&reload_intent).unwrap());
    let reload = Reload {
        schema: "elevenid.installer-openbao-tls-reload/v1".into(),
        reload_intent_sha256: reload_intent_sha256.clone(),
        command_acknowledged: true,
    };
    let reload_sha256 = sha256(&encode(&reload).unwrap());
    current.complete = Some(Completion {
        schema: "elevenid.installer-openbao-tls-recovery-complete/v1".into(),
        intent_sha256: current.intent_sha256.clone(),
        publication_sha256: publication_sha256.clone(),
        reload_sha256: reload_sha256.clone(),
        certificate_sha256: publication.receipt.certificate_sha256.clone(),
        ca_sha256: f.old.ca_sha256.clone(),
        spki_sha256: f.old.spki_sha256.clone(),
        cluster_id: CLUSTER.into(),
        verified_at: clock(f.now).unwrap(),
        file_publication_observed: true,
        reload_requested: true,
        network_tls_verified: true,
        installation_ready: false,
    });
    current.publication = Some(publication);
    current.publication_sha256 = Some(publication_sha256);
    current.reload_intent = Some(reload_intent);
    current.reload_intent_sha256 = Some(reload_intent_sha256);
    current.reload = Some(reload);
    current.reload_sha256 = Some(reload_sha256);
    current
}

#[test]
fn inspection_rejects_changed_identity_private_fields_duplicates_and_missing_flags() {
    let f = fixture();
    f.old.validate(&f.authority, f.now).unwrap();
    let serialized = encode(&f.old).unwrap();
    let parsed: Inspection = decode(&serialized).unwrap();
    assert_eq!(parsed, f.old);
    for change in [
        "installation_id",
        "cluster_id",
        "issuer_id",
        "ca_sha256",
        "spki_sha256",
        "certificate_sha256",
        "node_key_matches",
        "renewal_issuer_usable",
        "not_after",
        "transaction_sha256",
    ] {
        let mut altered = f.old.clone();
        match change {
            "installation_id" => altered.installation_id = NEXT.into(),
            "cluster_id" => altered.cluster_id = NEXT.into(),
            "issuer_id" => altered.issuer_id = NEXT.into(),
            "ca_sha256" => altered.ca_sha256 = "e".repeat(64),
            "spki_sha256" => altered.spki_sha256 = "e".repeat(64),
            "certificate_sha256" => altered.certificate_sha256 = "e".repeat(64),
            "node_key_matches" => altered.node_key_matches = false,
            "renewal_issuer_usable" => altered.renewal_issuer_usable = false,
            "not_after" => altered.not_after = clock(f.now + 1).unwrap(),
            "transaction_sha256" => altered.transaction_sha256 = Some("invalid".into()),
            _ => unreachable!(),
        }
        assert!(
            altered.validate(&f.authority, f.now).is_err(),
            "accepted changed {change}"
        );
    }
    let value = serde_json::to_value(&f.old).unwrap();
    for field in [
        "node_key_matches",
        "renewal_issuer_usable",
        "not_before",
        "not_after",
        "ca_not_after",
    ] {
        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(decode::<Inspection>(&encode(&missing).unwrap()).is_err());
    }
    let text = String::from_utf8(serialized).unwrap();
    for invalid in [
        text.replacen('{', "{\"schema\":\"duplicate\",", 1),
        format!("{text} {{}}"),
        text.replacen('{', "{\"secret_id\":\"forbidden\",", 1),
    ] {
        assert!(decode::<Inspection>(invalid.as_bytes()).is_err());
    }
    let future = timestamp(&f.old.not_after).unwrap() + 1;
    f.old.validate(&f.authority, future).unwrap();
}

#[test]
fn completion_requires_publication_hup_and_verified_leaf_in_the_same_history() {
    let f = fixture();
    let complete = completed(&f);
    validate_history(
        std::slice::from_ref(&complete),
        &f.authority,
        &f.resources,
        "test-project",
        f.now,
    )
    .unwrap();
    bind_current(std::slice::from_ref(&complete), &published(&f)).unwrap();
    for failure in [
        "no-publication",
        "no-reload-intent",
        "no-reload",
        "false-tls",
        "wrong-leaf",
        "wrong-cluster",
        "ready",
        "wrong-container",
    ] {
        let mut changed = complete.clone();
        match failure {
            "no-publication" => changed.publication = None,
            "no-reload-intent" => changed.reload_intent = None,
            "no-reload" => changed.reload = None,
            "false-tls" => changed.complete.as_mut().unwrap().network_tls_verified = false,
            "wrong-leaf" => changed.complete.as_mut().unwrap().certificate_sha256 = "e".repeat(64),
            "wrong-cluster" => changed.complete.as_mut().unwrap().cluster_id = NEXT.into(),
            "ready" => changed.complete.as_mut().unwrap().installation_ready = true,
            "wrong-container" => changed.intent.container_id = "f".repeat(64),
            _ => unreachable!(),
        }
        assert!(
            validate_history(
                &[changed],
                &f.authority,
                &f.resources,
                "test-project",
                f.now
            )
            .is_err(),
            "accepted {failure}"
        );
    }
    assert!(
        bind_current(&[complete], &f.old).is_err(),
        "completed receipt accepted an old active leaf"
    );
    assert!(
        bind_current(&[], &published(&f)).is_err(),
        "unrecorded local transaction was adopted"
    );
}

#[test]
fn expired_candidate_requires_linked_new_intent_and_cannot_bypass_unexpired_work() {
    let f = fixture();
    let first = pending(&f);
    let expiry = timestamp(&f.candidate.not_after).unwrap();
    let mut second = pending(&f);
    second.intent.attempt_id = NEXT.into();
    second.intent.sequence = 2;
    second.intent.previous_attempt_id = Some(ATTEMPT.into());
    second.intent.previous_intent_sha256 = Some(first.intent_sha256.clone());
    second.intent.reason = "candidate_expired".into();
    second.intent.created_at = clock(expiry + 1).unwrap();
    second.intent.superseded_transaction = Some(f.candidate.clone());
    second.intent.superseded_transaction_sha256 = Some("f".repeat(64));
    second.intent_sha256 = sha256(&encode(&second.intent).unwrap());
    validate_history(
        &[first.clone(), second.clone()],
        &f.authority,
        &f.resources,
        "test-project",
        expiry + 1,
    )
    .unwrap();
    let mut observation = f.old.clone();
    observation.transaction = Some(f.candidate.clone());
    observation.transaction_sha256 = second.intent.superseded_transaction_sha256.clone();
    observation.validate(&f.authority, expiry + 1).unwrap();
    bind_current(&[first.clone(), second.clone()], &observation).unwrap();
    for failure in [
        "unexpired",
        "missing-prior",
        "wrong-journal",
        "wrong-candidate",
        "skipped-sequence",
        "wrong-authority",
    ] {
        let mut changed = second.clone();
        match failure {
            "unexpired" => changed.intent.created_at = clock(f.now).unwrap(),
            "missing-prior" => changed.intent.previous_attempt_id = None,
            "wrong-journal" => changed.intent.superseded_transaction_sha256 = Some("a".repeat(64)),
            "wrong-candidate" => {
                changed
                    .intent
                    .superseded_transaction
                    .as_mut()
                    .unwrap()
                    .certificate_sha256 = "e".repeat(64)
            }
            "skipped-sequence" => changed.intent.sequence = 3,
            "wrong-authority" => {
                changed
                    .intent
                    .superseded_transaction
                    .as_mut()
                    .unwrap()
                    .issuer_id = NEXT.into()
            }
            _ => unreachable!(),
        }
        let history = [first.clone(), changed];
        assert!(
            validate_history(
                &history,
                &f.authority,
                &f.resources,
                "test-project",
                expiry + 1
            )
            .is_err()
                || bind_current(&history, &observation).is_err(),
            "accepted {failure}"
        );
    }
    let mut retired = observation.clone();
    retired.pending_supersession = Some(Supersession {
        schema: "elevenid.openbao-tcp-recovery-supersession/v1".into(),
        previous_transaction: f.candidate.clone(),
        previous_journal_sha256: observation.transaction_sha256.clone().unwrap(),
        replacement_attempt_id: NEXT.into(),
        observed_active_certificate_sha256: f.old.certificate_sha256.clone(),
        recorded_at: clock(expiry + 1).unwrap(),
        reason: "candidate_expired".into(),
        previous_certificate_published: false,
    });
    retired.pending_supersession_sha256 = Some("b".repeat(64));
    retired.validate(&f.authority, expiry + 1).unwrap();
    bind_current(&[first.clone(), second], &retired).unwrap();
    assert!(
        bind_current(&[first], &retired).is_err(),
        "retired attempt remained runnable"
    );
}

#[test]
fn durable_pending_intent_reopens_without_generating_another_uuid() {
    use crate::installer_state::{Identity, InstallerState, RuntimeBinding, RuntimeProfile};
    let mut f = fixture();
    let installation = f.directory.path().join("installation");
    let mut writer = InstallerState::create_with_runtime(
        &installation,
        Identity {
            source_sha: "a".repeat(40),
            release_tag: "v1.2.3".into(),
            inventory_sha256: format!("sha256:{}", "b".repeat(64)),
        },
        RuntimeBinding {
            docker_host: "unix:///var/run/docker.sock".into(),
            engine_id: "test-engine".into(),
            openbao_port: 18200,
            profile: RuntimeProfile::Rootful,
        },
    )
    .unwrap();
    writer.create_private_directory("evidence").unwrap();
    let id = writer.journal().installation_id().to_string();
    f.old.installation_id = id.clone();
    f.authority.observation.installation_id = id.clone();
    f.authority.observation.enrollment.installation_id = id;
    writer
        .with_maintenance(|state| {
            begin(
                state,
                &f.authority,
                &f.resources,
                &[],
                &f.old,
                "renewal_due",
                f.now,
            )
        })
        .unwrap();
    drop(writer);
    let mut state = LockedMaintenance::open(&installation).unwrap();
    let first = history(&state, &f.authority, &f.resources, f.now).unwrap();
    assert_eq!(first.len(), 1);
    bind_current(&first, &f.old).unwrap();
    let id = first[0].intent.attempt_id.clone();
    assert!(state
        .write_evidence_exclusive(
            &record_name(&id, "intent"),
            &encode(&first[0].intent).unwrap()
        )
        .is_err());
    drop(state);
    let state = LockedMaintenance::open(&installation).unwrap();
    let reopened = history(&state, &f.authority, &f.resources, f.now).unwrap();
    assert_eq!(reopened.len(), 1);
    assert_eq!(reopened[0].intent.attempt_id, id);
    assert!(reopened[0].publication.is_none());
    let evidence = installation.join("evidence");
    std::fs::write(evidence.join(format!("{PREFIX}unrecognized.json")), b"{}").unwrap();
    assert!(history(&state, &f.authority, &f.resources, f.now).is_err());
}

async fn server(f: &Fixture, certificate: &str, body: Value) -> (u16, tokio::task::JoinHandle<()>) {
    let der = CertificateDer::from_pem_file(f.directory.path().join(certificate)).unwrap();
    let key = PrivateKeyDer::from_pem_file(f.directory.path().join("node.key")).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![der], key)
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let body = serde_json::to_string(&body).unwrap();
    let task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        if let Ok(mut tls) = tokio_rustls::TlsAcceptor::from(Arc::new(config))
            .accept(socket)
            .await
        {
            let mut request = [0; 4096];
            let count = tls.read(&mut request).await.unwrap_or(0);
            if count == 0 {
                return;
            }
            let request = std::str::from_utf8(&request[..count])
                .unwrap()
                .to_ascii_lowercase();
            assert!(request.starts_with("get /v1/sys/health http/1.1\r\n"));
            assert!(
                !request.contains("x-vault-token:")
                    && !request.contains("authorization:")
                    && !request.contains("cookie:")
            );
            let response=format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len());
            let _ = tls.write_all(response.as_bytes()).await;
            let _ = tls.shutdown().await;
        }
    });
    (port, task)
}

#[tokio::test]
async fn verified_network_requires_current_leaf_trusted_ca_and_ready_enrolled_cluster() {
    let f = fixture();
    let observed = published(&f);
    for case in ["valid", "old-leaf", "wrong-cluster", "sealed", "wrong-ca"] {
        let leaf = if case == "old-leaf" {
            "old.pem"
        } else {
            "candidate.pem"
        };
        let body = serde_json::json!({"initialized":true,"sealed":case=="sealed","cluster_id":if case=="wrong-cluster" {NEXT} else {CLUSTER}});
        let (port, task) = server(&f, leaf, body).await;
        let mut authority = f.authority.clone();
        let wrong_ca = if case == "wrong-ca" {
            Some(fixture())
        } else {
            None
        };
        if let Some(wrong) = wrong_ca.as_ref() {
            authority.ca = wrong.authority.ca.clone();
        }
        assert_eq!(
            verify_network(&authority, &observed, port).await.is_ok(),
            case == "valid",
            "case {case}"
        );
        task.await.unwrap();
    }
}
