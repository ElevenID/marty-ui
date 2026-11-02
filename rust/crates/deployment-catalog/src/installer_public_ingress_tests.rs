use super::*;
use ring::{
    rand::SystemRandom,
    signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING},
};
use serde_json::json;
use spki::{
    der::{asn1::BitString, DecodePem, Encode},
    AlgorithmIdentifierOwned, ObjectIdentifier,
};
use std::str::FromStr;
use x509_cert::{
    ext::{
        pkix::{BasicConstraints, KeyUsage, KeyUsages},
        AsExtension,
    },
    name::Name,
    Certificate,
};

pub(crate) const OWNER: &str = "6d72c0ec-ef7d-4b90-90d5-81dc9e296a97";
pub(crate) const OBSERVED: u64 = 1_739_989_800;
const DNS: &str = "helloworld.letsencrypt.org";
const LEAF: &str = include_str!("../../../../tests/fixtures/acme/le-first-shortlived-leaf.pem");
const INTERMEDIATE: &str = include_str!("../../../../tests/fixtures/acme/le-e6.pem");

/// Historical public certificate only; this fixture contains no leaf private
/// key and makes no claim to own the real subject's Transit key or ACME order.
pub(crate) fn plan() -> PublicIngressPlan {
    fixture().0
}
pub(crate) fn fixture() -> (PublicIngressPlan, BTreeMap<String, Vec<u8>>) {
    let leaf = Certificate::from_pem(LEAF.as_bytes()).unwrap();
    let spki = leaf
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .unwrap();
    let key = RetainedIngressKey::from_recorded_public_key(OWNER, 1, &spki).unwrap();
    let identity =
        CertificateIdentity::from_ingress(&IngressIdentity::new(Some(DNS), None).unwrap()).unwrap();
    let certificate = certificates::admit_production_at(
        format!("{LEAF}{INTERMEDIATE}").as_bytes(),
        &identity,
        &key,
        Duration::from_secs(OBSERVED),
    )
    .unwrap();
    let mut plan = PublicIngressPlan(PlanData {
        schema: PLAN_SCHEMA.into(),
        installation_id: OWNER.into(),
        environment: AcmeEnvironment::Production,
        hosting_selection_sha256: "a".repeat(64),
        canonical_origin: format!("https://{DNS}"),
        public_entry_origin: None,
        enrolment_receipt_sha256: "b".repeat(64),
        enrolment_binding_sha256: "c".repeat(64),
        order_url: "https://acme-v02.api.letsencrypt.org/acme/order/historical-fixture".into(),
        csr_sha256: "d".repeat(64),
        key_name: key.transit_key_name().into(),
        key_version: 1,
        public_spki_base64: STANDARD.encode(spki),
        fullchain_pem: certificate.fullchain_pem().into(),
        certificate_admission: certificate.metadata().clone(),
        renewal_authority_plan_sha256: "e".repeat(64),
        renewal_enrolment_receipt_sha256: "f".repeat(64),
        initial_input_sha256: BTreeMap::new(),
        initial_inputs_observed_at: OBSERVED,
        initial_ingress_observed_at: OBSERVED,
        enrolment_cycle: 0,
        successor: None,
    });
    let initial = initial_current(&plan);
    let authority = super::authority::tests::from_inputs(&plan, &initial);
    plan.0.renewal_authority_plan_sha256 = authority.sha256().unwrap();
    plan.0.initial_input_sha256 = crate::installer_generation::hashes(&initial);
    (plan, initial)
}
pub(crate) fn current(plan: &PublicIngressPlan) -> BTreeMap<String, Vec<u8>> {
    let mut files = crate::installer_renewal_bootstrap::current_inputs()
        .into_iter()
        .map(|name| {
            let bytes = if name.ends_with("_token") {
                format!("old-private-fixture-token-{name}").into_bytes()
            } else {
                LEAF.as_bytes().to_vec()
            };
            (name, bytes)
        })
        .collect::<BTreeMap<_, _>>();
    files.insert(
        PUBLIC_OUTPUTS[0].into(),
        plan.0.fullchain_pem.as_bytes().to_vec(),
    );
    files.insert(
        PUBLIC_OUTPUTS[1].into(),
        b"old-private-fixture-ingress-token".to_vec(),
    );
    files
}
pub(crate) fn metadata(plan: &PublicIngressPlan, reused: bool) -> PublicIngressMetadata {
    let identity = plan.ingress_identity().unwrap();
    PublicIngressMetadata {
        schema: METADATA_SCHEMA.into(),
        installation_id: OWNER.into(),
        plan_sha256: plan.sha256().unwrap(),
        enrolment_receipt_sha256: plan.0.enrolment_receipt_sha256.clone(),
        key_name: plan.0.key_name.clone(),
        key_version: 1,
        public_spki_base64: plan.0.public_spki_base64.clone(),
        dns_names: identity.dns_names(),
        ip_addresses: identity.ip_addresses(),
        certificate_admission: plan.0.certificate_admission.clone(),
        certificate_reused: reused,
        token_ttl_seconds: 28800,
        token_observed_at: OBSERVED + 30,
        activation_performed: false,
        installation_ready: false,
    }
}

fn sign(mut certificate: Certificate, key: &EcdsaKeyPair) -> Certificate {
    certificate.signature_algorithm = AlgorithmIdentifierOwned {
        oid: ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"),
        parameters: None,
    };
    certificate.tbs_certificate.signature = certificate.signature_algorithm.clone();
    certificate.signature = BitString::from_bytes(
        key.sign(
            &SystemRandom::new(),
            &certificate.tbs_certificate.to_der().unwrap(),
        )
        .unwrap()
        .as_ref(),
    )
    .unwrap();
    certificate
}
pub(crate) fn initial_current(plan: &PublicIngressPlan) -> BTreeMap<String, Vec<u8>> {
    // Create only a throwaway test issuer. The ingress SPKI remains the public
    // historical fixture; no private key corresponding to it is available.
    let random = SystemRandom::new();
    let secret = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random).unwrap();
    let ca_key =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, secret.as_ref(), &random)
            .unwrap();
    let mut issuer = Certificate::from_pem(include_bytes!(
        "../../../../tests/fixtures/selfhost_ca_issuer_public.pem"
    ))
    .unwrap();
    issuer.tbs_certificate.subject =
        Name::from_str(&format!("CN=Marty local CA {}", OWNER.replace('-', ""))).unwrap();
    issuer.tbs_certificate.issuer = issuer.tbs_certificate.subject.clone();
    issuer
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key = BitString::from_bytes(ca_key.public_key().as_ref()).unwrap();
    issuer.tbs_certificate.validity.not_before = (UNIX_EPOCH + Duration::from_secs(OBSERVED - 60))
        .try_into()
        .unwrap();
    issuer.tbs_certificate.validity.not_after = (UNIX_EPOCH
        + Duration::from_secs(OBSERVED + 24 * 3600))
    .try_into()
    .unwrap();
    issuer.tbs_certificate.extensions = Some(vec![
        BasicConstraints {
            ca: true,
            path_len_constraint: None,
        }
        .to_extension(&issuer.tbs_certificate.subject, &[])
        .unwrap(),
        KeyUsage(KeyUsages::KeyCertSign.into())
            .to_extension(&issuer.tbs_certificate.subject, &[])
            .unwrap(),
    ]);
    let issuer = sign(issuer, &ca_key);
    let mut leaf = Certificate::from_pem(LEAF.as_bytes()).unwrap();
    leaf.tbs_certificate.subject = Name::from_str(&format!("CN={DNS}")).unwrap();
    leaf.tbs_certificate.issuer = issuer.tbs_certificate.subject.clone();
    leaf.tbs_certificate.validity.not_before = issuer.tbs_certificate.validity.not_before;
    leaf.tbs_certificate.validity.not_after = (UNIX_EPOCH
        + Duration::from_secs(OBSERVED + 8 * 3600))
    .try_into()
    .unwrap();
    leaf.tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .retain(|extension| {
            matches!(
                extension.extn_id.to_string().as_str(),
                "2.5.29.15" | "2.5.29.17" | "2.5.29.19" | "2.5.29.37"
            )
        });
    let leaf = sign(leaf, &ca_key);
    let mut files = current(plan);
    files.insert(
        ingress::OUTPUTS[0].into(),
        issuer
            .to_pem(spki::der::pem::LineEnding::LF)
            .unwrap()
            .into_bytes(),
    );
    files.insert(
        PUBLIC_OUTPUTS[0].into(),
        leaf.to_pem(spki::der::pem::LineEnding::LF)
            .unwrap()
            .into_bytes(),
    );
    files
}

#[test]
fn historical_public_chain_uses_real_compiled_roots_and_is_refused_at_current_time() {
    let plan = plan();
    plan.validate().unwrap();
    assert_eq!(
        plan.0.certificate_admission["trust_class"],
        "production_public"
    );
    assert_eq!(
        plan.0.certificate_admission["trust_store"],
        "mozilla_webpki_roots"
    );
    assert_eq!(
        plan.0.certificate_admission["revocation_status"],
        "not_checked"
    );
    assert!(
        plan.validate_current_certificate().is_err(),
        "historical fixture is expired, not live admission"
    );
    let bytes = plan.to_bytes().unwrap();
    assert_eq!(
        PublicIngressPlan::parse_authenticated(&bytes, &hash(&bytes)).unwrap(),
        plan
    );
}

#[test]
fn selected_chain_remains_valid_through_last_hour_while_new_admission_requires_margin() {
    let plan = plan();
    let metadata = metadata(&plan, true);
    let expiry = plan.certificate_admission()["not_after"].as_u64().unwrap();
    plan.validate_certificate_at(expiry - 3600).unwrap();
    assert!(plan.validate_certificate_at(expiry - 3599).is_err());
    for observed in [expiry - 3599, expiry - 1] {
        let selected = metadata
            .validate_selected_at(plan.fullchain_pem().as_bytes(), observed)
            .unwrap();
        assert_eq!(selected.metadata()["minimum_remaining_seconds"], 0);
        assert_eq!(
            plan.certificate_admission()["minimum_remaining_seconds"],
            3600
        );
    }
    assert!(metadata
        .validate_selected_at(plan.fullchain_pem().as_bytes(), expiry)
        .is_err());
    let mut changed = metadata.clone();
    changed.certificate_admission["leaf_der_sha256"] = json!("e".repeat(64));
    assert!(changed
        .validate_selected_at(plan.fullchain_pem().as_bytes(), expiry - 1)
        .is_err());
}

#[test]
fn public_plan_identity_preserves_independently_configured_origin_ports() {
    // Identity extraction is tested separately from this DNS-only historical
    // certificate's SAN admission. No IP certificate is manufactured here.
    let mut plan = plan();
    plan.0.canonical_origin = format!("https://{DNS}:9443");
    plan.0.public_entry_origin = Some("https://203.0.113.10:8443".into());
    let identity = plan.ingress_identity().unwrap();
    assert_eq!(identity.dns_names(), vec![DNS]);
    assert_eq!(identity.ip_addresses(), vec!["203.0.113.10"]);
    assert!(plan.validate().is_err(), "fixture has no IP SAN");
    for alias in [
        "http://203.0.113.10:8443",
        "https://127.0.0.1:8443",
        "https://alias.example.com",
        "https://203.0.113.10:0443",
        "https://203.0.113.10/path",
        "https://0.0.0.0",
    ] {
        plan.0.public_entry_origin = Some(alias.into());
        assert!(plan.ingress_identity().is_err(), "{alias}");
    }
    plan.0.canonical_origin = "https://localhost:9443".into();
    plan.0.public_entry_origin = None;
    assert!(plan.ingress_identity().is_err());
}

#[test]
fn public_helper_requires_exact_plan_mount_and_digest_before_job_creation() {
    let source = Path::new("/private/installation/evidence/generation-public-ingress-plan.json");
    let digest = "a".repeat(64);
    let service = json!({
        "environment": { PLAN_DIGEST_ENV: digest },
        "volumes": [{"type":"bind", "source":source, "target":PLAN_INPUT,
            "read_only":true, "bind":{"create_host_path":false}}],
    });
    require_job_model(&service, source, &digest).unwrap();
    for (field, value) in [
        ("type", json!("volume")),
        ("source", json!("/another/plan.json")),
        ("target", json!("/input/other.json")),
        ("read_only", json!(false)),
        ("bind", json!({"create_host_path":true})),
    ] {
        let mut wrong = service.clone();
        wrong["volumes"][0][field] = value;
        assert!(
            require_job_model(&wrong, source, &digest).is_err(),
            "{field}"
        );
    }
    for target in [
        "/",
        "/input",
        PLAN_INPUT,
        "/input/public-ingress-plan.json/child",
    ] {
        let mut wrong = service.clone();
        wrong["volumes"]
            .as_array_mut()
            .unwrap()
            .push(json!({"type":"tmpfs","target":target}));
        assert!(
            require_job_model(&wrong, source, &digest).is_err(),
            "{target}"
        );
    }
    for kind in ["secrets", "configs"] {
        let mut wrong = service.clone();
        wrong[kind] = json!([{"source":"shadow", "target":PLAN_INPUT}]);
        assert!(require_job_model(&wrong, source, &digest).is_err());
    }
    let mut wrong = service.clone();
    wrong["tmpfs"] = json!(["/input:rw"]);
    assert!(require_job_model(&wrong, source, &digest).is_err());
    let mut wrong = service.clone();
    wrong["environment"][PLAN_DIGEST_ENV] = json!("b".repeat(64));
    assert!(require_job_model(&wrong, source, &digest).is_err());
    let mut wrong = service;
    wrong["volumes"] = json!([]);
    assert!(require_job_model(&wrong, source, &digest).is_err());
}

#[test]
fn native_public_receipts_bind_plan_inventory_and_unchanged_certificate() {
    use crate::installer_generation::{hashes, validate_records, GenerationProof};
    let (plan, initial) = fixture();
    let identity = [
        "renewal-role-id",
        "renewal-secret-id",
        "renewal-leaf-policies.json",
    ]
    .into_iter()
    .map(|name| (name.into(), format!("fixture-{name}").into_bytes()))
    .collect();
    let keycloak = serde_json::to_vec(&json!({
        "schema":"elevenid.installer-keycloak/v2", "installation_id":OWNER,
        "engine_id":"engine", "container_id":"a".repeat(64),
        "container_name":format!("marty-install-{}-installer-keycloak-1", OWNER.replace('-',"")),
        "network_id":"b".repeat(64),
        "image":format!("ghcr.io/elevenid/marty-ui-oss/openbao-didcomm@sha256:{}", "c".repeat(64)),
        "nonce":"0123456789ab", "outputs":crate::installer_keycloak_bridge::OUTPUTS,
        "container_removed":false, "job_completed_successfully":true,
        "compose_receipt_sha256":"d".repeat(64), "installation_ready":false,
    }))
    .unwrap();
    for reused in [false, true] {
        let before = if reused {
            current(&plan)
        } else {
            initial.clone()
        };
        let mut after = current(&plan);
        for (name, value) in &mut after {
            if name == "workload_identity_ca_cert" || name == PUBLIC_OUTPUTS[0] {
                continue;
            }
            if name.ends_with("_token") {
                *value = format!("changed-fixture-token-{name}").into_bytes();
            } else {
                // Workload validation here checks its receipt and mutation;
                // the public ingress chain is validated cryptographically.
                value.push(b'\n');
            }
        }
        let proof = GenerationProof {
            owner: OWNER,
            current: &before,
            identity: &identity,
            keycloak_receipt: &keycloak,
            public_ingress_plan: Some(&plan),
        };
        let plan_hash = plan.sha256().unwrap();
        let records: BTreeMap<String, Vec<u8>> = [
            ("pending.json", json!({"schema":"elevenid.installer-generation-intent/v3",
                "installation_id":OWNER,"nonce":"0123456789ab","input_sha256":hashes(&before),
                "identity_sha256":hashes(&identity),"keycloak_receipt_sha256":hash(&keycloak),
                "root_retired":false,"activated":false,"public_ingress_plan_sha256":plan_hash})),
            ("validated.json", json!({"schema":"elevenid.installer-generation-validation/v3",
                "installation_id":OWNER,"output_sha256":hashes(&after),"orphan_tokens":22,
                "remote_key_version":1,"ca_changed":false,"public_ingress":metadata(&plan,reused),
                "public_ingress_plan_sha256":plan_hash})),
            ("completed.json", json!({"schema":"elevenid.installer-generation-result/v3",
                "installation_id":OWNER,"files":42,"changed_files":if reused {40} else {41},
                "orphan_tokens":22,"transient_revoked":true,"activated":false,"root_retired":false,
                "ingress_renewal":true,"installation_ready":false,"public_ingress_plan_sha256":plan_hash})),
        ].into_iter().map(|(name,value)| (name.into(),serde_json::to_vec(&value).unwrap())).collect();
        assert_eq!(
            validate_records(&records, &after, &proof).unwrap(),
            hashes(&after)
        );
        for (record, field, value) in [
            (
                "pending.json",
                "public_ingress_plan_sha256",
                json!("f".repeat(64)),
            ),
            ("validated.json", "public_ingress_plan_sha256", json!(null)),
            (
                "completed.json",
                "public_ingress_plan_sha256",
                json!("f".repeat(64)),
            ),
            ("completed.json", "files", json!(43)),
            (
                "completed.json",
                "changed_files",
                json!(if reused { 41 } else { 40 }),
            ),
            ("completed.json", "activated", json!(true)),
            ("completed.json", "installation_ready", json!(true)),
            ("validated.json", "ingress", json!({})),
        ] {
            let mut bad = records.clone();
            let mut receipt: Value = serde_json::from_slice(&bad[record]).unwrap();
            receipt[field] = value;
            bad.insert(record.into(), serde_json::to_vec(&receipt).unwrap());
            assert!(
                validate_records(&bad, &after, &proof).is_err(),
                "{record}:{field}"
            );
        }
        let mut bad = after.clone();
        bad.insert(
            "installer_ingress_ca_cert".into(),
            INTERMEDIATE.as_bytes().to_vec(),
        );
        assert!(validate_records(&records, &bad, &proof).is_err());
    }
}

#[test]
fn public_plan_rejects_staging_wrong_identity_key_version_and_unauthenticated_input() {
    let plan = plan();
    let bytes = plan.to_bytes().unwrap();
    assert!(PublicIngressPlan::parse_authenticated(&bytes, &"e".repeat(64)).is_err());
    for (field, value) in [
        ("environment", serde_json::json!("staging")),
        (
            "canonical_origin",
            serde_json::json!("https://another.example.com"),
        ),
        (
            "public_entry_origin",
            serde_json::json!("https://203.0.113.7"),
        ),
        ("key_version", serde_json::json!(2)),
        ("installation_id", serde_json::json!(OWNER.to_uppercase())),
        ("key_name", serde_json::json!("foreign")),
        ("unknown", serde_json::json!(true)),
    ] {
        let mut bad = serde_json::to_value(&plan).unwrap();
        bad[field] = value;
        let bytes = serde_json::to_vec(&bad).unwrap();
        assert!(
            PublicIngressPlan::parse_authenticated(&bytes, &hash(&bytes)).is_err(),
            "{field}"
        );
    }
    let duplicate = String::from_utf8(bytes)
        .unwrap()
        .replacen("{", "{\"key_version\":1,", 1);
    assert!(PublicIngressPlan::parse_authenticated(
        duplicate.as_bytes(),
        &hash(duplicate.as_bytes())
    )
    .is_err());
}

#[test]
fn carried_public_generation_reuses_exact_chain_and_requires_a_changed_scoped_token() {
    let plan = plan();
    let before = current(&plan);
    let mut after = before.clone();
    after.insert(
        PUBLIC_OUTPUTS[1].into(),
        b"new-private-fixture-ingress-token".to_vec(),
    );
    let evidence = metadata(&plan, true);
    validate_recorded_replacement(OWNER, &before, &after, &evidence, &plan).unwrap();
    assert!(validate_recorded_replacement(OWNER, &before, &before, &evidence, &plan).is_err());
    let mut wrong = after.clone();
    wrong.get_mut(PUBLIC_OUTPUTS[0]).unwrap().push(b'\n');
    assert!(validate_recorded_replacement(OWNER, &before, &wrong, &evidence, &plan).is_err());
    wrong = after.clone();
    wrong.insert(ingress::OUTPUTS[0].into(), INTERMEDIATE.as_bytes().to_vec());
    assert!(validate_recorded_replacement(OWNER, &before, &wrong, &evidence, &plan).is_err());
    let mut wrong = evidence.clone();
    wrong.certificate_reused = false;
    assert!(validate_recorded_replacement(OWNER, &before, &after, &wrong, &plan).is_err());
    wrong = evidence;
    wrong.token_observed_at = 1_740_562_200;
    assert!(validate_recorded_replacement(OWNER, &before, &after, &wrong, &plan).is_err());
}

#[test]
fn initial_public_generation_preserves_private_ca_checks_and_omits_it_from_outputs() {
    let (plan, before) = fixture();
    let mut after = current(&plan);
    after.insert(
        PUBLIC_OUTPUTS[1].into(),
        b"new-private-fixture-ingress-token".to_vec(),
    );
    let evidence = metadata(&plan, false);
    validate_recorded_replacement(OWNER, &before, &after, &evidence, &plan).unwrap();
    let mut wrong = before.clone();
    wrong.insert(ingress::OUTPUTS[0].into(), INTERMEDIATE.as_bytes().to_vec());
    assert!(validate_recorded_replacement(OWNER, &wrong, &after, &evidence, &plan).is_err());
    assert_eq!(after.len(), 42);
    assert!(!after.contains_key(ingress::OUTPUTS[0]));
}

#[test]
fn historical_enrollment_preserves_original_workload_key_and_issuer_after_expiry() {
    let (_, before) = fixture();
    let ca = &before["installer_ingress_ca_cert"];
    let leaf = &before["installer_ingress_tls_cert"];
    assert!(
        crate::operator_certificates::check_chain(leaf, ca).is_err(),
        "old test leaf is expired now"
    );
    // This is only the historical continuity sub-check. The connected enrolled
    // replacement path separately validates every new token and leaf live.
    crate::activation_preflight::retained_enrolled_leaf(leaf, leaf, ca, OBSERVED).unwrap();
    assert!(crate::activation_preflight::retained_enrolled_leaf(leaf, ca, ca, OBSERVED).is_err());
    assert!(crate::activation_preflight::retained_enrolled_leaf(
        leaf,
        leaf,
        INTERMEDIATE.as_bytes(),
        OBSERVED
    )
    .is_err());
    assert!(crate::activation_preflight::retained_enrolled_leaf(
        leaf,
        leaf,
        ca,
        OBSERVED + 48 * 3600
    )
    .is_err());
}
