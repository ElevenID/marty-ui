use super::*;
use crate::installer_generation::{self as producer, GenerationProof};
use ring::{
    rand::SystemRandom,
    signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING},
};
use serde_json::json;
use spki::{
    der::{asn1::BitString, DecodePem},
    AlgorithmIdentifierOwned, ObjectIdentifier,
};
use std::{
    str::FromStr,
    time::{Duration, UNIX_EPOCH},
};
use x509_cert::{
    ext::{
        pkix::{BasicConstraints, KeyUsage, KeyUsages},
        AsExtension,
    },
    name::Name,
    serial_number::SerialNumber,
    Certificate,
};

pub(crate) const OWNER: &str = "6d72c0ec-ef7d-4b90-90d5-81dc9e296a97";
const DNS: &str = "helloworld.letsencrypt.org";
pub(crate) const OBSERVED: u64 = 1_739_989_800;
pub(crate) const REPLACED: u64 = OBSERVED + 9 * 3600;
const LEAF: &[u8] = include_bytes!("../../../../tests/fixtures/acme/le-first-shortlived-leaf.pem");

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

fn pem(certificate: &Certificate) -> String {
    certificate.to_pem(spki::der::pem::LineEnding::LF).unwrap()
}

fn metadata(ca: &Certificate, leaf: &Certificate, at: u64) -> IngressMetadata {
    IngressMetadata {
        schema: "elevenid.installer-ingress/v2".into(),
        installation_id: OWNER.into(),
        key_name: ingress::resource_name(OWNER).unwrap(),
        key_version: 1,
        pki_mount: ingress::resource_name(OWNER).unwrap(),
        dns_names: vec![DNS.into()],
        ip_addresses: vec![],
        ca_der_sha256: hash(&ca.to_der().unwrap()),
        certificate_der_sha256: hash(&leaf.to_der().unwrap()),
        ca_pem_sha256: hash(pem(ca).as_bytes()),
        certificate_pem_sha256: hash(pem(leaf).as_bytes()),
        ca_expires_at: ca
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs(),
        certificate_expires_at: leaf
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs(),
        token_ttl_seconds: 28800,
        token_observed_at: at,
        trust_installed: false,
        installation_ready: false,
    }
}

pub(crate) struct Fixture {
    pub(crate) plan: ManagedRenewalPlan,
    pub(crate) current: BTreeMap<String, Vec<u8>>,
    pub(crate) identity: BTreeMap<String, Vec<u8>>,
    pub(crate) receipt: Vec<u8>,
    pub(crate) next: BTreeMap<String, Vec<u8>>,
    pub(crate) next_metadata: IngressMetadata,
    pub(crate) previous_leaf: Vec<u8>,
}

impl Fixture {
    pub(crate) fn new() -> Self {
        // Only the disposable test issuer is generated. Both ingress leaves
        // retain an existing public fixture SPKI; its private key is absent.
        let random = SystemRandom::new();
        let secret =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random).unwrap();
        let issuer_key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, secret.as_ref(), &random)
                .unwrap();
        let mut ca = Certificate::from_pem(include_bytes!(
            "../../../../tests/fixtures/selfhost_ca_issuer_public.pem"
        ))
        .unwrap();
        ca.tbs_certificate.subject =
            Name::from_str(&format!("CN=Marty local CA {}", OWNER.replace('-', ""))).unwrap();
        ca.tbs_certificate.issuer = ca.tbs_certificate.subject.clone();
        ca.tbs_certificate
            .subject_public_key_info
            .subject_public_key = BitString::from_bytes(issuer_key.public_key().as_ref()).unwrap();
        ca.tbs_certificate.validity.not_before = (UNIX_EPOCH + Duration::from_secs(OBSERVED - 60))
            .try_into()
            .unwrap();
        ca.tbs_certificate.validity.not_after = (UNIX_EPOCH
            + Duration::from_secs(OBSERVED + 7 * 86400))
        .try_into()
        .unwrap();
        ca.tbs_certificate.extensions = Some(vec![
            BasicConstraints {
                ca: true,
                path_len_constraint: None,
            }
            .to_extension(&ca.tbs_certificate.subject, &[])
            .unwrap(),
            KeyUsage(KeyUsages::KeyCertSign.into())
                .to_extension(&ca.tbs_certificate.subject, &[])
                .unwrap(),
        ]);
        let ca = sign(ca, &issuer_key);
        let leaf_at = |at, serial| {
            let mut leaf = Certificate::from_pem(LEAF).unwrap();
            leaf.tbs_certificate.subject = Name::from_str(&format!("CN={DNS}")).unwrap();
            leaf.tbs_certificate.issuer = ca.tbs_certificate.subject.clone();
            leaf.tbs_certificate.serial_number = SerialNumber::new(&[serial]).unwrap();
            leaf.tbs_certificate.validity.not_before = (UNIX_EPOCH + Duration::from_secs(at - 60))
                .try_into()
                .unwrap();
            leaf.tbs_certificate.validity.not_after = (UNIX_EPOCH
                + Duration::from_secs(at + 8 * 3600))
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
            sign(leaf, &issuer_key)
        };
        let leaf = leaf_at(OBSERVED, 1);
        let next_leaf = leaf_at(REPLACED, 2);
        let previous_leaf = leaf_at(OBSERVED - 1, 3);
        // Non-ingress values exercise exact source/receipt accounting here;
        // live workload custody and credential TTL remain producer checks.
        let mut current: BTreeMap<_, _> = installer_renewal_bootstrap::current_inputs()
            .into_iter()
            .map(|name| {
                let bytes = if name.ends_with("_token") {
                    format!("old-synthetic-credential-{name}").into_bytes()
                } else {
                    LEAF.to_vec()
                };
                (name, bytes)
            })
            .collect();
        current.insert(ingress::OUTPUTS[0].into(), pem(&ca).into_bytes());
        current.insert(ingress::OUTPUTS[1].into(), pem(&leaf).into_bytes());
        current.insert(
            ingress::OUTPUTS[2].into(),
            b"old-synthetic-ingress-credential".to_vec(),
        );
        let mut next = current.clone();
        for (name, bytes) in &mut next {
            if name == "workload_identity_ca_cert" || name == ingress::OUTPUTS[0] {
                continue;
            }
            if name.ends_with("_token") {
                *bytes = format!("new-synthetic-credential-{name}").into_bytes();
            } else {
                bytes.push(b'\n');
            }
        }
        next.insert(ingress::OUTPUTS[1].into(), pem(&next_leaf).into_bytes());
        let mut policies: Vec<_> = (0..21)
            .map(|n| format!("workload-fixture-{n:02}"))
            .collect();
        policies.push(ingress::resource_name(OWNER).unwrap());
        policies.sort();
        let identity = BTreeMap::from([
            (
                IDENTITY[0].into(),
                b"11111111-1111-4111-8111-111111111111\n".to_vec(),
            ),
            (
                IDENTITY[1].into(),
                b"22222222-2222-4222-8222-222222222222\n".to_vec(),
            ),
            (IDENTITY[2].into(), serde_json::to_vec(&policies).unwrap()),
        ]);
        let receipt = serde_json::to_vec(&json!({"schema":"elevenid.installer-keycloak/v2","installation_id":OWNER,
            "engine_id":"engine-identity-123","container_id":"a".repeat(64),
            "container_name":format!("marty-install-{}-installer-keycloak-1",OWNER.replace('-',"")),
            "network_id":"b".repeat(64),"image":format!("ghcr.io/elevenid/marty-ui-oss/openbao-didcomm@sha256:{}","c".repeat(64)),
            "nonce":"0123456789ab","outputs":crate::installer_keycloak_bridge::OUTPUTS,
            "container_removed":false,"job_completed_successfully":true,"compose_receipt_sha256":"d".repeat(64),"installation_ready":false})).unwrap();
        let plan = ManagedRenewalPlan(PlanData {
            schema: SCHEMA.into(),
            certificate_source: CertificateSource::ManagedCa,
            installation_id: OWNER.into(),
            engine_id: "engine-identity-123".into(),
            initial_configuration_sha256: "1".repeat(64),
            hosting_selection_sha256: Some("2".repeat(64)),
            hosting_source_sha256: "3".repeat(64),
            canonical_origin: format!("https://{DNS}:18443"),
            public_entry_origin: None,
            sequence: 1,
            attempt: 0,
            parent_attempt: 0,
            parent_binding_sha256: "4".repeat(64),
            renewal_enrolment_receipt_sha256: "5".repeat(64),
            original_generation_intent_sha256: "6".repeat(64),
            identity_sha256: producer::hashes(&identity),
            leaf_policies: policies,
            input_sha256: producer::hashes(&current),
            input_observed_at: OBSERVED,
            ingress: metadata(&ca, &leaf, OBSERVED),
            ingress_ca_pem: pem(&ca),
            ingress_leaf_pem: pem(&leaf),
            ingress_spki_sha256: hash(
                &leaf
                    .tbs_certificate
                    .subject_public_key_info
                    .to_der()
                    .unwrap(),
            ),
            keycloak_receipt_sha256: hash(&receipt),
        });
        plan.validate().unwrap();
        Self {
            plan,
            current,
            identity,
            receipt,
            next,
            next_metadata: metadata(&ca, &next_leaf, REPLACED),
            previous_leaf: pem(&previous_leaf).into_bytes(),
        }
    }
    fn proof(&self) -> GenerationProof<'_> {
        GenerationProof {
            owner: OWNER,
            current: &self.current,
            identity: &self.identity,
            keycloak_receipt: &self.receipt,
            public_ingress_plan: None,
        }
    }
    fn records(&self) -> BTreeMap<String, Vec<u8>> {
        let digest = self.plan.sha256().unwrap();
        [
            ("pending.json", json!({"schema":"elevenid.installer-generation-intent/v4","installation_id":OWNER,
                "nonce":"0123456789ab","input_sha256":producer::hashes(&self.current),"identity_sha256":producer::hashes(&self.identity),
                "keycloak_receipt_sha256":hash(&self.receipt),"root_retired":false,"activated":false,"managed_renewal_plan_sha256":digest})),
            ("validated.json", json!({"schema":"elevenid.installer-generation-validation/v4","installation_id":OWNER,
                "output_sha256":producer::hashes(&self.next),"orphan_tokens":22,"remote_key_version":1,"ca_changed":false,
                "ingress":self.next_metadata,"managed_renewal_plan_sha256":digest})),
            ("completed.json", json!({"schema":"elevenid.installer-generation-result/v4","installation_id":OWNER,
                "files":43,"changed_files":41,"orphan_tokens":22,"transient_revoked":true,"activated":false,"root_retired":false,
                "ingress_renewal":true,"installation_ready":false,"managed_renewal_plan_sha256":digest})),
        ].into_iter().map(|(name, value)| (name.into(), serde_json::to_vec(&value).unwrap())).collect()
    }
}

#[test]
fn managed_plan_authenticates_exact_source_and_historical_expired_leaf() {
    let fixture = Fixture::new();
    let plan = &fixture.plan;
    assert!(plan.0.ingress.certificate_expires_at < REPLACED);
    assert!(plan.input_observed_at() + plan.0.ingress.token_ttl_seconds < REPLACED);
    let bytes = plan.to_bytes().unwrap();
    assert_eq!(
        ManagedRenewalPlan::parse_authenticated(&bytes, &hash(&bytes)).unwrap(),
        *plan
    );
    plan.require_snapshot(OWNER, &fixture.current, &fixture.identity, &fixture.receipt)
        .unwrap();
    assert_eq!(plan.workload_policies().len(), 21);
    assert!(!plan.workload_policies().contains(&plan.0.ingress.key_name));
    assert!(ManagedRenewalPlan::parse_authenticated(&bytes, &"a".repeat(64)).is_err());
    let mut changed_bytes = bytes.clone();
    changed_bytes.push(b'\n');
    assert!(
        ManagedRenewalPlan::parse_authenticated(&changed_bytes, &hash(&changed_bytes)).is_err()
    );
    for source in [CertificateSource::Acme, CertificateSource::FoundationImport] {
        let mut other = plan.clone();
        other.0.certificate_source = source;
        assert!(other.to_bytes().is_err());
    }
}

#[test]
fn source_custody_and_observation_cannot_be_replaced_or_freshened() {
    let fixture = Fixture::new();
    let plan = &fixture.plan;
    for field in [
        "key_version",
        "token_observed_at",
        "dns_names",
        "trust_installed",
        "installation_ready",
    ] {
        let mut value = serde_json::to_value(&plan.0).unwrap();
        value["ingress"][field] = match field {
            "key_version" => json!(2),
            "token_observed_at" => json!(REPLACED),
            "dns_names" => json!(["foreign.example"]),
            _ => json!(true),
        };
        let changed = ManagedRenewalPlan(serde_json::from_value(value).unwrap());
        assert!(changed.to_bytes().is_err(), "accepted {field}");
    }
    let mut freshened = plan.clone();
    freshened.0.input_observed_at = REPLACED;
    freshened.0.ingress.token_observed_at = REPLACED;
    assert!(freshened.to_bytes().is_err());
    let mut changed = plan.clone();
    changed.0.ingress_spki_sha256 = "f".repeat(64);
    assert!(changed.to_bytes().is_err());
    let mut missing = fixture.current.clone();
    missing.remove(ingress::OUTPUTS[0]);
    assert!(plan
        .require_snapshot(OWNER, &missing, &fixture.identity, &fixture.receipt)
        .is_err());
    let mut wrong_identity = fixture.identity.clone();
    wrong_identity.get_mut(IDENTITY[1]).unwrap().push(b'x');
    assert!(plan
        .require_snapshot(OWNER, &fixture.current, &wrong_identity, &fixture.receipt)
        .is_err());
    let mut wrong_source = fixture.current.clone();
    let name = wrong_source
        .keys()
        .find(|name| name.ends_with("_token"))
        .unwrap()
        .clone();
    wrong_source.get_mut(&name).unwrap().push(b'x');
    assert!(plan
        .require_snapshot(OWNER, &wrong_source, &fixture.identity, &fixture.receipt)
        .is_err());
    assert!(plan
        .require_snapshot(
            "00000000-0000-4000-8000-000000000000",
            &fixture.current,
            &fixture.identity,
            &fixture.receipt
        )
        .is_err());
}

#[test]
fn managed_generation_receipts_are_distinct_and_preserve_expired_source_identity() {
    let fixture = Fixture::new();
    let records = fixture.records();
    assert_eq!(
        producer::validate_managed_records(
            &records,
            &fixture.next,
            &fixture.proof(),
            &fixture.plan
        )
        .unwrap(),
        producer::hashes(&fixture.next)
    );
    assert!(producer::validate_records(&records, &fixture.next, &fixture.proof()).is_err());
    for (name, field, value) in [
        (
            "pending.json",
            "managed_renewal_plan_sha256",
            json!("f".repeat(64)),
        ),
        (
            "pending.json",
            "public_ingress_plan_sha256",
            json!("f".repeat(64)),
        ),
        ("validated.json", "remote_key_version", json!(2)),
        ("validated.json", "orphan_tokens", json!(21)),
        ("completed.json", "transient_revoked", json!(false)),
        ("completed.json", "installation_ready", json!(true)),
        ("completed.json", "activated", json!(true)),
        ("completed.json", "files", json!(42)),
    ] {
        let mut changed = records.clone();
        let mut record: Value = serde_json::from_slice(&changed[name]).unwrap();
        record[field] = value;
        changed.insert(name.into(), serde_json::to_vec(&record).unwrap());
        assert!(
            producer::validate_managed_records(
                &changed,
                &fixture.next,
                &fixture.proof(),
                &fixture.plan
            )
            .is_err(),
            "accepted {name}/{field}"
        );
    }
    let mut incomplete = records.clone();
    incomplete.remove("completed.json");
    assert!(producer::validate_managed_records(
        &incomplete,
        &fixture.next,
        &fixture.proof(),
        &fixture.plan
    )
    .is_err());
    assert!(producer::validate_managed_records(
        &records,
        &fixture.current,
        &fixture.proof(),
        &fixture.plan
    )
    .is_err());
    let public_plan = crate::installer_public_ingress::tests::plan();
    let mut cross_source = fixture.proof();
    cross_source.public_ingress_plan = Some(&public_plan);
    assert!(producer::validate_managed_records(
        &records,
        &fixture.next,
        &cross_source,
        &fixture.plan
    )
    .is_err());
}

#[test]
fn expired_private_leaf_does_not_authorize_issuer_expiry_or_rotation() {
    let fixture = Fixture::new();
    let plan = &fixture.plan;
    let leaf = ingress::certificate(&plan.0.ingress_leaf_pem).unwrap();
    let public = leaf
        .tbs_certificate
        .subject_public_key_info
        .to_pem(spki::der::pem::LineEnding::LF)
        .unwrap();
    let identity = plan.ingress_identity().unwrap();
    ingress::validate_retained_private_identity_at(
        &plan.0.ingress_ca_pem,
        &plan.0.ingress_leaf_pem,
        &public,
        &plan.0.ingress.key_name,
        &identity,
        REPLACED,
    )
    .unwrap();
    assert!(ingress::validate_retained_private_identity_at(
        &plan.0.ingress_ca_pem,
        &plan.0.ingress_leaf_pem,
        &public,
        &plan.0.ingress.key_name,
        &identity,
        plan.0.ingress.ca_expires_at - 3600
    )
    .is_err());
    let other = Fixture::new();
    assert!(ingress::validate_retained_private_identity_at(
        &other.plan.0.ingress_ca_pem,
        &plan.0.ingress_leaf_pem,
        &public,
        &plan.0.ingress.key_name,
        &identity,
        REPLACED
    )
    .is_err());
}

#[test]
fn managed_identity_preserves_local_default_and_independent_alias_ports() {
    assert_eq!(
        identity_from_origins("https://localhost:18443", None).unwrap(),
        IngressIdentity::localhost()
    );
    assert_eq!(
        identity_from_origins(
            "https://marty.example:9443",
            Some("https://192.0.2.10:18443")
        )
        .unwrap(),
        IngressIdentity::new(Some("marty.example"), Some("192.0.2.10".parse().unwrap())).unwrap()
    );
    for (canonical, alias) in [
        ("https://MARTY.example:9443", None),
        ("https://marty.example", Some("https://192.0.2.10:443")),
        ("https://marty.example", Some("https://127.0.0.1")),
        ("https://marty.example", Some("https://other.example")),
        ("https://localhost", Some("https://192.0.2.10")),
    ] {
        assert!(
            identity_from_origins(canonical, alias).is_err(),
            "accepted {canonical} / {alias:?}"
        );
    }
}

#[test]
fn managed_fixed_job_refuses_competing_public_plan_and_any_plan_shadow() {
    let source = Path::new(
        "/installation/evidence/generation-00000000000000000001-managed-renewal-plan.json",
    );
    let digest = "a".repeat(64);
    let service = json!({"environment":{PLAN_DIGEST_ENV:digest},"volumes":[
        {"type":"bind","source":source,"target":PLAN_INPUT,"read_only":true,"bind":{"create_host_path":false}},
        {"type":"bind","source":"/installation/current","target":"/input/current","read_only":true,"bind":{"create_host_path":false}}
    ]});
    require_job_model(&service, source, &digest).unwrap();
    for field in [
        crate::installer_public_ingress::PLAN_DIGEST_ENV,
        crate::installer_public_ingress::AUTHORITY_PLAN_DIGEST_ENV,
    ] {
        let mut changed = service.clone();
        changed["environment"][field] = json!("b".repeat(64));
        assert!(require_job_model(&changed, source, &digest).is_err());
    }
    for target in [
        "/input",
        PLAN_INPUT,
        "/input/managed-renewal-plan.json/child",
        crate::installer_public_ingress::PLAN_INPUT,
        crate::installer_public_ingress::AUTHORITY_PLAN_INPUT,
    ] {
        for kind in ["volumes", "tmpfs", "configs", "secrets"] {
            let mut changed = service.clone();
            let mount = match kind {
                "tmpfs" => json!(target),
                "volumes" => {
                    json!({"type":"bind","source":"/other","target":target,"read_only":true,"bind":{"create_host_path":false}})
                }
                _ => json!({"source":"other","target":target}),
            };
            if kind == "volumes" {
                changed[kind].as_array_mut().unwrap().push(mount);
            } else {
                changed[kind] = json!([mount]);
            }
            assert!(
                require_job_model(&changed, source, &digest).is_err(),
                "accepted {kind}/{target}"
            );
        }
    }
    for field in ["read_only", "bind"] {
        let mut changed = service.clone();
        changed["volumes"][0][field] = json!(false);
        assert!(require_job_model(&changed, source, &digest).is_err());
    }
}
