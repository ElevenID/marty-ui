//! Native receipt observations are synthetic here. The fixture uses normal
//! fresh storage creation and real certificate signatures, and tests only the
//! read-only prepared boundary; it never claims actual Docker or CA execution.
use super::*;
use crate::installer_compose::{ContainerIdentity, SetupExecution};
use serde_json::json;
use std::{fs as files, os::unix::fs::PermissionsExt};

struct Boundary {
    _files: tempfile::TempDir,
    installation: PathBuf,
    state: InstallerState,
    acme: Option<crate::installer_acme::tests::Fixture>,
}
fn private_file(path: &Path, bytes: &[u8], mode: u32) {
    files::write(path, bytes).unwrap();
    files::set_permissions(path, files::Permissions::from_mode(mode)).unwrap();
}
fn initial_ingress_evidence(
    state: &mut InstallerState,
    installation: &Path,
    public_leaf: Option<&[u8]>,
) -> RetainedIngressKey {
    use ring::{
        rand::SystemRandom,
        signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING},
    };
    use spki::{
        der::{
            asn1::{BitString, Ia5String, OctetString},
            DecodePem,
        },
        AlgorithmIdentifierOwned, ObjectIdentifier,
    };
    use std::str::FromStr;
    use x509_cert::{
        ext::{
            pkix::{
                name::GeneralName, BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages,
                SubjectAltName,
            },
            AsExtension,
        },
        name::Name,
        Certificate,
    };
    let owner = state.journal().installation_id().to_string();
    let ip = state
        .with_inspection(installer_hosting::resolve)
        .unwrap()
        .certificate_ip_address();
    let identity =
        installer_ingress_provision::IngressIdentity::new(Some("login.example.com"), ip).unwrap();
    let name = installer_ingress_provision::resource_name(&owner).unwrap();
    let observed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let random = SystemRandom::new();
    let secret = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random).unwrap();
    let ca_key =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, secret.as_ref(), &random)
            .unwrap();
    let mut ca = Certificate::from_pem(include_bytes!(
        "../../../../tests/fixtures/selfhost_ca_issuer_public.pem"
    ))
    .unwrap();
    let mut leaf_spki = ca.tbs_certificate.subject_public_key_info.clone();
    if let Some(public) = public_leaf {
        leaf_spki.subject_public_key = BitString::from_bytes(public).unwrap();
    }
    ca.tbs_certificate.subject =
        Name::from_str(&format!("CN=Marty local CA {}", owner.replace('-', ""))).unwrap();
    ca.tbs_certificate.issuer = ca.tbs_certificate.subject.clone();
    ca.tbs_certificate
        .subject_public_key_info
        .subject_public_key = BitString::from_bytes(ca_key.public_key().as_ref()).unwrap();
    ca.tbs_certificate.validity.not_before = (UNIX_EPOCH + Duration::from_secs(observed - 60))
        .try_into()
        .unwrap();
    ca.tbs_certificate.validity.not_after = (UNIX_EPOCH + Duration::from_secs(observed + 86400))
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
    let mut leaf = ca.clone();
    leaf.tbs_certificate.subject = Name::from_str("CN=login.example.com").unwrap();
    leaf.tbs_certificate.subject_public_key_info = leaf_spki;
    leaf.tbs_certificate.validity.not_after = (UNIX_EPOCH + Duration::from_secs(observed + 28800))
        .try_into()
        .unwrap();
    let mut names = vec![GeneralName::DnsName(
        Ia5String::new("login.example.com").unwrap(),
    )];
    if let Some(ip) = ip {
        let bytes = match ip {
            std::net::IpAddr::V4(ip) => ip.octets().to_vec(),
            std::net::IpAddr::V6(ip) => ip.octets().to_vec(),
        };
        names.push(GeneralName::IpAddress(OctetString::new(bytes).unwrap()));
    }
    leaf.tbs_certificate.extensions = Some(vec![
        BasicConstraints {
            ca: false,
            path_len_constraint: None,
        }
        .to_extension(&leaf.tbs_certificate.subject, &[])
        .unwrap(),
        KeyUsage(KeyUsages::DigitalSignature.into())
            .to_extension(&leaf.tbs_certificate.subject, &[])
            .unwrap(),
        ExtendedKeyUsage(vec![ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1")])
            .to_extension(&leaf.tbs_certificate.subject, &[])
            .unwrap(),
        SubjectAltName(names)
            .to_extension(&leaf.tbs_certificate.subject, &[])
            .unwrap(),
    ]);
    let sign = |cert: &mut Certificate| {
        cert.signature_algorithm = AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"),
            parameters: None,
        };
        cert.tbs_certificate.signature = cert.signature_algorithm.clone();
        cert.signature = BitString::from_bytes(
            ca_key
                .sign(&random, &cert.tbs_certificate.to_der().unwrap())
                .unwrap()
                .as_ref(),
        )
        .unwrap();
    };
    sign(&mut ca);
    sign(&mut leaf);
    let ca_pem = ca.to_pem(LineEnding::LF).unwrap();
    let leaf_pem = leaf.to_pem(LineEnding::LF).unwrap();
    let key = RetainedIngressKey::from_recorded_public_key(
        &owner,
        1,
        &leaf
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .unwrap(),
    )
    .unwrap();
    let expiry = installer_ingress_provision::check_certificates_for(
        &ca_pem,
        &leaf_pem,
        &leaf
            .tbs_certificate
            .subject_public_key_info
            .to_pem(LineEnding::LF)
            .unwrap(),
        &name,
        observed,
        &identity,
    )
    .unwrap();
    let metadata = installer_ingress_outputs::IngressMetadata {
        schema: "elevenid.installer-ingress/v2".into(),
        installation_id: owner,
        key_name: name.clone(),
        pki_mount: name,
        key_version: 1,
        dns_names: identity.dns_names(),
        ip_addresses: identity.ip_addresses(),
        ca_der_sha256: sha(&ca.to_der().unwrap()),
        certificate_der_sha256: sha(&leaf.to_der().unwrap()),
        ca_pem_sha256: sha(ca_pem.as_bytes()),
        certificate_pem_sha256: sha(leaf_pem.as_bytes()),
        ca_expires_at: expiry.0,
        certificate_expires_at: expiry.1,
        token_ttl_seconds: 28800,
        token_observed_at: observed,
        trust_installed: false,
        installation_ready: false,
    };
    state
        .write_evidence("installer-ingress.json", &encode(&metadata).unwrap())
        .unwrap();
    for filename in crate::installer_renewal_bootstrap::managed_inputs() {
        let bytes = match filename.as_str() {
            "installer_ingress_ca_cert" => ca_pem.as_bytes().to_vec(),
            "installer_ingress_tls_cert" => leaf_pem.as_bytes().to_vec(),
            value if value.ends_with("_token") => {
                format!("synthetic-previous-token-{value}").into_bytes()
            }
            _ => ca_pem.as_bytes().to_vec(),
        };
        private_file(&installation.join("secrets").join(filename), &bytes, 0o444);
    }
    key
}
fn container(service: &str, image: &str, number: u8, setup: bool) -> ContainerIdentity {
    ContainerIdentity {
        id: format!("{number:02x}").repeat(32),
        service: service.into(),
        image: image.into(),
        config_hash: "f".repeat(64),
        setup,
        setup_execution: setup.then(|| SetupExecution {
            started_at: "2026-11-01T00:00:01Z".into(),
            finished_at: "2026-11-01T00:00:02Z".into(),
            completed_without_restart: true,
        }),
        health_required: false,
        cap_add: BTreeSet::new(),
        cap_drop: BTreeSet::new(),
        read_only: true,
        memory_limit: 134217728,
    }
}
fn receipt(
    inputs: &ComposeInputs,
    engine: &str,
    operation: &str,
    resources: ProjectResources,
) -> ComposeReceipt {
    let mut input_files = inputs
        .prior
        .as_ref()
        .map(|receipt| receipt.input_files.clone())
        .unwrap_or_default();
    input_files.extend(
        inputs
            .files
            .iter()
            .chain([&inputs.environment])
            .chain(&inputs.bound_inputs)
            .map(|file| (file.path.clone(), file.sha256.clone())),
    );
    ComposeReceipt {
        schema: "elevenid.installer-compose-operation/v1".into(),
        project: inputs.project.clone(),
        engine_id: engine.into(),
        operation: operation.into(),
        configuration_sha256: "e".repeat(64),
        input_files,
        command_succeeded: true,
        client_exit_code: Some(0),
        failure_class: None,
        observation_validated: true,
        status: resources
            .containers
            .iter()
            .map(|(service, container)| {
                json!({"Service":service,"ID":container.id,
            "State":if container.setup{"exited"}else{"running"},"ExitCode":0})
            })
            .collect(),
        resources: Some(resources),
        installation_ready: false,
    }
}

fn boundary_fixture() -> Boundary {
    boundary_fixture_with_staging(false)
}
fn boundary_fixture_with_staging(staging: bool) -> Boundary {
    assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "run this rootless boundary fixture as an ordinary nonroot identity"
    );
    let environment = if staging {
        AcmeEnvironment::Staging
    } else {
        AcmeEnvironment::Production
    };
    let mut hosting = json!({"schema":"elevenid.installation-hosting/v1","mode":"direct","public_origin":"https://login.example.com",
        "listener":{"bind_address":"0.0.0.0","port":8443},"tls":{"termination":"marty-keyless","certificate_source":"acme","http01_host_port":18080,
        "acme":{"environment":environment,"directory_url":environment.directory_url(),"profile":"shortlived",
            "terms_url":"https://letsencrypt.org/documents/LE-SA-v1.6-August-18-2025.pdf","terms_agreed":true}}});
    if staging {
        hosting["public_entry_origin"] = json!("https://203.0.113.7");
    }
    let runtime = RuntimeBinding {
        docker_host: format!("unix:///run/user/{}/docker.sock", unsafe {
            libc::geteuid()
        }),
        engine_id: "synthetic-rootless-engine".into(),
        openbao_port: 18200,
        profile: RuntimeProfile::Rootless,
    };
    let (files, installation, mut state) =
        crate::installer_acme_preparation::prepared_fixture(&hosting, runtime.clone());
    private_file(
        &installation.join("marty-deploy"),
        b"synthetic retained operator\n",
        0o700,
    );
    let operator_sha =
        crate::installer_verify::operator_digest(&installation.join("marty-deploy")).unwrap();
    let configuration = state
        .with_inspection(BoundAcmeConfiguration::from_selection)
        .unwrap();
    use ring::{
        rand::SystemRandom,
        signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING},
    };
    let test_leaf = staging.then(|| {
        let random = SystemRandom::new();
        let secret =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random).unwrap();
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, secret.as_ref(), &random).unwrap()
    });
    let ingress = initial_ingress_evidence(
        &mut state,
        &installation,
        test_leaf.as_ref().map(|key| key.public_key().as_ref()),
    );
    let acme = test_leaf.map(|leaf| {
        crate::installer_acme::tests::Fixture::attach_prepared(&mut state, &installation, leaf)
    });
    let authority = state
        .with_inspection(|view| {
            crate::installer_public_ingress::PublicRenewalAuthorityPlan::from_initial(
                view,
                &installation,
            )
        })
        .unwrap();
    let authority_path = authority
        .record_for_install(&installation, &mut state)
        .unwrap();
    let authority_sha = authority.sha256().unwrap();
    let bundle = installation.join("bundle");
    files::create_dir(&bundle).unwrap();
    files::set_permissions(&bundle, files::Permissions::from_mode(0o700)).unwrap();
    let layer = bundle.join(LAYER);
    files::create_dir_all(layer.parent().unwrap()).unwrap();
    let layer_bytes =
        include_bytes!("../../../../deploy-config/compose/selfhost-installer/compose.acme.yml");
    private_file(&layer, layer_bytes, 0o644);
    let image = format!(
        "ghcr.io/elevenid/marty-ui-oss/services@sha256:{}",
        "a".repeat(64)
    );
    let mut env = b"MARTY_INSTALLATION_ID='synthetic-fixture'\n".to_vec();
    for (key, value) in [
        (
            crate::installer_public_ingress::AUTHORITY_PLAN_DIGEST_ENV,
            authority_sha.clone(),
        ),
        (
            "MARTY_ACME_CANONICAL_ORIGIN",
            configuration.canonical_origin().into(),
        ),
        (
            "MARTY_ACME_PUBLIC_ENTRY_ORIGIN",
            configuration
                .public_entry_origin()
                .unwrap_or_default()
                .into(),
        ),
        ("MARTY_ACME_HTTP01_HOST_PORT", "18080".into()),
    ] {
        append(&mut env, key, &value).unwrap();
    }
    state.write_evidence(RENEWAL_ENVIRONMENT, &env).unwrap();
    let mut bootstrap = ComposeInputs {
        installation: installation.clone(),
        project: state.journal().compose_project(),
        files: vec![BoundFile {
            path: layer,
            sha256: sha(layer_bytes),
        }],
        bound_inputs: vec![BoundFile {
            path: authority_path,
            sha256: authority_sha.clone(),
        }],
        environment: BoundFile {
            path: installation.join("evidence").join(RENEWAL_ENVIRONMENT),
            sha256: sha(&env),
        },
        profiles: vec!["setup".into()],
        services: vec!["installer-renewal".into()],
        approved_images: BTreeSet::from([image.clone()]),
        #[cfg(feature = "installer-development")]
        development_image: None,
        writable_bind_roots: BTreeSet::new(),
        readonly_bind_roots: BTreeSet::new(),
        allowed_loopback_ports: BTreeSet::from([18200, 18080]),
        ingress_listener: Some(installer_hosting::Listener {
            bind_address: "0.0.0.0".parse().unwrap(),
            port: 8443,
        }),
        prior: None,
    };
    let infrastructure = OpenBaoInventory {
        installation_id: state.journal().installation_id().to_string(),
        engine_id: runtime.engine_id.clone(),
        project: bootstrap.project.clone(),
        image: format!(
            "ghcr.io/elevenid/marty-ui-oss/openbao@sha256:{}",
            "b".repeat(64)
        ),
        host_port: 18200,
        network_name: format!("{}_default", bootstrap.project),
        network_id: "c".repeat(64),
        container_ids: BTreeMap::new(),
        pending_receipt: installation.join("evidence/openbao-pending.json"),
    };
    let mut resources = ProjectResources::default();
    resources.networks.insert(
        infrastructure.network_name.clone(),
        infrastructure.network_id.clone(),
    );
    resources.containers.insert(
        "installer-renewal".into(),
        container("installer-renewal", &image, 1, true),
    );
    let prior = receipt(
        &bootstrap,
        &runtime.engine_id,
        "setup-installer-renewal",
        resources.clone(),
    );
    state
        .write_evidence(
            "compose-setup-installer-renewal-result.json",
            &encode(&prior).unwrap(),
        )
        .unwrap();
    let identities = [
        (
            "renewal-role-id",
            b"synthetic-retained-renewal-role-id".to_vec(),
        ),
        (
            "renewal-secret-id",
            b"synthetic-retained-renewal-secret-id".to_vec(),
        ),
        (
            "renewal-leaf-policies.json",
            encode(
                &((0..21)
                    .map(|i| format!("fixture-leaf-policy-{i}"))
                    .chain([ingress.transit_key_name().into()])
                    .collect::<Vec<_>>()),
            )
            .unwrap(),
        ),
    ];
    state.create_private_directory("renewal-transfer").unwrap();
    let delivered = installation.join("renewal-transfer/delivered");
    files::create_dir(&delivered).unwrap();
    files::set_permissions(&delivered, files::Permissions::from_mode(0o700)).unwrap();
    for (name, bytes) in &identities {
        private_file(&delivered.join(name), bytes, 0o600);
    }
    for (name, body) in [
        (
            "pending.json",
            json!({"schema":"elevenid.installer-renewal-bootstrap-intent/v3","installation_id":infrastructure.installation_id,
        "root_retired":false,"ingress_renewal":true,"public_renewal_authority_plan_sha256":authority_sha}),
        ),
        (
            "completed.json",
            json!({"schema":"elevenid.installer-renewal-bootstrap-result/v3","installation_id":infrastructure.installation_id,
            "identity_files":identities.iter().map(|(name,_)|name).collect::<Vec<_>>(),"policy_count":22,"scoped_login_verified":true,"verification_token_revoked":true,
            "root_retired":false,"ingress_renewal":true,"public_renewal_authority_plan_sha256":authority_sha}),
        ),
    ] {
        private_file(&delivered.join(name), &encode(&body).unwrap(), 0o600);
    }
    let renewal = crate::installer_renewal::RenewalReceipt {
        schema: "elevenid.installer-renewal-host/v4".into(),
        installation_id: infrastructure.installation_id.clone(),
        engine_id: runtime.engine_id.clone(),
        container_id: resources.containers["installer-renewal"].id.clone(),
        container_name: format!("{}-installer-renewal-1", bootstrap.project),
        network_id: infrastructure.network_id.clone(),
        image: image.clone(),
        root_retired: false,
        ingress_renewal: true,
        public_renewal_authority_plan_sha256: Some(authority_sha),
        public_identity_sha256: Some(
            identities
                .iter()
                .map(|(name, bytes)| (name.to_string(), sha(bytes)))
                .collect(),
        ),
        private_identity_validated: true,
        outputs: identities
            .iter()
            .map(|(name, _)| name.to_string())
            .collect(),
        compose_receipt_sha256: installer_jobs::receipt_digest(&prior).unwrap(),
        job_completed_successfully: true,
        container_removed: false,
        installation_ready: false,
    };
    for name in ["renewal-result.json", "renewal-observation.json"] {
        state
            .write_evidence(name, &encode(&renewal).unwrap())
            .unwrap();
    }
    bootstrap.prior = Some(prior.clone());
    let context = HostInputs {
        docker: Path::new("/unexecuted/docker"),
        installation: &installation,
        bundle: &bundle,
        infrastructure: &infrastructure,
        services_image: &image,
        operator_sha256: &operator_sha,
    };
    let base = augmented_inputs(&context, &state, &bootstrap, 18080).unwrap();
    let intent = Intent {
        schema: "elevenid.installer-acme-host-intent/v1".into(),
        installation_id: state.journal().installation_id(),
        configuration: value(&configuration).unwrap(),
        release: state.journal().identity().clone(),
        runtime: runtime.clone(),
        bootstrap: bootstrap.clone(),
        prior: prior.clone(),
        infrastructure: infrastructure.clone(),
        bundle,
        services_image: image.clone(),
        operator_sha256: operator_sha,
        ingress_key: PublicKey::new(&ingress),
        openbao_ca_pem_sha256: "d".repeat(64),
        server_cluster_id: uuid::Uuid::new_v4().to_string(),
        application_preparation_sha256: state
            .with_inspection(|view| {
                Ok(sha(&view.read_evidence(
                    crate::installer_acme_preparation::RECORD,
                )?))
            })
            .unwrap(),
        public_renewal_enrolment_sha256: state
            .with_inspection(|view| {
                require_public_renewal(view, &bootstrap, &infrastructure, &image)
            })
            .unwrap(),
        staging_roots_sha256: if staging {
            Some(
                state
                    .with_inspection(|view| Ok(sha(&view.read_evidence(STAGING_ROOTS)?)))
                    .unwrap(),
            )
        } else {
            None
        },
    };
    state
        .write_evidence(&name(environment, "intent"), &encode(&intent).unwrap())
        .unwrap();
    let projection = prepare_projection(&state, &installation).unwrap();
    let public_plan = b"{\"synthetic_public_plan\":true}";
    for plan in [CUSTODY_PLAN, CREDENTIAL_PLAN] {
        state.write_evidence(plan, public_plan).unwrap();
    }
    let mut previous = prior;
    for (phase, service, number) in [("custody", CUSTODY, 2), ("credentials", CREDENTIALS, 3)] {
        let inputs = phase_inputs(
            &mut state,
            &intent,
            &base,
            &configuration,
            phase,
            &sha(public_plan),
            (phase == "credentials")
                .then(|| sha(public_plan))
                .as_deref(),
            previous,
            service,
        )
        .unwrap();
        let identity = container(service, &image, number, true);
        resources
            .containers
            .insert(service.into(), identity.clone());
        let observed = receipt(
            &inputs,
            &runtime.engine_id,
            &format!("setup-{service}"),
            resources.clone(),
        );
        state
            .write_evidence(
                &format!("compose-setup-{service}-result.json"),
                &encode(&observed).unwrap(),
            )
            .unwrap();
        record_job(
            &mut state,
            environment,
            phase,
            service,
            &sha(public_plan),
            &installer_jobs::CompletedJob {
                compose: observed.clone(),
                container_id: identity.id,
                container_name: format!("{}-{service}-1", bootstrap.project),
                image: image.clone(),
            },
        )
        .unwrap();
        previous = observed;
    }
    let mut inputs = phase_inputs(
        &mut state,
        &intent,
        &base,
        &configuration,
        "responder",
        &sha(public_plan),
        Some(&sha(public_plan)),
        previous,
        RESPONDER,
    )
    .unwrap();
    resources
        .containers
        .insert(RESPONDER.into(), container(RESPONDER, &image, 4, false));
    let mut observed = receipt(&inputs, &runtime.engine_id, RESPONDER_OPERATION, resources);
    // Every prior input remains part of the cumulative native receipt.
    for file in inputs.prior.as_ref().unwrap().input_files.clone() {
        observed.input_files.insert(file.0, file.1);
    }
    state
        .write_evidence(
            &format!("compose-{RESPONDER_OPERATION}-result.json"),
            &encode(&observed).unwrap(),
        )
        .unwrap();
    inputs.prior = Some(observed.clone());
    if let Some(acme) = &acme {
        // The in-memory worker's real account binding must be the exact public
        // account retained by this otherwise synthetic native setup fixture.
        state
            .write_evidence(
                &format!("acme-custody-{}-result.json", environment.as_str()),
                &encode(&serde_json::json!({
                    "schema":"elevenid.installer-acme-custody-result/v1",
                    "account_key":acme.inputs().account_key.binding_metadata()
                }))
                .unwrap(),
            )
            .unwrap();
    }
    for filename in evidence_names(environment) {
        if state
            .with_inspection(|view| view.diagnostic_record(&filename, true))
            .unwrap()
            .is_none()
        {
            state
                .write_evidence(&filename, b"{\"synthetic_historical_setup_evidence\":true}")
                .unwrap();
        }
    }
    let prepared = Prepared {
        schema: "elevenid.installer-acme-host-prepared/v1".into(),
        installation_id: state.journal().installation_id(),
        environment,
        evidence_sha256: state
            .with_inspection(|view| fingerprints(view, environment))
            .unwrap(),
        projection,
        inputs,
        receipt: observed,
        initial_setup_complete: true,
        activation_performed: false,
        installation_ready: false,
    };
    state
        .write_evidence(&name(environment, "prepared"), &encode(&prepared).unwrap())
        .unwrap();
    Boundary {
        _files: files,
        installation,
        state,
        acme,
    }
}

#[path = "installer_acme_initial_terminal_tests.rs"]
mod initial_terminal_cases;

#[test]
#[ignore = "requires an ordinary nonroot OS identity for rootless prepared-boundary admission"]
fn complete_prepared_staging_candidate_can_roll_over_after_expiry_and_resume_its_permit() {
    let mut fixture = boundary_fixture_with_staging(true);
    let acme = fixture.acme.take().unwrap();
    let prepared_path = fixture
        .installation
        .join("evidence")
        .join(name(AcmeEnvironment::Staging, "prepared"));
    let original_prepared = files::read(&prepared_path).unwrap();
    let candidate = fixture
        .state
        .with_maintenance(|state| acme.finish_locked(state))
        .unwrap()
        .candidate
        .unwrap();
    assert_eq!(candidate.cycle(), 0);
    let inputs = acme.inputs();
    assert!(fixture
        .state
        .with_maintenance(|state| initial_rollover::select(
            state,
            inputs.configuration,
            inputs.ingress_key
        ))
        .unwrap()
        .is_none());
    let expiry = candidate.metadata()["not_after"].as_u64().unwrap();
    acme.advance(expiry - installer_acme::now().unwrap());
    let permit = fixture
        .state
        .with_maintenance(|state| {
            initial_rollover::select(state, inputs.configuration, inputs.ingress_key)
        })
        .unwrap()
        .unwrap();
    assert_eq!(permit.cycle(), 1);
    assert_eq!(
        permit.prior_candidate().unwrap().metadata(),
        candidate.metadata()
    );
    fixture
        .state
        .with_inspection(|view| permit.require_worker(view, &inputs))
        .unwrap();
    let digest = permit.sha256().to_owned();
    drop(fixture.state);
    let mut reopened =
        crate::installer_state::LockedMaintenance::open(&fixture.installation).unwrap();
    let retained =
        initial_rollover::select(&mut reopened, inputs.configuration, inputs.ingress_key)
            .unwrap()
            .unwrap();
    assert_eq!(retained.sha256(), digest);
    retained
        .require_worker(reopened.inspection(), &inputs)
        .unwrap();
    assert!(crate::installer_acme_state::Ledger::load_cycle(
        reopened.inspection(),
        AcmeEnvironment::Staging,
        1
    )
    .unwrap()
    .is_none());
    assert_eq!(files::read(prepared_path).unwrap(), original_prepared);
    reopened
        .write_evidence_exclusive("generation-pending.json", b"{}")
        .unwrap();
    assert!(retained
        .require_worker(reopened.inspection(), &inputs)
        .is_err());
    assert!(
        initial_rollover::select(&mut reopened, inputs.configuration, inputs.ingress_key).is_err()
    );
}

#[test]
#[ignore = "requires an ordinary nonroot OS identity for rootless prepared-boundary admission"]
fn initial_replacement_never_crosses_application_or_lifecycle_ownership() {
    for marker in [
        "generation-pending.json",
        "application-started.json",
        "compose-session.json",
        "lifecycle-config.json",
        "uninstall-intent.json",
    ] {
        let mut fixture = boundary_fixture();
        let (intent, _, configuration) = fixture.state.with_inspection(load_prepared).unwrap();
        let key = intent.ingress_key.bind(intent.installation_id).unwrap();
        assert!(fixture
            .state
            .with_maintenance(|state| initial_rollover::select(state, &configuration, &key))
            .unwrap()
            .is_none());
        fixture.state.write_evidence(marker, b"{}").unwrap();
        assert!(
            fixture
                .state
                .with_maintenance(|state| initial_rollover::select(state, &configuration, &key))
                .is_err(),
            "{marker}"
        );
    }
}

#[test]
#[ignore = "requires an ordinary nonroot OS identity for rootless prepared-boundary admission"]
fn recurring_setup_retains_provenance_without_reapplying_original_storage_observations() {
    let fixture = boundary_fixture();
    let journal = files::read(fixture.installation.join("installation.json")).unwrap();
    fixture
        .state
        .with_inspection(|view| load_prepared(view).map(|_| ()))
        .unwrap();
    files::set_permissions(
        fixture.installation.join("state/postgres"),
        files::Permissions::from_mode(0o770),
    )
    .unwrap();
    fixture
        .state
        .with_inspection(|view| {
            assert!(
                load_prepared(view).is_err(),
                "pending initial enrollment still requires pristine storage"
            );
            let context = maintenance_context(view)?;
            assert_eq!(context.compose_inputs.installation, fixture.installation);
            assert_eq!(
                context.compose_inputs.project,
                view.journal().compose_project()
            );
            let status = preparation_status(view);
            assert_eq!(status["state"], "prepared");
            assert_eq!(status["check"], Value::Null);
            assert_eq!(status["initial_preparation"]["checked"], true);
            assert_eq!(status["initial_preparation"]["matches"], false);
            assert_eq!(
                status["initial_preparation"]["check"],
                "application_preparation"
            );
            assert_eq!(status["continuation_authorized"], false);
            assert_eq!(status["installation_ready"], false);
            Ok(())
        })
        .unwrap();
    let original = fixture
        .installation
        .join("evidence")
        .join(name(AcmeEnvironment::Production, "custody"));
    let mut record = files::read(&original).unwrap();
    record.push(b' ');
    files::write(original, record).unwrap();
    assert!(
        fixture.state.with_inspection(maintenance_context).is_err(),
        "immutable setup evidence still binds maintenance"
    );
    let status = fixture
        .state
        .with_inspection(|view| Ok(preparation_status(view)))
        .unwrap();
    assert_eq!(status["state"], "refused");
    assert_eq!(status["check"], "evidence_fingerprints");
    assert_eq!(
        files::read(fixture.installation.join("installation.json")).unwrap(),
        journal
    );
}

#[test]
#[ignore = "requires an ordinary nonroot OS identity for rootless prepared-boundary admission"]
fn complete_pending_boundary_reopens_and_rejects_rebound_inputs_proofs_and_native_jobs() {
    for mutation in [
        "none",
        "environment",
        "renewal-identity",
        "renewal-observation",
        "application-projection",
        "custody-job",
        "native-setup",
        "operator",
        "projection-directory",
        "source-layer",
        "prepared-ready",
        "prepared-port",
        "prepared-runtime",
    ] {
        let fixture = boundary_fixture();
        assert!(fixture
            .state
            .with_inspection(continuation_available)
            .unwrap());
        let journal = files::read(fixture.installation.join("installation.json")).unwrap();
        if mutation != "none" {
            let path = match mutation {
                "environment" => fixture
                    .installation
                    .join("evidence")
                    .join(RENEWAL_ENVIRONMENT),
                "renewal-identity" => fixture
                    .installation
                    .join("renewal-transfer/delivered/renewal-secret-id"),
                "renewal-observation" => fixture
                    .installation
                    .join("evidence/renewal-observation.json"),
                "application-projection" => fixture
                    .installation
                    .join("secrets/operator_bootstrap_password"),
                "custody-job" => fixture
                    .installation
                    .join("evidence")
                    .join(name(AcmeEnvironment::Production, "custody")),
                "native-setup" => fixture
                    .installation
                    .join(format!("evidence/compose-setup-{CREDENTIALS}-result.json")),
                "operator" => fixture.installation.join("marty-deploy"),
                "source-layer" => fixture.installation.join("bundle").join(LAYER),
                "projection-directory" => {
                    let original = fixture.installation.join(PROJECTION);
                    files::rename(&original, fixture.installation.join("retained-projection"))
                        .unwrap();
                    files::create_dir(&original).unwrap();
                    files::set_permissions(&original, files::Permissions::from_mode(0o755))
                        .unwrap();
                    original
                }
                _ => fixture
                    .installation
                    .join("evidence")
                    .join(name(AcmeEnvironment::Production, "prepared")),
            };
            if mutation.starts_with("prepared-") {
                let mut record: Value =
                    serde_json::from_slice(&files::read(&path).unwrap()).unwrap();
                match mutation {
                    "prepared-ready" => record["installation_ready"] = json!(true),
                    "prepared-port" => {
                        record["inputs"]["allowed_loopback_ports"] = json!([18080, 18200, 28080])
                    }
                    "prepared-runtime" => {
                        record["inputs"]["services"] = json!([RESPONDER, "foreign-service"])
                    }
                    _ => unreachable!(),
                }
                files::write(&path, encode(&record).unwrap()).unwrap();
            } else if mutation != "projection-directory" {
                let mut bytes = files::read(&path).unwrap();
                bytes.push(b' ');
                let mode = files::metadata(&path).unwrap().mode() & 0o7777;
                files::set_permissions(&path, files::Permissions::from_mode(0o600)).unwrap();
                files::write(&path, &bytes).unwrap();
                files::set_permissions(&path, files::Permissions::from_mode(mode)).unwrap();
            }
        }
        drop(fixture.state);
        let view = LockedInspection::open(&fixture.installation).unwrap();
        let expected_check = match mutation {
            "none" => None,
            // The responder owns its derived environment; the earlier renewal
            // environment remains bound in the cumulative native receipt.
            "environment" => Some(Check::InputCustody),
            "renewal-identity" | "renewal-observation" => Some(Check::PublicRenewal),
            "application-projection" => Some(Check::ApplicationPreparation),
            "custody-job" => Some(Check::EvidenceFingerprints),
            "native-setup" => Some(Check::CredentialsJob),
            "operator" => Some(Check::OperatorBinding),
            "projection-directory" => Some(Check::Projection),
            "source-layer" => Some(Check::InputCustody),
            "prepared-ready" => Some(Check::PreparationState),
            "prepared-port" => Some(Check::RuntimeInputs),
            "prepared-runtime" => Some(Check::ServiceSelection),
            _ => unreachable!(),
        };
        assert_eq!(
            inspect_retained_setup(&view, true).err(),
            expected_check,
            "{mutation}"
        );
        assert_eq!(
            continuation_available(&view).is_ok(),
            mutation == "none",
            "{mutation}"
        );
        if let Some(check) = expected_check {
            assert_eq!(continuation_available(&view).unwrap_err(), check.refusal());
        }
        let status = installer_acme::status(&view).unwrap();
        assert_eq!(status["configured"], false);
        assert_eq!(status["environments"], serde_json::json!([]));
        let host = &status["host_preparation"];
        if mutation == "application-projection" {
            assert_eq!(host["state"], "prepared");
            assert_eq!(host["initial_preparation"]["matches"], false);
            assert_eq!(
                host["initial_preparation"]["check"],
                "application_preparation"
            );
        } else if let Some(check) = expected_check {
            assert_eq!(host["state"], "refused", "{mutation}");
            assert_eq!(host["check"], check.code(), "{mutation}");
        } else {
            assert_eq!(host["state"], "prepared");
            assert_eq!(host["initial_preparation"]["matches"], true);
            assert_eq!(host["initial_preparation"]["check"], Value::Null);
        }
        assert_eq!(host["runtime_observed"], false);
        assert_eq!(host["continuation_authorized"], false);
        assert_eq!(host["setup_replay_authorized"], false);
        assert_eq!(host["installation_ready"], false);
        assert!(!status
            .to_string()
            .contains(fixture.installation.to_str().unwrap()));
        if mutation == "none" {
            let context = continuation_context(&view).unwrap();
            assert_eq!(context.compose_inputs.services, [RESPONDER]);
            assert_eq!(
                context.compose_inputs.environment.path,
                fixture
                    .installation
                    .join("evidence")
                    .join(environment_name(AcmeEnvironment::Production, "responder"))
            );
        }
        assert_eq!(
            files::read(fixture.installation.join("installation.json")).unwrap(),
            journal
        );
    }
}
