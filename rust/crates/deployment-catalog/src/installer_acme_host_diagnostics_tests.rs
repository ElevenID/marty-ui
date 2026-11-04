use super::*;
use serde_json::json;

#[test]
fn checkpoints_keep_fixed_codes_and_discard_private_inner_errors() {
    let codes = [
        Check::Configuration,
        Check::Context,
        Check::InitialInputs,
        Check::InitialIngress,
        Check::OpenbaoConnection,
        Check::OpenbaoServer,
        Check::ResponderModel,
        Check::RuntimeContext,
        Check::PreparedRead,
        Check::PreparedDecode,
        Check::IntentRead,
        Check::IntentDecode,
        Check::InstallationPath,
        Check::ApplicationPreparation,
        Check::ApplicationProvenance,
        Check::PublicRenewal,
        Check::StagingTrust,
        Check::Schemas,
        Check::InstallationIdentity,
        Check::ConfigurationBinding,
        Check::ReleaseRuntime,
        Check::PreparationState,
        Check::ServiceSelection,
        Check::EnvironmentPath,
        Check::EvidenceFingerprints,
        Check::ApplicationProofDigest,
        Check::PriorReceipt,
        Check::Projection,
        Check::AuthorityDigests,
        Check::IngressKey,
        Check::BundleFiles,
        Check::OperatorBinding,
        Check::PriorOperation,
        Check::ResponderOperation,
        Check::ResponderReceipt,
        Check::CurrentInputReceipt,
        Check::HistoricalInputReceipt,
        Check::InputCustody,
        Check::CustodyJob,
        Check::CredentialsJob,
        Check::Http01Port,
        Check::EnvironmentDerivation,
        Check::ComposeLayers,
        Check::BoundInputs,
        Check::RuntimeInputs,
        Check::Resources,
        Check::Unchanged,
        Check::PresenceEvidence,
        Check::PreparedRecordMissing,
        Check::ContinuationBinding,
        Check::RuntimeModel,
        Check::LiveResources,
        Check::RuntimeHealth,
    ];
    let mut unique = BTreeSet::new();
    for code in codes {
        assert!(unique.insert(code.code()));
        assert_eq!(serde_json::to_value(code).unwrap(), code.code());
        for inner in [
            "credential=PRIVATE_TEST_TOKEN",
            "/private/customer/installation/private-record.json",
            "backend error with\nPRIVATE_RESPONSE\n",
        ] {
            let calls = std::cell::Cell::new(0);
            let failure = checkpoint::<()>(code, || {
                calls.set(calls.get() + 1);
                Err(inner.into())
            })
            .unwrap_err();
            assert_eq!(calls.get(), 1);
            assert_eq!(failure, format!("{REFUSED}; check={}", code.code()));
            assert!(!failure.contains(inner));
            let output = report("refused", Some(code), true, true, Some(Err(code)));
            assert_eq!(output["check"], code.code());
            assert_eq!(output["initial_preparation"]["check"], code.code());
            assert!(!output.to_string().contains(inner));
            assert_eq!(output["continuation_authorized"], false);
            assert_eq!(output["setup_replay_authorized"], false);
            assert_eq!(output["installation_ready"], false);
        }
    }
    let calls = std::cell::Cell::new(0);
    assert_eq!(
        checkpoint(Check::PreparedDecode, || {
            calls.set(calls.get() + 1);
            Ok(17)
        })
        .unwrap(),
        17
    );
    assert_eq!(calls.get(), 1);
}

fn prepared_serialization_fixture() -> Prepared {
    let installation = PathBuf::from("/synthetic-retained-installation");
    let receipt = ComposeReceipt {
        schema: "elevenid.installer-compose-operation/v1".into(),
        project: "marty-install-synthetic".into(),
        engine_id: "synthetic-engine".into(),
        operation: RESPONDER_OPERATION.into(),
        configuration_sha256: "a".repeat(64),
        input_files: BTreeMap::from([
            (installation.join("evidence/z-input.env"), "b".repeat(64)),
            (installation.join("evidence/a-input.env"), "c".repeat(64)),
        ]),
        command_succeeded: true,
        client_exit_code: Some(0),
        failure_class: None,
        observation_validated: true,
        resources: Some(ProjectResources::default()),
        // Preserve the native status object's insertion order. This is public
        // synthetic padding, not captured command output or a runtime fixture.
        status: vec![json!({
            "Service":RESPONDER,"State":"running","Health":"",
            "Command":"synthetic owned responder ".repeat(4096),
            "Labels":{"z-fixture":"last","a-fixture":"first"},
            "Publishers":[],"ExitCode":0
        })],
        installation_ready: false,
    };
    Prepared {
        schema: "elevenid.installer-acme-host-prepared/v1".into(),
        installation_id: uuid::Uuid::nil(),
        environment: AcmeEnvironment::Production,
        evidence_sha256: BTreeMap::new(),
        projection: ProjectionDirectory {
            device: 1,
            inode: 2,
            owner: 1001,
            group: 1001,
        },
        inputs: ComposeInputs {
            installation: installation.clone(),
            project: receipt.project.clone(),
            files: Vec::new(),
            bound_inputs: Vec::new(),
            environment: BoundFile {
                path: installation.join("evidence/acme-production-responder.env"),
                sha256: "d".repeat(64),
            },
            profiles: vec!["setup".into()],
            services: vec![RESPONDER.into()],
            approved_images: BTreeSet::new(),
            #[cfg(feature = "installer-development")]
            development_image: None,
            writable_bind_roots: BTreeSet::new(),
            readonly_bind_roots: BTreeSet::new(),
            allowed_loopback_ports: BTreeSet::from([18080]),
            ingress_listener: None,
            prior: Some(receipt.clone()),
        },
        receipt,
        initial_setup_complete: true,
        activation_performed: false,
        installation_ready: false,
    }
}

#[test]
fn native_prepared_roundtrip_preserves_large_receipt_bytes_and_digest() {
    let prepared = prepared_serialization_fixture();
    let receipt_bytes = encode(&prepared.receipt).unwrap();
    assert_eq!(
        installer_jobs::receipt_digest(&prepared.receipt).unwrap(),
        sha(&receipt_bytes)
    );
    let bytes = encode(&prepared).unwrap();
    assert!(bytes.len() > 128 * 1024 && bytes.len() < 4 * 1024 * 1024);
    let reopened: Prepared = decode(&bytes).unwrap();
    assert_eq!(encode(&reopened).unwrap(), bytes);
    assert_eq!(encode(&reopened.receipt).unwrap(), receipt_bytes);
    assert_eq!(
        installer_jobs::receipt_digest(&reopened.receipt).unwrap(),
        sha(&receipt_bytes)
    );
    assert_eq!(
        installer_jobs::receipt_digest(reopened.inputs.prior.as_ref().unwrap()).unwrap(),
        sha(&receipt_bytes)
    );
    // The product workspace enables preserve_order. Semantic JSON equality is
    // insufficient to substitute recursively sorted bytes for native receipts.
    let native = value(&reopened.receipt).unwrap();
    let mut sorted = native.clone();
    sorted.sort_all_objects();
    assert_eq!(sorted, native);
    assert_ne!(serde_json::to_vec(&sorted).unwrap(), receipt_bytes);
}

#[test]
fn typed_prepared_decode_reports_its_boundary_without_parser_details() {
    let prepared = prepared_serialization_fixture();
    for mutation in ["unknown-field", "wrong-number-type", "malformed"] {
        let mut value = value(&prepared).unwrap();
        match mutation {
            "unknown-field" => value["PRIVATE_UNKNOWN_FIELD"] = json!("PRIVATE_TEST_TOKEN"),
            "wrong-number-type" => value["projection"]["owner"] = json!(-1),
            "malformed" => (),
            _ => unreachable!(),
        }
        let bytes = if mutation == "malformed" {
            b"{\"PRIVATE_TEST_TOKEN\":".to_vec()
        } else {
            serde_json::to_vec(&value).unwrap()
        };
        let result = checked(Check::PreparedDecode, || decode::<Prepared>(&bytes));
        assert!(matches!(result, Err(Check::PreparedDecode)), "{mutation}");
        let message = result.unwrap_err().refusal();
        assert_eq!(message, format!("{REFUSED}; check=prepared_decode"));
        assert!(!message.contains("PRIVATE"));
    }
}
