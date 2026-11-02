//! Read-only rebinding of a previously authenticated AcceptanceOnly scope.
//! This neither authenticates signatures nor grants a new dispatch. In
//! particular, historical grant validity permits observing an already owned
//! canary after interruption; it never renews the original execution window.
use super::{release, require, Consumption, Result, REFUSED};
use crate::installer_state::{
    AcceptanceScope, ExecutionScope, Identity, LockedInspection, RuntimeBinding, RuntimeProfile,
    ACCEPTANCE_AUTHENTICATED_EVIDENCE,
};
use std::collections::BTreeMap;

struct Context<'a> {
    scope: &'a AcceptanceScope,
    identity: &'a Identity,
    runtime: &'a RuntimeBinding,
    installation_id: uuid::Uuid,
    operator_sha: &'a str,
    observed_at: u64,
}

fn bind_records(
    context: Context<'_>,
    records: &BTreeMap<String, Vec<u8>>,
) -> Result<Option<release::CandidateHosting>> {
    let Context {
        scope,
        identity,
        runtime,
        installation_id,
        operator_sha,
        observed_at,
    } = context;
    let pinned = scope.authenticated_evidence()?;
    require(records.len() == ACCEPTANCE_AUTHENTICATED_EVIDENCE.len())?;
    for name in ACCEPTANCE_AUTHENTICATED_EVIDENCE {
        let bytes = records.get(name).ok_or(REFUSED)?;
        require(!bytes.is_empty() && pinned.get(name) == Some(&release::sha256(bytes)))?;
    }
    let authorization = &records["installer-candidate-authorization.json"];
    let controller = &records["installer-controller-consumption.json"];
    let inventory = &records["installer-inventory.json"];
    require(runtime.profile == RuntimeProfile::Rootless)?;
    let receipt = release::parse_controller_consumption(controller, observed_at)?;
    let expected = release::CandidateContext {
        operator_sha: operator_sha.into(),
        source_sha: identity.source_sha.clone(),
        release_tag: identity.release_tag.clone(),
        phase: receipt.phase,
        nonce: receipt.nonce.clone(),
        harness_source_sha: receipt.harness_source_sha.clone(),
        run_id: receipt.run_id,
        run_attempt: receipt.run_attempt,
        hosting: receipt.hosting.clone(),
    };
    // Reconstructed fields are constrained by the context digest retained in
    // the installation at the original authenticated nonce-consumption point.
    require(
        scope.authorization_sha256 == release::sha256(authorization)
            && scope.context_sha256 == release::candidate_context_sha256(&expected)?
            && identity.inventory_sha256 == format!("sha256:{}", release::sha256(inventory))
            && receipt.installation_id == installation_id.to_string(),
    )?;
    release::bind_controller_consumption(
        controller,
        authorization,
        inventory,
        &expected,
        &runtime.engine_id,
        receipt.consumed_at,
    )?;
    let claim = Consumption {
        nonce: expected.nonce,
        authorization_sha256: scope.authorization_sha256.clone(),
        context_sha256: scope.context_sha256.clone(),
        installation_id,
        engine_id: runtime.engine_id.clone(),
    };
    let consumed = serde_json::to_vec(&serde_json::json!({
        "schema":"elevenid.installer-candidate-consumption/v1",
        "scope":"guest-local", "claim":claim,
    }))
    .map_err(|_| REFUSED)?;
    require(scope.consumption_id == release::sha256(&consumed))?;
    Ok(receipt.hosting)
}

pub(crate) fn require_retained(
    view: &LockedInspection,
    operator_sha: &str,
) -> Result<BTreeMap<String, String>> {
    let journal = view.journal();
    let ExecutionScope::AcceptanceOnly(scope) = journal.execution_scope() else {
        return Err(REFUSED.into());
    };
    let runtime = journal.runtime().ok_or(REFUSED)?;
    runtime.validate()?;
    let uid = unsafe { libc::geteuid() };
    require(uid != 0 && runtime.docker_host == format!("unix:///run/user/{uid}/docker.sock"))?;
    let records: BTreeMap<String, Vec<u8>> = ACCEPTANCE_AUTHENTICATED_EVIDENCE
        .into_iter()
        .map(|name| view.read_evidence(name).map(|bytes| (name.into(), bytes)))
        .collect::<Result<_>>()?;
    let hosting = bind_records(
        Context {
            scope,
            identity: journal.identity(),
            runtime,
            installation_id: journal.installation_id(),
            operator_sha,
            observed_at: super::now()?,
        },
        &records,
    )?;
    let selected = crate::installer_hosting::resolve(view)?;
    if let Some(hosting) = hosting {
        let raw = view.read_evidence(crate::installer_hosting::SOURCE)?;
        let roots = view.diagnostic_record(crate::installer_command::STAGING_ROOTS, true)?;
        require(
            crate::installer_hosting::candidate_binding(&raw, roots.as_deref())? == hosting
                && selected.source_sha256() == hosting.input_sha256,
        )?;
    } else {
        require(
            selected.mode() == crate::installer_hosting::Mode::Local
                && view
                    .diagnostic_record(crate::installer_command::STAGING_ROOTS, true)?
                    .is_none(),
        )?;
    }
    view.require_unchanged()?;
    Ok(scope.authenticated_evidence()?.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    struct Fixture {
        scope: AcceptanceScope,
        identity: Identity,
        runtime: RuntimeBinding,
        installation_id: uuid::Uuid,
        operator: String,
        authorization: Vec<u8>,
        controller: Vec<u8>,
        inventory: Vec<u8>,
        proofs: BTreeMap<String, Vec<u8>>,
    }
    impl Fixture {
        fn new() -> Self {
            let fixture: Value = serde_json::from_str(include_str!(
                "../tests/fixtures/installer-candidate-records.json"
            ))
            .unwrap();
            let authorization = fixture["authorization"]
                .as_str()
                .unwrap()
                .as_bytes()
                .to_vec();
            let inventory = fixture["inventory"].as_str().unwrap().as_bytes().to_vec();
            let now = fixture["now"].as_u64().unwrap();
            let auth = release::parse_candidate_authorization(&authorization, now).unwrap();
            let expected = release::CandidateContext {
                operator_sha: auth.operator_sha256.clone(),
                source_sha: auth.source_sha.clone(),
                release_tag: auth.release_tag.clone(),
                phase: auth.phase,
                nonce: auth.nonce.clone(),
                harness_source_sha: auth.harness_source_sha.clone(),
                run_id: auth.run_id,
                run_attempt: auth.run_attempt,
                hosting: auth.hosting.clone(),
            };
            let installation_id = uuid::Uuid::new_v4();
            let runtime = RuntimeBinding {
                docker_host: "unix:///run/user/1000/docker.sock".into(),
                engine_id: "test-engine-12345678".into(),
                openbao_port: 18442,
                profile: RuntimeProfile::Rootless,
            };
            let mut controller: Value = serde_json::from_slice(&authorization).unwrap();
            for field in ["expires_at", "issued_at", "platform"] {
                controller.as_object_mut().unwrap().remove(field);
            }
            let context = release::candidate_context_sha256(&expected).unwrap();
            controller["schema"] = json!("elevenid.installer-controller-consumption/v1");
            controller["scope"] = json!("controller-dispatch-consumed");
            controller["authorization_sha256"] = json!(release::sha256(&authorization));
            controller["context_sha256"] = json!(context);
            controller["guest_id"] = json!(uuid::Uuid::new_v4());
            controller["disk_id"] = json!("d".repeat(64));
            controller["engine_id"] = json!(runtime.engine_id);
            controller["installation_id"] = json!(installation_id);
            controller["consumed_at"] = json!(now);
            let claim = Consumption {
                nonce: auth.nonce,
                authorization_sha256: release::sha256(&authorization),
                context_sha256: context.clone(),
                installation_id,
                engine_id: runtime.engine_id.clone(),
            };
            let consumed = serde_json::to_vec(&json!({
                "schema":"elevenid.installer-candidate-consumption/v1", "scope":"guest-local", "claim":claim
            })).unwrap();
            let mut result = Self {
                scope: AcceptanceScope {
                    authorization_sha256: release::sha256(&authorization),
                    context_sha256: context,
                    consumption_id: release::sha256(&consumed),
                    authenticated_evidence_sha256: None,
                },
                identity: Identity {
                    source_sha: auth.source_sha,
                    release_tag: auth.release_tag,
                    inventory_sha256: format!("sha256:{}", release::sha256(&inventory)),
                },
                runtime,
                installation_id,
                operator: auth.operator_sha256,
                authorization,
                controller: serde_json::to_vec(&controller).unwrap(),
                inventory,
                proofs: ACCEPTANCE_AUTHENTICATED_EVIDENCE
                    .into_iter()
                    .filter(|name| {
                        name.ends_with(".sigstore.json") || name.ends_with(".provenance.jsonl")
                    })
                    .map(|name| {
                        (
                            name.into(),
                            format!("synthetic fixture proof for {name}").into_bytes(),
                        )
                    })
                    .collect(),
            };
            result.scope.authenticated_evidence_sha256 = Some(
                result
                    .records()
                    .into_iter()
                    .map(|(name, bytes)| (name, release::sha256(&bytes)))
                    .collect(),
            );
            result
        }
        fn records(&self) -> BTreeMap<String, Vec<u8>> {
            let mut records = self.proofs.clone();
            for (name, bytes) in [
                (
                    "installer-candidate-authorization.json",
                    &self.authorization,
                ),
                ("installer-controller-consumption.json", &self.controller),
                ("installer-inventory.json", &self.inventory),
            ] {
                records.insert(name.into(), bytes.clone());
            }
            records
        }
        fn check(&self) -> Result<()> {
            bind_records(
                Context {
                    scope: &self.scope,
                    identity: &self.identity,
                    runtime: &self.runtime,
                    installation_id: self.installation_id,
                    operator_sha: &self.operator,
                    observed_at: 200_000,
                },
                &self.records(),
            )
            .map(|_| ())
        }
    }

    #[test]
    fn retained_acceptance_scope_remains_historical_after_grant_expiry() {
        let fixture = Fixture::new();
        assert!(release::parse_candidate_authorization(&fixture.authorization, 200_000).is_err());
        fixture.check().unwrap();
    }

    #[test]
    fn retained_acceptance_scope_binds_both_grants_uuid_engine_inventory_operator_and_nonce() {
        for mutation in [
            "authorization",
            "context",
            "consumption",
            "installation",
            "engine",
            "inventory",
            "operator",
            "rootful",
            "receipt-run",
            "receipt-uuid",
            "receipt-nonce",
            "receipt-guest",
            "receipt-disk",
            "receipt-consumed-at",
        ] {
            let mut fixture = Fixture::new();
            match mutation {
                "authorization" => fixture.scope.authorization_sha256 = "e".repeat(64),
                "context" => fixture.scope.context_sha256 = "e".repeat(64),
                "consumption" => fixture.scope.consumption_id = "e".repeat(64),
                "installation" => fixture.installation_id = uuid::Uuid::new_v4(),
                "engine" => fixture.runtime.engine_id = "other-engine-12345678".into(),
                "inventory" => fixture.inventory.push(b'\n'),
                "operator" => fixture.operator = "e".repeat(64),
                "rootful" => {
                    fixture.runtime.profile = RuntimeProfile::Rootful;
                    fixture.runtime.docker_host = "unix:///var/run/docker.sock".into();
                }
                _ => {
                    let mut value: Value = serde_json::from_slice(&fixture.controller).unwrap();
                    match mutation {
                        "receipt-run" => value["run_attempt"] = json!(99),
                        "receipt-uuid" => value["installation_id"] = json!(uuid::Uuid::new_v4()),
                        "receipt-nonce" => value["nonce"] = json!("9".repeat(64)),
                        "receipt-guest" => value["guest_id"] = json!(uuid::Uuid::new_v4()),
                        "receipt-disk" => value["disk_id"] = json!("e".repeat(64)),
                        "receipt-consumed-at" => value["consumed_at"] = json!(100_001),
                        _ => unreachable!(),
                    }
                    fixture.controller = serde_json::to_vec(&value).unwrap();
                }
            }
            assert!(fixture.check().is_err(), "accepted {mutation}");
        }
    }

    #[test]
    fn retained_acceptance_scope_requires_the_exact_authenticated_proof_map() {
        for mutation in [
            "legacy",
            "missing",
            "extra",
            "cross-record",
            "changed-proof",
        ] {
            let mut fixture = Fixture::new();
            match mutation {
                "legacy" => fixture.scope.authenticated_evidence_sha256 = None,
                "missing" => {
                    fixture
                        .scope
                        .authenticated_evidence_sha256
                        .as_mut()
                        .unwrap()
                        .remove("installer-controller-consumption.json.sigstore.json");
                }
                "extra" => {
                    fixture
                        .scope
                        .authenticated_evidence_sha256
                        .as_mut()
                        .unwrap()
                        .insert("other-proof.json".into(), "a".repeat(64));
                }
                "cross-record" => {
                    let map = fixture
                        .scope
                        .authenticated_evidence_sha256
                        .as_mut()
                        .unwrap();
                    let other =
                        map["installer-candidate-authorization.json.provenance.jsonl"].clone();
                    map.insert(
                        "installer-controller-consumption.json.provenance.jsonl".into(),
                        other,
                    );
                }
                "changed-proof" => fixture
                    .proofs
                    .get_mut("installer-controller-consumption.json.sigstore.json")
                    .unwrap()
                    .extend_from_slice(b" changed"),
                _ => unreachable!(),
            }
            assert!(fixture.check().is_err(), "accepted {mutation}");
        }
    }
}
