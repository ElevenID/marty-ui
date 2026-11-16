//! Signed acceptance startup observations. This owner reads the real retained
//! authorities and native runtime; it never repairs, resumes, or grants Ready.
#![cfg(target_os = "linux")]

use crate::{
    installer_candidate_command, installer_command, installer_doctor,
    installer_generation_binding as generation, installer_hosting, installer_release as release,
    installer_rootless_storage_canary as canary,
    installer_state::{AcceptanceScope, ExecutionScope, LockedInspection, Phase, RuntimeProfile},
    installer_trust::TrustSource,
    installer_validation, installer_verify,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

type Result<T> = std::result::Result<T, String>;
const REFUSED: &str = "Signed startup observation refused or incomplete; preserve installation evidence. No Ready or functional qualification was granted";
pub const SCHEMA: &str = "elevenid.installer-signed-startup-observation/v1";
pub const MAX_BYTES: usize = 65536;

fn require(condition: bool) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}
fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|_| REFUSED.into())
}
fn hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn signed_scope(
    scope: &ExecutionScope,
    phase: Phase,
    profile: RuntimeProfile,
) -> Result<&AcceptanceScope> {
    let ExecutionScope::AcceptanceOnly(scope) = scope else {
        return Err(REFUSED.into());
    };
    require(phase == Phase::Provisioning && profile == RuntimeProfile::Rootless)?;
    require(
        scope
            .authenticated_evidence()?
            .get("installer-candidate-authorization.json")
            == Some(&scope.authorization_sha256),
    )?;
    Ok(scope)
}

fn public_hosting(hosting: &release::CandidateHosting) -> Result<()> {
    hosting.validate()?;
    require(
        hosting.certificate_source == "acme"
            && hosting.acme_environment.as_deref() == Some("production")
            && hosting.public_entry_origin.is_some()
            && hosting.staging_trust.is_none(),
    )
}

/// Explicit local continuation retains its historical consumed authority. The
/// controller separately checks the still-active grant before every automatic
/// invocation; this helper never creates or extends a dispatch authorization.
pub(crate) fn retained_signed_startup(view: &LockedInspection, operator: &str) -> Result<bool> {
    if !matches!(
        view.journal().execution_scope(),
        ExecutionScope::AcceptanceOnly(_)
    ) {
        return Ok(false);
    }
    signed_scope(
        view.journal().execution_scope(),
        view.journal().phase(),
        view.journal().runtime().ok_or(REFUSED)?.profile,
    )?;
    installer_candidate_command::require_retained_scope(view, operator)?;
    let receipt = view.read_evidence("installer-controller-consumption.json")?;
    let consumed = release::parse_controller_consumption(&receipt, now()?)?;
    let Some(hosting) = consumed.hosting else {
        return Ok(false);
    };
    if hosting.certificate_source != "acme"
        || hosting.acme_environment.as_deref() != Some("production")
        || hosting.public_entry_origin.is_none()
    {
        return Ok(false);
    }
    public_hosting(&hosting)?;
    require(installer_hosting::resolve(view)?.source_sha256() == hosting.input_sha256)?;
    Ok(true)
}

fn page_trust(
    source: TrustSource,
    origin: &str,
    certificate_scope: &str,
    page: &installer_validation::PageObservation,
    hosting: &release::CandidateHosting,
) -> Result<()> {
    require(
        source == TrustSource::MozillaPublicRoots
            && origin == hosting.public_origin
            && certificate_scope == "public-ingress"
            && Some(&page.origin) == hosting.public_entry_origin.as_ref()
            && page.alias_api_isolation_observed
            && page.app_name.is_some(),
    )
}

#[derive(Clone, Serialize)]
pub(crate) struct StartupObservationRequest {
    observation_id: String,
    challenge: String,
}
impl StartupObservationRequest {
    pub(crate) fn parse(observation_id: &str, challenge: &str) -> Result<Self> {
        let id = uuid::Uuid::parse_str(observation_id).map_err(|_| REFUSED)?;
        require(id.to_string() == observation_id && id.get_version_num() == 4 && hex(challenge))?;
        Ok(Self {
            observation_id: observation_id.into(),
            challenge: challenge.into(),
        })
    }
    pub(crate) fn fresh() -> Self {
        Self {
            observation_id: uuid::Uuid::new_v4().to_string(),
            challenge: release::sha256(
                format!("{}{}", uuid::Uuid::new_v4(), uuid::Uuid::new_v4()).as_bytes(),
            ),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct CurrentSelection {
    kind: &'static str,
    sequence: u64,
    attempt: u64,
    current_binding_sha256: String,
    session_sha256: String,
    configuration_sha256: String,
    selected_evidence_sha256: BTreeMap<String, String>,
}

fn selection(
    view: &LockedInspection,
    installation: &Path,
    saved: &installer_doctor::SavedSession,
) -> Result<CurrentSelection> {
    let binding = generation::load_verified(
        installation,
        &view.journal().installation_id().to_string(),
        &view.journal().runtime().ok_or(REFUSED)?.engine_id,
    )?
    .ok_or(REFUSED)?;
    // These immutable binding flags describe the producer, not current native
    // activation. load_verified and the selected session prove selection.
    require(binding.public_ingress() && !binding.activated && !binding.installation_ready)?;
    let evidence = if binding.sequence() == 0 {
        [
            "application-generation.json",
            "application-generation-pending.json",
            "application-generation-selection.json",
            "compose-session.json",
        ]
        .into_iter()
        .map(|name| Ok((name.into(), release::sha256(&view.read_evidence(name)?))))
        .collect::<Result<_>>()?
    } else {
        binding.selected_evidence(installation)?
    };
    Ok(CurrentSelection {
        kind: "current",
        sequence: binding.sequence(),
        attempt: binding.attempt(),
        current_binding_sha256: binding.sha256()?,
        session_sha256: release::sha256(&serde_json::to_vec(saved).map_err(|_| REFUSED)?),
        configuration_sha256: saved.configuration_sha256.clone(),
        selected_evidence_sha256: evidence,
    })
}

/// Fields are private so a caller cannot manufacture a successful native result.
#[derive(Serialize)]
pub(crate) struct StartupObservation {
    schema: &'static str,
    status: &'static str,
    request: StartupObservationRequest,
    installation_id: String,
    engine_id: String,
    operator_sha256: String,
    context_sha256: String,
    authority: Value,
    runtime: Value,
    hosting: release::CandidateHosting,
    selection: CurrentSelection,
    canary_evidence_sha256: BTreeMap<String, String>,
    bundle_validation: Value,
    bundle_validation_sha256: String,
    resources: crate::installer_compose::ProjectResources,
    services: Value,
    validation: Value,
    trust: crate::installer_trust::TrustInfo,
    page: installer_validation::PageObservation,
    started_at: u64,
    completed_at: u64,
    not_atomic_snapshot: bool,
    installation_ready: bool,
    functional_recovery_qualified: bool,
    load_characterized: bool,
}
impl StartupObservation {
    pub(crate) fn bytes(&self) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(self).map_err(|_| REFUSED)?;
        require(!bytes.is_empty() && bytes.len() <= MAX_BYTES)?;
        Ok(bytes)
    }
}

pub(crate) fn observe_locked(
    view: &LockedInspection,
    installation: &Path,
    docker: &Path,
    request: StartupObservationRequest,
) -> Result<StartupObservation> {
    installer_command::require_rootless_process()?;
    view.require_path_binding(installation)?;
    let started_at = now()?;
    let deadline = Instant::now() + Duration::from_secs(120);
    let journal = view.journal();
    let runtime = journal.runtime().ok_or(REFUSED)?;
    let scope = signed_scope(journal.execution_scope(), journal.phase(), runtime.profile)?;
    let operator = installer_verify::current_operator_digest()?;
    let pins = installer_candidate_command::require_retained_scope(view, &operator)?;
    let auth = view.read_evidence("installer-candidate-authorization.json")?;
    let receipt = view.read_evidence("installer-controller-consumption.json")?;
    let inventory = view.read_evidence("installer-inventory.json")?;
    let consumed = release::parse_controller_consumption(&receipt, started_at)?;
    let hosting = consumed.hosting.clone().ok_or(REFUSED)?;
    public_hosting(&hosting)?;
    let selected_hosting = installer_hosting::resolve(view)?;
    require(selected_hosting.source_sha256() == hosting.input_sha256)?;
    let canary_evidence_sha256 = canary::require_completed(view)?;
    require(
        canary_evidence_sha256.len() == canary::COMPLETED_EVIDENCE.len() + pins.len()
            && pins
                .iter()
                .all(|(name, digest)| canary_evidence_sha256.get(name) == Some(digest)),
    )?;
    let saved = installer_doctor::load_session(view, installation)?;
    require(saved.schema == "elevenid.installer-compose-session/v1")?;
    let selected = selection(view, installation, &saved)?;
    let resources = saved.receipt.resources.clone().ok_or(REFUSED)?;
    let bundle_bytes = view.read_evidence("bundle-validation.json")?;
    let bundle = crate::installer_json::decode(&bundle_bytes).map_err(|_| REFUSED)?;
    require(
        bundle.as_object().is_some_and(|v| v.len() == 6)
            && bundle["schema"] == "elevenid.installer-bundle-validation/v1"
            && bundle["runtime_observed"] == false
            && bundle["file_count"].as_u64().is_some_and(|v| v > 0)
            && bundle["directory_count"].as_u64().is_some()
            && bundle["marker_sha256"].as_str().is_some_and(hex)
            && bundle["image_lock_sha256"].as_str().is_some_and(hex),
    )?;
    let parsed_inventory = release::parse_inventory(&inventory)?;
    require(
        bundle["image_lock_sha256"]
            == parsed_inventory
                .artifact("prepared-selfhost-images.json")?
                .sha256,
    )?;
    let observed = installer_validation::observe_locked(installation, docker, view, false)?;
    let page = observed.page.ok_or(REFUSED)?;
    page_trust(
        observed.trust.trust_source,
        &observed.trust.origin,
        observed.trust.certificate_scope,
        &page,
        &hosting,
    )?;
    let after = installer_doctor::load_session(view, installation)?;
    require(
        selection(view, installation, &after)? == selected
            && serde_json::to_value(&saved).map_err(|_| REFUSED)?
                == serde_json::to_value(&after).map_err(|_| REFUSED)?
            && pins == installer_candidate_command::require_retained_scope(view, &operator)?
            && view.read_evidence("bundle-validation.json")? == bundle_bytes
            && Instant::now() < deadline,
    )?;
    let record_bytes = serde_json::to_vec_pretty(&observed.record).map_err(|_| REFUSED)?;
    require(release::sha256(&record_bytes) == observed.record_sha256)?;
    let completed_at = now()?;
    require(started_at <= completed_at && completed_at - started_at <= 120)?;
    view.require_path_binding(installation)?;
    let report = StartupObservation {
        schema: SCHEMA,
        status: "startup_observed",
        request,
        installation_id: journal.installation_id().to_string(),
        engine_id: runtime.engine_id.clone(),
        operator_sha256: operator,
        context_sha256: scope.context_sha256.clone(),
        authority: json!({"authorization_sha256":release::sha256(&auth),
            "controller_consumption_sha256":release::sha256(&receipt),
            "inventory_sha256":release::sha256(&inventory),"consumption_id":scope.consumption_id,
            "authenticated_evidence_sha256":pins,"consumed_at":consumed.consumed_at}),
        runtime: json!({"profile":"rootless","uid":unsafe { libc::geteuid() },
            "docker_host":runtime.docker_host,"no_new_privileges":true}),
        hosting,
        selection: selected,
        canary_evidence_sha256,
        bundle_validation: bundle,
        bundle_validation_sha256: release::sha256(&bundle_bytes),
        resources,
        services: observed.services,
        validation: json!({"name":observed.record_name,"sha256":observed.record_sha256,
            "record":std::str::from_utf8(&record_bytes).map_err(|_| REFUSED)?}),
        trust: observed.trust,
        page,
        started_at,
        completed_at,
        not_atomic_snapshot: true,
        installation_ready: false,
        functional_recovery_qualified: false,
        load_characterized: false,
    };
    report.bytes()?;
    Ok(report)
}

struct Options {
    installation: PathBuf,
    docker: PathBuf,
    request: StartupObservationRequest,
}
fn options(args: &[String]) -> Result<Options> {
    let mut values = BTreeMap::new();
    require(args.len() == 8)?;
    for pair in args.chunks_exact(2) {
        require(
            [
                "--install-dir",
                "--docker-bin",
                "--observation-id",
                "--challenge",
            ]
            .contains(&pair[0].as_str())
                && values.insert(pair[0].as_str(), pair[1].as_str()).is_none(),
        )?;
    }
    let path = |name: &str| -> Result<PathBuf> {
        let value = PathBuf::from(values.get(name).ok_or(REFUSED)?);
        require(
            value.is_absolute()
                && value.components().all(|part| {
                    matches!(
                        part,
                        std::path::Component::RootDir | std::path::Component::Normal(_)
                    )
                }),
        )?;
        Ok(value)
    };
    Ok(Options {
        installation: path("--install-dir")?,
        docker: path("--docker-bin")?,
        request: StartupObservationRequest::parse(
            values.get("--observation-id").ok_or(REFUSED)?,
            values.get("--challenge").ok_or(REFUSED)?,
        )?,
    })
}

pub fn run(args: &[String]) -> Result<()> {
    let options = options(args)?;
    let view = LockedInspection::open(&options.installation)?;
    let report = observe_locked(
        &view,
        &options.installation,
        &options.docker,
        options.request,
    )?;
    println!(
        "{}",
        std::str::from_utf8(&report.bytes()?).map_err(|_| REFUSED)?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn scope() -> ExecutionScope {
        ExecutionScope::AcceptanceOnly(AcceptanceScope {
            authorization_sha256: "a".repeat(64),
            context_sha256: "b".repeat(64),
            consumption_id: "c".repeat(64),
            authenticated_evidence_sha256: Some(
                crate::installer_state::ACCEPTANCE_AUTHENTICATED_EVIDENCE
                    .into_iter()
                    .map(|name| {
                        (
                            name.into(),
                            if name == "installer-candidate-authorization.json" {
                                "a".repeat(64)
                            } else {
                                "d".repeat(64)
                            },
                        )
                    })
                    .collect(),
            ),
        })
    }

    fn hosting() -> release::CandidateHosting {
        serde_json::from_value(json!({
            "input_sha256":"a".repeat(64),"input_size_bytes":512,
            "public_origin":"https://marty.example.com","public_entry_origin":"https://8.8.4.4",
            "certificate_source":"acme","acme_environment":"production",
            "acme_terms_url":"https://letsencrypt.org/documents/fixture-terms.pdf","staging_trust":null,
        }))
        .unwrap()
    }

    #[test]
    fn native_observer_requires_authenticated_acceptance_provisioning_and_rootless_scope() {
        let good = scope();
        assert!(signed_scope(&good, Phase::Provisioning, RuntimeProfile::Rootless).is_ok());
        for phase in [
            Phase::Initialized,
            Phase::Verified,
            Phase::Provisioned,
            Phase::Ready,
        ] {
            assert!(signed_scope(&good, phase, RuntimeProfile::Rootless).is_err());
        }
        assert!(signed_scope(&good, Phase::Provisioning, RuntimeProfile::Rootful).is_err());
        for other in [
            ExecutionScope::Unclassified,
            ExecutionScope::CandidateTest(crate::installer_state::CandidateTestScope {
                inventory_sha256: "e".repeat(64),
                build_run_id: 1,
                build_run_attempt: 1,
            }),
        ] {
            assert!(signed_scope(&other, Phase::Provisioning, RuntimeProfile::Rootless).is_err());
        }
        for mutation in ["legacy", "missing", "extra", "authority"] {
            let mut bad = scope();
            let ExecutionScope::AcceptanceOnly(ref mut value) = bad else {
                unreachable!()
            };
            match mutation {
                "legacy" => value.authenticated_evidence_sha256 = None,
                "missing" => {
                    value
                        .authenticated_evidence_sha256
                        .as_mut()
                        .unwrap()
                        .remove("installer-controller-consumption.json");
                }
                "extra" => {
                    value
                        .authenticated_evidence_sha256
                        .as_mut()
                        .unwrap()
                        .insert("foreign.json".into(), "a".repeat(64));
                }
                "authority" => {
                    value
                        .authenticated_evidence_sha256
                        .as_mut()
                        .unwrap()
                        .insert(
                            "installer-candidate-authorization.json".into(),
                            "e".repeat(64),
                        );
                }
                _ => unreachable!(),
            }
            assert!(
                signed_scope(&bad, Phase::Provisioning, RuntimeProfile::Rootless).is_err(),
                "accepted {mutation}"
            );
        }
    }

    #[test]
    fn native_observer_never_promotes_private_staging_or_unbound_ip_hosting() {
        let good = hosting();
        assert!(public_hosting(&good).is_ok());
        for mutation in ["managed", "staging", "alias", "identity", "extra-trust"] {
            let mut bad = good.clone();
            match mutation {
                "managed" => {
                    bad.certificate_source = "managed-ca".into();
                    bad.acme_environment = None;
                    bad.acme_terms_url = None;
                }
                "staging" => {
                    bad.acme_environment = Some("staging".into());
                }
                "alias" => bad.public_entry_origin = None,
                "identity" => bad.public_origin = "https://8.8.4.4".into(),
                "extra-trust" => {
                    let mut value = serde_json::to_value(&bad).unwrap();
                    value["staging_trust"] = json!({"sha256":"a".repeat(64),"size_bytes":32});
                    bad = serde_json::from_value(value).unwrap();
                }
                _ => unreachable!(),
            }
            assert!(public_hosting(&bad).is_err(), "accepted {mutation}");
        }
    }

    #[test]
    fn native_observer_requires_actual_alias_page_brand_and_public_trust() {
        let hosting = hosting();
        let page = installer_validation::PageObservation {
            origin: hosting.public_entry_origin.clone().unwrap(),
            assets: vec![],
            app_name: Some("Actual branding".into()),
            alias_api_isolation_observed: true,
        };
        let good = || page.clone();
        assert!(page_trust(
            TrustSource::MozillaPublicRoots,
            &hosting.public_origin,
            "public-ingress",
            &page,
            &hosting
        )
        .is_ok());
        assert!(page_trust(
            TrustSource::ConfiguredCa,
            &hosting.public_origin,
            "public-ingress",
            &page,
            &hosting
        )
        .is_err());
        assert!(page_trust(
            TrustSource::MozillaPublicRoots,
            "https://other.example.com",
            "public-ingress",
            &page,
            &hosting
        )
        .is_err());
        assert!(page_trust(
            TrustSource::MozillaPublicRoots,
            &hosting.public_origin,
            "backend",
            &page,
            &hosting
        )
        .is_err());
        for mutation in ["origin", "brand", "api"] {
            let mut bad = good();
            match mutation {
                "origin" => bad.origin = hosting.public_origin.clone(),
                "brand" => bad.app_name = None,
                "api" => bad.alias_api_isolation_observed = false,
                _ => unreachable!(),
            }
            assert!(page_trust(
                TrustSource::MozillaPublicRoots,
                &hosting.public_origin,
                "public-ingress",
                &bad,
                &hosting
            )
            .is_err());
        }
    }
    #[test]
    fn startup_request_is_canonical_and_cannot_select_an_origin_or_operation() {
        let good = vec![
            "--install-dir".into(),
            "/private/install".into(),
            "--docker-bin".into(),
            "/usr/bin/docker".into(),
            "--observation-id".into(),
            "12345678-1234-4234-8234-123456789abc".into(),
            "--challenge".into(),
            "a".repeat(64),
        ];
        assert!(options(&good).is_ok());
        for index in [0, 2, 4, 6] {
            let mut bad = good.clone();
            bad[index] = "--origin".into();
            assert!(options(&bad).is_err());
        }
        for (index, value) in [
            (1, "relative"),
            (3, "/usr/../bin/docker"),
            (5, "12345678-1234-1234-8234-123456789abc"),
            (7, "not-a-digest"),
        ] {
            let mut bad = good.clone();
            bad[index] = value.into();
            assert!(options(&bad).is_err());
        }
        let mut duplicate = good;
        duplicate[2] = "--install-dir".into();
        assert!(options(&duplicate).is_err());
    }
    #[test]
    fn fresh_observation_challenges_are_independent() {
        let first = StartupObservationRequest::fresh();
        let second = StartupObservationRequest::fresh();
        assert_ne!(first.challenge, second.challenge);
        assert_ne!(first.observation_id, second.observation_id);
        assert!(StartupObservationRequest::parse(&first.observation_id, &first.challenge).is_ok());
    }
}
