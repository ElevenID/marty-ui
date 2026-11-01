//! Runtime-only recovery shared by prepared enrollment and recurring issuance.
//! No resource creation or initial setup service can enter this selection.
use super::*;
use crate::{installer_compose::RuntimeOperationOwner, installer_state::LockedMaintenance};

const SERVICES: [&str; 3] = ["openbao", "openbao-unseal", RESPONDER];

fn needs_start(resources: &ProjectResources, statuses: &[Value]) -> Result<bool> {
    require(statuses.len() == resources.containers.len())?;
    let mut seen = BTreeSet::new();
    let mut stopped = false;
    for row in statuses {
        let service = row["Service"].as_str().ok_or(REFUSED)?;
        let identity = resources.containers.get(service).ok_or(REFUSED)?;
        require(seen.insert(service) && row["ID"] == identity.id)?;
        if identity.setup {
            require(
                row["State"] == "exited"
                    && row["ExitCode"] == 0
                    && identity
                        .setup_execution
                        .as_ref()
                        .is_some_and(|setup| setup.completed_without_restart),
            )?;
        } else if SERVICES.contains(&service) {
            match row["State"].as_str() {
                Some("running") => {}
                Some("exited") => stopped = true,
                _ => return Err(REFUSED.into()),
            }
        }
    }
    for service in SERVICES {
        require(
            resources
                .containers
                .get(service)
                .is_some_and(|container| !container.setup)
                && seen.contains(service),
        )?;
    }
    Ok(stopped)
}

pub(super) fn recover_runtime(
    context: &HostInputs<'_>,
    state: &mut LockedMaintenance,
    inputs: &ComposeInputs,
) -> Result<()> {
    state
        .inspection()
        .require_path_binding(context.installation)?;
    let configuration = BoundAcmeConfiguration::from_selection(state.inspection())?;
    let binding = state.journal().runtime().ok_or(REFUSED)?.clone();
    require(
        binding.profile == RuntimeProfile::Rootless
            && inputs.installation == context.installation
            && inputs.project == state.journal().compose_project(),
    )?;
    let prior = inputs.prior.as_ref().ok_or(REFUSED)?;
    successful(prior, &inputs.project, &binding.engine_id)?;
    let resources = prior.resources.as_ref().ok_or(REFUSED)?;
    for (service, image) in [
        ("openbao", context.infrastructure.image.as_str()),
        ("openbao-unseal", context.infrastructure.image.as_str()),
        (RESPONDER, context.services_image),
    ] {
        require(
            resources
                .containers
                .get(service)
                .is_some_and(|container| !container.setup && container.image == image),
        )?;
    }
    let mut selected = inputs.clone();
    selected.services = SERVICES.map(str::to_owned).into();
    let session = ComposeSession::new(context.docker, &binding, selected.clone())?;
    session.require_runtime_selection()?;
    require(
        session.model()["services"]
            .as_object()
            .ok_or(REFUSED)?
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            == SERVICES.into_iter().collect(),
    )?;
    let responder = serde_json::json!({"services": {(RESPONDER):session.model()["services"][RESPONDER].clone()}});
    responder_model(
        &responder,
        &selected,
        &configuration,
        installer_hosting::resolve(state.inspection())?
            .http01_host_port()
            .ok_or(REFUSED)?,
    )?;
    require(session.observe_resources()? == *resources)?;
    if needs_start(resources, &session.status()?)? {
        let operation = format!("infrastructure-start-{}", uuid::Uuid::new_v4().simple());
        let receipt = session.start_existing_owned(
            state,
            RuntimeOperationOwner::Acme,
            &operation,
            Duration::from_secs(120),
        )?;
        successful(&receipt, &inputs.project, &binding.engine_id)?;
        require(receipt.resources.as_ref() == Some(resources))?;
    }
    // The two OpenBao health probes above use the local Unix listener. The
    // previous HTTPS leaf may be expired; scoped recovery precedes HTTPS use.
    crate::installer_openbao_recovery::reconcile_locked(
        context.installation,
        context.docker,
        state,
        &session,
    )?;
    require(
        session.observe_resources()? == *resources && !needs_start(resources, &session.status()?)?,
    )?;
    state.require_unchanged()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::installer_compose::{ContainerIdentity, SetupExecution};
    use serde_json::json;

    fn observed() -> (ProjectResources, Vec<Value>) {
        let mut resources = ProjectResources::default();
        let mut statuses = Vec::new();
        for (index, service) in SERVICES
            .into_iter()
            .chain([CUSTODY, "application"])
            .enumerate()
        {
            let setup = service == CUSTODY;
            let id = format!("{index:02x}").repeat(32);
            resources.containers.insert(
                service.into(),
                ContainerIdentity {
                    id: id.clone(),
                    service: service.into(),
                    image: "fixture".into(),
                    config_hash: "a".repeat(64),
                    setup,
                    setup_execution: setup.then(|| SetupExecution {
                        started_at: "2026-11-01T00:00:01Z".into(),
                        finished_at: "2026-11-01T00:00:02Z".into(),
                        completed_without_restart: true,
                    }),
                    health_required: true,
                    cap_add: BTreeSet::new(),
                    cap_drop: BTreeSet::new(),
                    read_only: true,
                    memory_limit: 1024,
                },
            );
            statuses.push(json!({"Service":service,"ID":id,"State":if setup{"exited"}else{"running"},"ExitCode":0,"Health":"unhealthy"}));
        }
        (resources, statuses)
    }
    #[test]
    fn only_exact_stopped_infrastructure_requests_start_before_tls_recovery() {
        let (resources, mut statuses) = observed();
        assert!(!needs_start(&resources, &statuses).unwrap());
        // Unhealthy HTTPS does not prevent reaching the independent Unix path.
        statuses[0]["State"] = json!("exited");
        assert!(needs_start(&resources, &statuses).unwrap());
        statuses[0]["State"] = json!("running");
        statuses[4]["State"] = json!("exited");
        assert!(
            !needs_start(&resources, &statuses).unwrap(),
            "this adapter does not start application services"
        );
        for mutation in [
            "missing",
            "foreign-id",
            "setup-running",
            "duplicate",
            "dead",
        ] {
            let mut changed = statuses.clone();
            match mutation {
                "missing" => {
                    changed.remove(0);
                }
                "foreign-id" => changed[0]["ID"] = json!("f".repeat(64)),
                "setup-running" => changed[3]["State"] = json!("running"),
                "duplicate" => changed[0] = changed[1].clone(),
                "dead" => changed[0]["State"] = json!("dead"),
                _ => unreachable!(),
            }
            assert!(needs_start(&resources, &changed).is_err(), "{mutation}");
        }
    }
}
