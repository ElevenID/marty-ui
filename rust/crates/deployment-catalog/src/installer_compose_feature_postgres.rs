//! Fixed retained-container recovery for the feature PostgreSQL TLS owner.
//! No SQL, credentials, container creation, or public database listener is used.
use super::*;

const ROLES: [&str; 2] = ["postgres", "installer-ingress"];
const PREFIX: &str = "feature-postgres-carrier-compose-";

fn role_state<'a>(rows: &'a [Value], role: &str, id: &str) -> Result<&'a str> {
    let matches: Vec<_> = rows.iter().filter(|row| row["Service"] == role).collect();
    require(matches.len() == 1 && matches[0]["ID"] == id)?;
    let state = matches[0]["State"].as_str().ok_or(REFUSED)?;
    require(["running", "created", "exited"].contains(&state))?;
    Ok(state)
}

fn next_start_operation(state: &LockedMaintenance) -> Result<String> {
    let view = state.inspection();
    let directory = crate::installer_host_fs::open_child(
        view.installation_directory(),
        "evidence",
        libc::O_RDONLY | libc::O_DIRECTORY,
        REFUSED,
    )?;
    let names: BTreeSet<_> = crate::installer_host_fs::file_names(&directory, REFUSED)?
        .into_iter()
        .filter(|name| name.starts_with(PREFIX))
        .collect();
    require(names.len() < 8192 && names.len().is_multiple_of(2))?;
    let count = names.len() / 2;
    let expected: BTreeSet<_> = (1..=count)
        .flat_map(|sequence| {
            [
                format!("{PREFIX}start-{sequence:06}-intent.json"),
                format!("{PREFIX}start-{sequence:06}-result.json"),
            ]
        })
        .collect();
    require(names == expected)?;
    for sequence in 1..=count {
        let operation = format!("start-{sequence:06}");
        let intent = crate::installer_json::decode(
            &view.read_evidence(&format!("{PREFIX}{operation}-intent.json"))?,
        )
        .map_err(|_| REFUSED)?;
        let receipt: ComposeReceipt = serde_json::from_value(
            crate::installer_json::decode(
                &view.read_evidence(&format!("{PREFIX}{operation}-result.json"))?,
            )
            .map_err(|_| REFUSED)?,
        )
        .map_err(|_| REFUSED)?;
        require(
            intent["schema"] == "elevenid.installer-compose-intent/v1"
                && intent["project"] == view.journal().compose_project()
                && intent["engine_id"] == view.journal().runtime().ok_or(REFUSED)?.engine_id
                && intent["selected_services"] == json!(ROLES)
                && receipt.schema == "elevenid.installer-compose-operation/v1"
                && receipt.operation == operation
                && receipt.project == view.journal().compose_project()
                && receipt.engine_id == view.journal().runtime().ok_or(REFUSED)?.engine_id
                && intent["configuration_sha256"] == receipt.configuration_sha256
                && intent["input_files"]
                    == serde_json::to_value(&receipt.input_files).map_err(|_| REFUSED)?
                && receipt.command_succeeded
                && receipt.observation_validated
                && receipt.client_exit_code == Some(0)
                && receipt.failure_class.is_none()
                && !receipt.installation_ready,
        )?;
    }
    state.require_unchanged()?;
    Ok(format!("start-{:06}", count + 1))
}

impl ComposeSession {
    fn feature_postgres_owned(&self) -> Result<ProjectResources> {
        require(
            crate::installer_features::for_inputs(&self.inputs)?.is_some()
                && self.inputs.services == ROLES
                && !self.cleanup_only
                && self.generation_transition.is_none()
                && self.runtime_recovery_roles.is_none(),
        )?;
        let configuration =
            crate::installer_json::decode(&crate::installer_verify::read_private_bytes(
                &self
                    .inputs
                    .installation
                    .join("evidence/lifecycle-configuration.json"),
                65_536,
            )?)
            .map_err(|_| REFUSED)?;
        require(
            configuration["schema"] == "elevenid.installer-lifecycle-configuration/v2"
                && configuration["compose_project"] == self.inputs.project
                && configuration["runtime"]["engine_id"] == self.binding.engine_id
                && configuration["operator_sha256"]
                    == crate::installer_verify::operator_digest(
                        &self.inputs.installation.join("marty-deploy"),
                    )?,
        )?;
        let resources = self.observe_resources()?;
        for role in ROLES {
            let identity = resources.containers.get(role).ok_or(REFUSED)?;
            require(!identity.setup && self.prior().containers.get(role) == Some(identity))?;
        }
        Ok(resources)
    }

    /// Start only these two exact retained IDs, without a health-based wait.
    /// The expired public ingress certificate may make its HTTPS probe fail;
    /// the process is sufficient for the independent PostgreSQL TLS check.
    pub(crate) fn start_feature_postgres_carrier(
        &self,
        state: &mut LockedMaintenance,
    ) -> Result<()> {
        let operation = next_start_operation(state)?;
        let before = self.feature_postgres_owned()?;
        let rows = self.status()?;
        for (role, identity) in &before.containers {
            if identity.setup {
                let found: Vec<_> = rows.iter().filter(|row| row["Service"] == *role).collect();
                require(
                    found.len() == 1
                        && found[0]["ID"] == identity.id
                        && found[0]["State"] == "exited"
                        && found[0]["ExitCode"] == 0,
                )?;
            }
        }
        let mut command = vec!["start"];
        for role in ROLES {
            let identity = &before.containers[role];
            if role_state(&rows, role, &identity.id)? != "running" {
                command.push(identity.id.as_str());
            }
        }
        if command.len() == 1 {
            return Ok(());
        }
        let mut evidence =
            Evidence::Maintenance(state, Some(RuntimeOperationOwner::FeaturePostgres));
        self.begin(&mut evidence, &operation, &command)?;
        // Direct Docker start has no dependency traversal and cannot create or
        // recreate a container. IDs come only from this admitted prior session.
        let result = self
            .docker
            .run_checked_with_timeout(&command, Duration::from_secs(30));
        let resources = self.observe_resources();
        let status = self.status();
        let running = matches!((&resources, &status), (Ok(current), Ok(rows))
            if *current == before && ROLES.into_iter().all(|role|
                role_state(rows, role, &before.containers[role].id).is_ok_and(|state| state == "running")));
        self.receipt(
            &mut evidence,
            &operation,
            &result,
            running,
            resources,
            status,
        )?;
        Ok(())
    }

    pub(crate) fn feature_postgres_probe_ready(&self) -> Result<()> {
        let resources = self.feature_postgres_owned()?;
        let rows = self.status()?;
        for role in ROLES {
            require(role_state(&rows, role, &resources.containers[role].id)? == "running")?;
        }
        Ok(())
    }

    pub(crate) fn reload_feature_postgres(&self) -> Result<()> {
        self.feature_postgres_probe_ready()?;
        let before = self.observe_resources()?;
        let id = &before.containers.get("postgres").ok_or(REFUSED)?.id;
        self.docker.reload_feature_postgres_tls(id)?;
        require(self.observe_resources()? == before)
    }

    pub(crate) fn bounded_feature_postgres_renewal(mut self) -> Self {
        // Every Docker endpoint check, ownership census, HUP and TLS exec shares
        // this total deadline; per-call limits cannot extend the transaction.
        self.docker = self
            .docker
            .with_deadline(Instant::now() + Duration::from_secs(60));
        self
    }

    pub(crate) fn probe_feature_postgres(&self, expected_der_sha256: &str) -> Result<()> {
        require(digest(expected_der_sha256))?;
        self.feature_postgres_probe_ready()?;
        let before = self.observe_resources()?;
        let id = &before
            .containers
            .get("installer-ingress")
            .ok_or(REFUSED)?
            .id;
        let deadline = Instant::now() + Duration::from_secs(30);
        // HUP is asynchronous. Retry only this same authenticated container and
        // the newly issued fingerprint, within one fixed convergence deadline.
        loop {
            require(self.feature_postgres_owned()? == before)?;
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or(REFUSED)?;
            let result = self.docker.probe_feature_postgres_tls(
                id,
                expected_der_sha256,
                remaining.min(Duration::from_secs(10)),
            );
            require(self.feature_postgres_owned()? == before)?;
            if result.is_ok() {
                return Ok(());
            }
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or(REFUSED)?;
            std::thread::sleep(remaining.min(Duration::from_millis(250)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn carrier_selection_requires_one_exact_retained_id_and_a_startable_state() {
        let id = "a".repeat(64);
        for accepted in ["running", "created", "exited"] {
            let rows = [json!({"Service":"installer-ingress","ID":id,"State":accepted})];
            assert_eq!(
                role_state(&rows, "installer-ingress", &id).unwrap(),
                accepted
            );
        }
        for rejected in ["paused", "restarting", "dead", "removing", "unknown"] {
            let rows = [json!({"Service":"installer-ingress","ID":id,"State":rejected})];
            assert!(role_state(&rows, "installer-ingress", &id).is_err());
        }
        let row = json!({"Service":"installer-ingress","ID":id,"State":"running"});
        assert!(role_state(&[row.clone(), row.clone()], "installer-ingress", &id).is_err());
        assert!(role_state(std::slice::from_ref(&row), "flow", &id).is_err());
        assert!(role_state(&[row], "installer-ingress", &"b".repeat(64)).is_err());
        assert!(role_state(&[], "installer-ingress", &id).is_err());
    }
}
