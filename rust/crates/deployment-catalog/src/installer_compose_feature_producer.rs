//! One retained feature identity producer execution per immutable renewal plan.
//! Creation does not start the helper; only its recorded full ID may start once.
use super::*;
use crate::installer_features::generations::RenewalPermit;

const ROLE: &str = "installer-feature-identities";
const NOT_STARTED: &str = "0001-01-01T00:00:00Z";

#[derive(Clone, Copy)]
enum Stage {
    Created,
    Started,
    Completed,
}

/// Keep the complete census and all unrelated identities exact. Only the new
/// helper's execution timestamps may change after its recorded create.
fn same_producer_resources(before: &ProjectResources, current: &ProjectResources) -> bool {
    let (Some(expected), Some(observed)) =
        (before.containers.get(ROLE), current.containers.get(ROLE))
    else {
        return false;
    };
    if !expected.setup || !observed.setup {
        return false;
    }
    let mut normalized = current.clone();
    normalized.containers.get_mut(ROLE).unwrap().setup_execution = expected.setup_execution.clone();
    normalized == *before
}

fn producer_census(resources: &ProjectResources, rows: &[Value], stage: Stage) -> bool {
    let Some(helper) = resources.containers.get(ROLE) else {
        return false;
    };
    let Some(execution) = helper.setup_execution.as_ref() else {
        return false;
    };
    if !helper.setup || helper.service != ROLE {
        return false;
    }
    let mut seen = BTreeSet::new();
    rows.len() == resources.containers.len()
        && rows.iter().all(|row| {
            let Some(role) = row["Service"].as_str() else {
                return false;
            };
            let Some(identity) = resources.containers.get(role) else {
                return false;
            };
            if !seen.insert(role) || row["ID"] != identity.id {
                return false;
            }
            if role == ROLE {
                match stage {
                    Stage::Created => {
                        row["State"] == "created"
                            && execution.started_at == NOT_STARTED
                            && execution.finished_at == NOT_STARTED
                            && !execution.completed_without_restart
                    }
                    Stage::Started => {
                        ["running", "exited"].contains(&row["State"].as_str().unwrap_or(""))
                            && execution.started_at != NOT_STARTED
                    }
                    Stage::Completed => {
                        row["State"] == "exited"
                            && row["ExitCode"] == 0
                            && execution.started_at != NOT_STARTED
                            && execution.finished_at != NOT_STARTED
                            && execution.completed_without_restart
                    }
                }
            } else if identity.setup {
                row["State"] == "exited"
                    && row["ExitCode"] == 0
                    && identity
                        .setup_execution
                        .as_ref()
                        .is_some_and(|run| run.completed_without_restart)
            } else {
                ["running", "created", "exited", "restarting", "paused"]
                    .contains(&row["State"].as_str().unwrap_or(""))
            }
        })
}

fn same_started_execution(started: &ProjectResources, current: &ProjectResources) -> bool {
    if !same_producer_resources(started, current) {
        return false;
    }
    let (Some(before), Some(after)) = (
        started.containers[ROLE].setup_execution.as_ref(),
        current.containers[ROLE].setup_execution.as_ref(),
    ) else {
        return false;
    };
    before.started_at != NOT_STARTED
        && before.started_at == after.started_at
        && (before.finished_at == NOT_STARTED || before == after)
}

/// This read-only view can observe one receipt-authenticated pending producer,
/// never an arbitrary incomplete setup or a different execution of its helper.
pub(super) struct RecoveryObservation {
    expected: ProjectResources,
    started: bool,
}

impl RecoveryObservation {
    fn matches(&self, resources: &ProjectResources, rows: &[Value]) -> bool {
        if self.started {
            same_started_execution(&self.expected, resources)
                && producer_census(resources, rows, Stage::Started)
                && rows
                    .iter()
                    .find(|row| row["Service"] == ROLE)
                    .is_some_and(|row| {
                        row["State"] == "running"
                            || producer_census(resources, rows, Stage::Completed)
                    })
        } else {
            resources == &self.expected && producer_census(resources, rows, Stage::Created)
        }
    }

    pub(super) fn require(&self, resources: &ProjectResources, rows: &[Value]) -> Result<()> {
        require(self.matches(resources, rows))
    }
}

fn infrastructure_ready(
    resources: &ProjectResources,
    rows: &[Value],
    selected: &BTreeSet<String>,
) -> bool {
    !selected.is_empty()
        && selected.iter().all(|role| {
            let Some(identity) = resources.containers.get(role) else {
                return false;
            };
            let found: Vec<_> = rows.iter().filter(|row| row["Service"] == *role).collect();
            !identity.setup
                && found.len() == 1
                && found[0]["ID"] == identity.id
                && found[0]["State"] == "running"
                && (!identity.health_required || found[0]["Health"] == "healthy")
        })
}

fn infrastructure_history_count(names: &BTreeSet<String>, prefix: &str) -> Result<usize> {
    require(names.len() < 8192 && names.len().is_multiple_of(2))?;
    let count = names.len() / 2;
    let expected: BTreeSet<_> = (1..=count)
        .flat_map(|sequence| {
            [
                format!("{prefix}{sequence:06}-intent.json"),
                format!("{prefix}{sequence:06}-result.json"),
            ]
        })
        .collect();
    require(names == &expected)?;
    Ok(count)
}

impl ComposeSession {
    fn feature_producer_roles(&self, permit: &RenewalPermit) -> Result<BTreeSet<String>> {
        permit.require_session(&self.inputs, &self.model)?;
        let service = &self.model["services"][ROLE];
        require(
            (1..=999_999).contains(&permit.sequence())
                && !self.cleanup_only
                && self.runtime_recovery_roles.is_none()
                && self.generation_transition.is_none()
                && self.inputs.services == [ROLE]
                && self.inputs.profiles == ["setup"]
                && service["labels"][SETUP_LABEL] == "setup"
                && service["restart"] == "no"
                && empty(service.get("depends_on"))
                && self.prior().containers.get(ROLE).is_some_and(|old| {
                    old.setup
                        && old.image == service["image"]
                        && old
                            .setup_execution
                            .as_ref()
                            .is_some_and(|run| run.completed_without_restart)
                }),
        )?;
        Ok(BTreeSet::from([ROLE.into()]))
    }

    /// Authenticate an already successful fixed-phase receipt without invoking
    /// Docker. The owner may continue from it instead of replaying that phase.
    pub(crate) fn retained_feature_producer_receipt<'a>(
        &self,
        state: &LockedMaintenance,
        permit: &RenewalPermit,
        phase: &str,
        receipt: &'a ComposeReceipt,
    ) -> Result<&'a ProjectResources> {
        require(["create", "start", "wait"].contains(&phase))?;
        self.feature_producer_roles(permit)?;
        let operation = permit.operation(phase);
        let raw = state
            .inspection()
            .read_evidence(&format!("generation-compose-{operation}-result.json"))?;
        require(
            crate::installer_release::sha256(&raw)
                == crate::installer_jobs::receipt_digest(receipt)?
                && receipt.schema == "elevenid.installer-compose-operation/v1"
                && receipt.operation == operation
                && receipt.project == self.inputs.project
                && receipt.engine_id == self.binding.engine_id
                && receipt.configuration_sha256 == self.configuration_sha256
                && receipt.input_files == self.bindings
                && receipt.command_succeeded
                && receipt.client_exit_code == Some(0)
                && receipt.failure_class.is_none()
                && receipt.observation_validated
                && !receipt.installation_ready,
        )?;
        state.require_unchanged()?;
        receipt.resources.as_ref().ok_or_else(|| REFUSED.into())
    }

    fn feature_infrastructure_operation(
        &self,
        state: &LockedMaintenance,
        permit: &RenewalPermit,
        command: &[&str],
        selected: &BTreeSet<String>,
    ) -> Result<String> {
        let view = state.inspection();
        let directory = crate::installer_host_fs::open_child(
            view.installation_directory(),
            "evidence",
            libc::O_RDONLY | libc::O_DIRECTORY,
            REFUSED,
        )?;
        let prefix = format!("generation-compose-{}-", permit.operation("infrastructure"));
        let names: BTreeSet<_> = crate::installer_host_fs::file_names(&directory, REFUSED)?
            .into_iter()
            .filter(|name| name.starts_with(&prefix))
            .collect();
        let count = infrastructure_history_count(&names, &prefix)?;
        for sequence in 1..=count {
            let operation = permit.operation(&format!("infrastructure-{sequence:06}"));
            let intent = crate::installer_json::decode(
                &view.read_evidence(&format!("generation-compose-{operation}-intent.json"))?,
            )
            .map_err(|_| REFUSED)?;
            let receipt: ComposeReceipt = serde_json::from_value(
                crate::installer_json::decode(
                    &view.read_evidence(&format!("generation-compose-{operation}-result.json"))?,
                )
                .map_err(|_| REFUSED)?,
            )
            .map_err(|_| REFUSED)?;
            let prior: ProjectResources =
                serde_json::from_value(intent["prior_resources"].clone()).map_err(|_| REFUSED)?;
            let current = receipt.resources.as_ref().ok_or(REFUSED)?;
            let anchor = &self
                .feature_producer_observation
                .as_ref()
                .ok_or(REFUSED)?
                .expected;
            require(
                intent["schema"] == "elevenid.installer-compose-intent/v1"
                    && intent["project"] == self.inputs.project
                    && intent["engine_id"] == self.binding.engine_id
                    && intent["configuration_sha256"] == self.configuration_sha256
                    && intent["input_files"]
                        == serde_json::to_value(&self.bindings).map_err(|_| REFUSED)?
                    && intent["command"] == json!(command)
                    && intent["selected_services"] == json!(selected)
                    && intent["automatic_retry"] == false
                    && intent["installation_ready"] == false
                    && receipt.schema == "elevenid.installer-compose-operation/v1"
                    && receipt.operation == operation
                    && receipt.project == self.inputs.project
                    && receipt.engine_id == self.binding.engine_id
                    && receipt.configuration_sha256 == self.configuration_sha256
                    && receipt.input_files == self.bindings
                    && receipt.command_succeeded
                    && receipt.client_exit_code == Some(0)
                    && receipt.failure_class.is_none()
                    && receipt.observation_validated
                    && !receipt.installation_ready
                    && same_producer_resources(anchor, &prior)
                    && same_producer_resources(anchor, current)
                    && (current == &prior || same_started_execution(&prior, current))
                    && infrastructure_ready(current, &receipt.status, selected),
            )?;
        }
        state.require_unchanged()?;
        Ok(permit.operation(&format!("infrastructure-{:06}", count + 1)))
    }

    /// Recover infrastructure around one authenticated producer execution. The
    /// returned session is read-only and the caller lends it only to the local
    /// OpenBao TLS recovery owner; ordinary mutation methods reject this view.
    pub(crate) fn into_feature_producer_recovery(
        mut self,
        state: &mut LockedMaintenance,
        permit: &RenewalPermit,
        created: &ComposeReceipt,
        started: Option<&ComposeReceipt>,
    ) -> Result<Self> {
        let replacing = self.feature_producer_roles(permit)?;
        let initial = self.retained_feature_producer_receipt(state, permit, "create", created)?;
        require(
            producer_census(initial, &created.status, Stage::Created)
                && initial.containers[ROLE].id != self.prior().containers[ROLE].id,
        )?;
        let expected = if let Some(receipt) = started {
            let begun = self.retained_feature_producer_receipt(state, permit, "start", receipt)?;
            require(
                same_producer_resources(initial, begun)
                    && producer_census(begun, &receipt.status, Stage::Started),
            )?;
            begun.clone()
        } else {
            // An intent without an authenticated successful result cannot be
            // converted into a new start permission by infrastructure recovery.
            require(
                state
                    .read_evidence(&format!(
                        "generation-compose-{}-intent.json",
                        permit.operation("start")
                    ))?
                    .is_none()
                    && state
                        .read_evidence(&format!(
                            "generation-compose-{}-result.json",
                            permit.operation("start")
                        ))?
                        .is_none(),
            )?;
            initial.clone()
        };
        self.generation_transition = Some(replacing);
        self.feature_producer_observation = Some(RecoveryObservation {
            expected,
            started: started.is_some(),
        });
        let before = self.observe_resources()?;
        let selected: BTreeSet<String> = ["openbao", "openbao-unseal", "installer-acme-http01"]
            .into_iter()
            .filter(|role| before.containers.contains_key(*role))
            .map(str::to_owned)
            .collect();
        require(
            selected.contains("openbao")
                && selected.iter().all(|role| {
                    before.containers.get(role).is_some_and(|identity| {
                        !identity.setup && self.model["services"][role].is_object()
                    })
                }),
        )?;
        let mut command = vec!["start", "--wait", "--wait-timeout", "120"];
        command.extend(selected.iter().map(String::as_str));
        // Check every prior pair even when the infrastructure is already up.
        // A lost/failed response remains an owned recovery boundary.
        let operation =
            self.feature_infrastructure_operation(state, permit, &command, &selected)?;
        if infrastructure_ready(&before, &self.status()?, &selected) {
            return Ok(self);
        }
        let mut writer = Evidence::Maintenance(state, Some(RuntimeOperationOwner::Generation));
        self.generation_intent(
            &mut writer,
            &operation,
            &command,
            &before,
            &selected.iter().cloned().collect::<Vec<_>>(),
        )?;
        let result = self.compose(&command, false, Duration::from_secs(180));
        let resources = self.observe_resources();
        let statuses = self.status();
        let complete = matches!((&resources, &statuses), (Ok(current), Ok(rows))
            if (current == &before || same_started_execution(&before, current))
                && infrastructure_ready(current, rows, &selected));
        self.receipt(
            &mut writer,
            &operation,
            &result,
            complete,
            resources,
            statuses,
        )?;
        Ok(self)
    }

    pub(crate) fn create_feature_producer(
        &self,
        state: &mut LockedMaintenance,
        permit: &RenewalPermit,
    ) -> Result<ComposeReceipt> {
        let selected = self.feature_producer_roles(permit)?;
        let prior = self.prior();
        let before = self.observe_transition(false, Some(&selected))?;
        // A completed response is not adopted after a lost/uncertain create.
        // The existing intent and result remain the original owner's evidence.
        require(before == prior && generation::completed_setups(&before, &self.status()?))?;
        let operation = permit.operation("create");
        let command = [
            "up",
            "--no-build",
            "--pull",
            "never",
            "--no-deps",
            "--no-start",
            "--force-recreate",
            "--timeout",
            "60",
        ];
        let mut writer = Evidence::Maintenance(state, Some(RuntimeOperationOwner::Generation));
        self.generation_intent(
            &mut writer,
            &operation,
            &command,
            &before,
            &self.inputs.services,
        )?;
        let result = self.compose(&command, true, Duration::from_secs(180));
        let resources = self.observe_transition(false, Some(&selected));
        let statuses = self.status();
        let complete = matches!((&resources, &statuses), (Ok(current), Ok(rows))
            if current.containers.get(ROLE).is_some_and(|helper| helper.id != prior.containers[ROLE].id)
                && producer_census(current, rows, Stage::Created));
        self.receipt(
            &mut writer,
            &operation,
            &result,
            complete,
            resources,
            statuses,
        )
    }

    pub(crate) fn start_feature_producer(
        &self,
        state: &mut LockedMaintenance,
        permit: &RenewalPermit,
        created: &ComposeReceipt,
    ) -> Result<ComposeReceipt> {
        let selected = self.feature_producer_roles(permit)?;
        let expected = self.retained_feature_producer_receipt(state, permit, "create", created)?;
        require(producer_census(expected, &created.status, Stage::Created))?;
        let before = self.observe_transition(false, Some(&selected))?;
        require(before == *expected && producer_census(&before, &self.status()?, Stage::Created))?;
        let id = &before.containers[ROLE].id;
        require(id != &self.prior().containers[ROLE].id)?;
        let operation = permit.operation("start");
        let command = ["start", id.as_str()];
        let mut writer = Evidence::Maintenance(state, Some(RuntimeOperationOwner::Generation));
        self.generation_intent(
            &mut writer,
            &operation,
            &command,
            &before,
            &self.inputs.services,
        )?;
        self.recheck()?;
        // A direct start selects the recorded ID only, with no dependencies or
        // creation. Exclusive intent creation prevents a second execution.
        let result = self
            .docker
            .run_checked_with_timeout(&command, Duration::from_secs(60));
        let resources = self.observe_transition(false, Some(&selected));
        let statuses = self.status();
        let complete = matches!((&resources, &statuses), (Ok(current), Ok(rows))
            if same_producer_resources(&before, current)
                && producer_census(current, rows, Stage::Started));
        self.receipt(
            &mut writer,
            &operation,
            &result,
            complete,
            resources,
            statuses,
        )
    }

    pub(crate) fn wait_feature_producer(
        &self,
        state: &mut LockedMaintenance,
        permit: &RenewalPermit,
        created: &ComposeReceipt,
        started: &ComposeReceipt,
    ) -> Result<ComposeReceipt> {
        let selected = self.feature_producer_roles(permit)?;
        let initial = self.retained_feature_producer_receipt(state, permit, "create", created)?;
        let begun = self.retained_feature_producer_receipt(state, permit, "start", started)?;
        require(
            producer_census(initial, &created.status, Stage::Created)
                && producer_census(begun, &started.status, Stage::Started)
                && same_producer_resources(initial, begun),
        )?;
        let before = self.observe_transition(false, Some(&selected))?;
        require(
            same_started_execution(begun, &before)
                && producer_census(&before, &self.status()?, Stage::Started),
        )?;
        let id = &before.containers[ROLE].id;
        require(id != &self.prior().containers[ROLE].id)?;
        let operation = permit.operation("wait");
        let command = ["wait", id.as_str()];
        let mut writer = Evidence::Maintenance(state, Some(RuntimeOperationOwner::Generation));
        self.generation_intent(
            &mut writer,
            &operation,
            &command,
            &before,
            &self.inputs.services,
        )?;
        self.recheck()?;
        // Waiting never starts, stops, recreates, or replays the producer.
        let result = self
            .docker
            .run_checked_with_timeout(&command, Duration::from_secs(MAX_WAIT));
        let resources = self.observe_transition(false, Some(&selected));
        let statuses = self.status();
        let complete = matches!((&resources, &statuses), (Ok(current), Ok(rows))
            if same_started_execution(begun, current)
                && producer_census(current, rows, Stage::Completed));
        self.receipt(
            &mut writer,
            &operation,
            &result,
            complete,
            resources,
            statuses,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(stage: Stage) -> (ProjectResources, Vec<Value>) {
        let (status, started, finished, complete) = match stage {
            Stage::Created => ("created", NOT_STARTED, NOT_STARTED, false),
            Stage::Started => ("running", "2026-11-26T00:00:00Z", NOT_STARTED, false),
            Stage::Completed => (
                "exited",
                "2026-11-26T00:00:00Z",
                "2026-11-26T00:00:01Z",
                true,
            ),
        };
        let helper = ContainerIdentity {
            id: "a".repeat(64),
            service: ROLE.into(),
            image: format!("example.invalid/services@sha256:{}", "b".repeat(64)),
            config_hash: "c".repeat(64),
            setup: true,
            setup_execution: Some(SetupExecution {
                started_at: started.into(),
                finished_at: finished.into(),
                completed_without_restart: complete,
            }),
            health_required: false,
            cap_add: BTreeSet::new(),
            cap_drop: BTreeSet::from(["ALL".into()]),
            read_only: true,
            memory_limit: 268435456,
        };
        let runtime = ContainerIdentity {
            id: "d".repeat(64),
            service: "openbao".into(),
            setup: false,
            setup_execution: None,
            ..helper.clone()
        };
        let resources = ProjectResources {
            containers: BTreeMap::from([
                (ROLE.into(), helper.clone()),
                ("openbao".into(), runtime.clone()),
            ]),
            networks: BTreeMap::from([("project_default".into(), "e".repeat(64))]),
            volumes: BTreeSet::new(),
        };
        (
            resources,
            vec![
                json!({"Service":ROLE,"ID":helper.id,"State":status,"ExitCode":0}),
                json!({"Service":"openbao","ID":runtime.id,"State":"running","Health":"healthy"}),
            ],
        )
    }

    #[test]
    fn exact_created_started_completed_sequence_preserves_all_other_resources() {
        let (created, create_rows) = fixture(Stage::Created);
        let (started, start_rows) = fixture(Stage::Started);
        let (completed, complete_rows) = fixture(Stage::Completed);
        assert!(producer_census(&created, &create_rows, Stage::Created));
        assert!(producer_census(&started, &start_rows, Stage::Started));
        assert!(producer_census(
            &completed,
            &complete_rows,
            Stage::Completed
        ));
        assert!(same_producer_resources(&created, &started));
        assert!(same_started_execution(&started, &completed));
        assert!(!producer_census(&started, &start_rows, Stage::Created));
        assert!(!producer_census(&created, &create_rows, Stage::Started));
        assert!(!producer_census(&started, &start_rows, Stage::Completed));
    }

    #[test]
    fn changed_id_configuration_neighbor_or_resource_cannot_be_adopted() {
        let (before, _) = fixture(Stage::Created);
        let (current, _) = fixture(Stage::Started);
        for case in [
            "id", "image", "config", "neighbor", "network", "volume", "role",
        ] {
            let mut changed = current.clone();
            match case {
                "id" => changed.containers.get_mut(ROLE).unwrap().id = "f".repeat(64),
                "image" => {
                    changed.containers.get_mut(ROLE).unwrap().image = "another:latest".into()
                }
                "config" => changed.containers.get_mut(ROLE).unwrap().config_hash = "f".repeat(64),
                "neighbor" => changed.containers.get_mut("openbao").unwrap().id = "f".repeat(64),
                "network" => {
                    changed
                        .networks
                        .insert("project_default".into(), "f".repeat(64));
                }
                "volume" => {
                    changed.volumes.insert("unrecorded_volume".into());
                }
                _ => changed.containers.get_mut(ROLE).unwrap().setup = false,
            }
            assert!(!same_producer_resources(&before, &changed), "{case}");
        }
    }

    #[test]
    fn duplicate_rows_failed_exit_restart_or_second_execution_refuse() {
        let (started, _) = fixture(Stage::Started);
        let (completed, rows) = fixture(Stage::Completed);
        let mut duplicate = rows.clone();
        duplicate[1] = duplicate[0].clone();
        assert!(!producer_census(&completed, &duplicate, Stage::Completed));
        for state in ["created", "paused", "restarting", "dead", "removing"] {
            let mut changed = rows.clone();
            changed[0]["State"] = json!(state);
            assert!(!producer_census(&completed, &changed, Stage::Completed));
        }
        let mut nonzero = rows.clone();
        nonzero[0]["ExitCode"] = json!(1);
        assert!(!producer_census(&completed, &nonzero, Stage::Completed));
        let mut restarted = completed.clone();
        restarted
            .containers
            .get_mut(ROLE)
            .unwrap()
            .setup_execution
            .as_mut()
            .unwrap()
            .completed_without_restart = false;
        assert!(!producer_census(&restarted, &rows, Stage::Completed));
        let mut repeated = completed.clone();
        repeated
            .containers
            .get_mut(ROLE)
            .unwrap()
            .setup_execution
            .as_mut()
            .unwrap()
            .started_at = "2026-11-26T00:00:01Z".into();
        assert!(!same_started_execution(&started, &repeated));
        let mut changed_finish = completed.clone();
        changed_finish
            .containers
            .get_mut(ROLE)
            .unwrap()
            .setup_execution
            .as_mut()
            .unwrap()
            .finished_at = "2026-11-26T00:00:02Z".into();
        assert!(!same_started_execution(&completed, &changed_finish));
    }

    #[test]
    fn cold_recovery_keeps_pending_created_helper_unexecuted_and_census_exact() {
        let (created, mut rows) = fixture(Stage::Created);
        let observation = RecoveryObservation {
            expected: created.clone(),
            started: false,
        };
        rows[1]["State"] = json!("exited");
        observation.require(&created, &rows).unwrap();
        let selected = BTreeSet::from(["openbao".into()]);
        assert!(!infrastructure_ready(&created, &rows, &selected));
        rows[1]["State"] = json!("running");
        assert!(observation.matches(&created, &rows));
        assert!(infrastructure_ready(&created, &rows, &selected));
        assert!(!infrastructure_ready(
            &created,
            &rows,
            &BTreeSet::from([ROLE.into()])
        ));
        let (started, start_rows) = fixture(Stage::Started);
        assert!(!observation.matches(&started, &start_rows));
        for role in [ROLE, "openbao"] {
            let mut changed = created.clone();
            changed.containers.get_mut(role).unwrap().id = "f".repeat(64);
            assert!(!observation.matches(&changed, &rows));
        }
        let mut changed = created;
        changed.volumes.insert("unrecorded".into());
        assert!(!observation.matches(&changed, &rows));
    }

    #[test]
    fn started_recovery_view_accepts_only_the_original_execution_finishing() {
        let (started, rows) = fixture(Stage::Started);
        let observation = RecoveryObservation {
            expected: started.clone(),
            started: true,
        };
        observation.require(&started, &rows).unwrap();
        let (completed, complete_rows) = fixture(Stage::Completed);
        assert!(observation.matches(&completed, &complete_rows));
        let mut failed = complete_rows.clone();
        failed[0]["ExitCode"] = json!(1);
        assert!(!observation.matches(&completed, &failed));
        let mut unqualified = completed.clone();
        unqualified
            .containers
            .get_mut(ROLE)
            .unwrap()
            .setup_execution
            .as_mut()
            .unwrap()
            .completed_without_restart = false;
        assert!(!observation.matches(&unqualified, &complete_rows));
        let mut changed = completed;
        changed
            .containers
            .get_mut(ROLE)
            .unwrap()
            .setup_execution
            .as_mut()
            .unwrap()
            .started_at = "2026-11-26T00:00:02Z".into();
        assert!(!observation.matches(&changed, &complete_rows));
        let (created, create_rows) = fixture(Stage::Created);
        assert!(!observation.matches(&created, &create_rows));
        let mut paused = rows;
        paused[0]["State"] = json!("paused");
        assert!(!observation.matches(&started, &paused));
    }

    #[test]
    fn infrastructure_recovery_history_never_advances_an_unpaired_attempt() {
        let prefix = "generation-compose-feature-000001-infrastructure-";
        assert_eq!(
            infrastructure_history_count(&BTreeSet::new(), prefix).unwrap(),
            0
        );
        let complete = BTreeSet::from([
            format!("{prefix}000001-intent.json"),
            format!("{prefix}000001-result.json"),
        ]);
        assert_eq!(infrastructure_history_count(&complete, prefix).unwrap(), 1);
        for invalid in [
            BTreeSet::from([format!("{prefix}000001-intent.json")]),
            BTreeSet::from([format!("{prefix}000001-result.json")]),
            BTreeSet::from([
                format!("{prefix}000002-intent.json"),
                format!("{prefix}000002-result.json"),
            ]),
            BTreeSet::from([
                format!("{prefix}000001-intent.json"),
                format!("{prefix}000001-other.json"),
            ]),
        ] {
            assert!(infrastructure_history_count(&invalid, prefix).is_err());
        }
    }
}
