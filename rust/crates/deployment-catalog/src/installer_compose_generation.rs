//! Native create/start/observe operations reserved for immutable generations.
//! A credential producer is created and its full ID retained before it starts.
use super::*;

impl ComposeSession {
    fn generation_roles(&self, operation: GenerationOperation) -> Result<BTreeSet<String>> {
        require(
            !self.cleanup_only
                && self.runtime_recovery_roles.is_none()
                && self.generation_transition.is_none()
                && self.inputs.prior.is_some(),
        )?;
        let selected: BTreeSet<_> = self.inputs.services.iter().cloned().collect();
        require(!selected.is_empty() && selected.len() == self.inputs.services.len())?;
        match operation {
            GenerationOperation::Candidate => {
                let service = &self.model["services"]["installer-generation"];
                let installation = self
                    .inputs
                    .project
                    .trim_start_matches("marty-install-")
                    .parse::<uuid::Uuid>()
                    .map_err(|_| REFUSED)?
                    .to_string();
                require(
                    self.inputs.services == ["installer-generation"]
                        && self.inputs.profiles == ["setup"]
                        && service["labels"][SETUP_LABEL] == "setup"
                        && service["restart"] == "no"
                        && service["entrypoint"] == json!(["/input/marty-deploy"])
                        && service["command"]
                            == json!([
                                "installer-generation-provision-transfer",
                                "--installation-id",
                                installation
                            ])
                        && empty(service.get("depends_on"))
                        && self
                            .prior()
                            .containers
                            .get("installer-generation")
                            .is_some_and(|prior| {
                                prior.setup
                                    && prior.image == service["image"]
                                    && prior.setup_execution.as_ref().is_some_and(|execution| {
                                        execution.completed_without_restart
                                    })
                            }),
                )?;
            }
            GenerationOperation::Activate => {
                require(self.inputs.profiles.is_empty())?;
                self.require_runtime_selection()?;
                for role in &selected {
                    let prior = self.prior().containers.get(role).cloned().ok_or(REFUSED)?;
                    require(!prior.setup && self.model["services"][role]["image"] == prior.image)?;
                }
            }
        }
        Ok(selected)
    }

    /// Every unselected object keeps its full ID. A selected object may be the
    /// old ID, absent during create, or exactly the new model. No new network,
    /// volume, image, setup dependency, or neighboring service is admitted.
    pub(crate) fn observe_generation_transition(
        &self,
        operation: GenerationOperation,
    ) -> Result<ProjectResources> {
        self.observe_transition(false, Some(&self.generation_roles(operation)?))
    }

    /// Lend only a read-only mixed-ID view to the existing local OpenBao
    /// recovery owner. The normal mutation entry points reject this view.
    pub(crate) fn into_generation_observation(mut self, kind: GenerationOperation) -> Result<Self> {
        let replacing = self.generation_roles(kind)?;
        self.observe_transition(false, Some(&replacing))?;
        self.generation_transition = Some(replacing);
        Ok(self)
    }

    /// Service hashes do not cover referenced top-level declarations. Keep
    /// this comparison read-only so retained activation receipts enforce the
    /// same effective credential selection without invoking Docker.
    pub(crate) fn generation_reference_changes(
        previous_model: &Value,
        model: &Value,
    ) -> Result<BTreeSet<String>> {
        let mut changed = BTreeSet::new();
        for (role, service) in model["services"].as_object().ok_or(REFUSED)? {
            require(previous_model["services"][role].is_object())?;
            for kind in ["secrets", "configs"] {
                let Some(references) = service.get(kind) else {
                    continue;
                };
                for reference in references.as_array().ok_or(REFUSED)? {
                    let name = reference["source"].as_str().ok_or(REFUSED)?;
                    require(
                        model[kind][name].is_object() && previous_model[kind][name].is_object(),
                    )?;
                    if model[kind][name] != previous_model[kind][name] {
                        changed.insert(role.clone());
                    }
                }
            }
        }
        Ok(changed)
    }

    pub(crate) fn changed_generation_services(
        &self,
        previous_model: &Value,
    ) -> Result<Vec<String>> {
        require(
            !self.cleanup_only
                && self.generation_transition.is_none()
                && self.inputs.profiles.is_empty(),
        )?;
        let prior = self.prior();
        let services = self.model["services"].as_object().ok_or(REFUSED)?;
        require(services.keys().all(|role| {
            prior
                .containers
                .get(role)
                .is_some_and(|old| !old.setup && self.model["services"][role]["image"] == old.image)
        }))?;
        let referenced_changed = Self::generation_reference_changes(previous_model, &self.model)?;
        let mut changed = Vec::new();
        for role in services.keys() {
            if referenced_changed.contains(role)
                || self.hashes.get(role) != prior.containers.get(role).map(|old| &old.config_hash)
            {
                changed.push(role.clone());
            }
        }
        Ok(changed)
    }

    /// Cold recovery starts only existing infrastructure. In particular, the
    /// candidate setup is never included even when its create/start is pending.
    pub(crate) fn start_generation_infrastructure(
        &self,
        state: &mut LockedMaintenance,
        operation: &str,
        kind: GenerationOperation,
    ) -> Result<ComposeReceipt> {
        let replacing = self.generation_roles(kind)?;
        let before = self.observe_transition(false, Some(&replacing))?;
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
        let mut writer = Evidence::Maintenance(state, Some(RuntimeOperationOwner::Generation));
        let mut command = vec!["start", "--wait", "--wait-timeout", "120"];
        command.extend(selected.iter().map(String::as_str));
        self.generation_intent(
            &mut writer,
            operation,
            &command,
            &before,
            &selected.iter().cloned().collect::<Vec<_>>(),
        )?;
        let result = self.compose(&command, false, Duration::from_secs(180));
        let resources = self.observe_transition(false, Some(&replacing));
        let statuses = self.status();
        let complete = matches!((&resources, &statuses), (Ok(resources), Ok(rows)) if generation_runtime_observation(resources, rows, &selected, &replacing, false));
        self.receipt(
            &mut writer,
            operation,
            &result,
            complete,
            resources,
            statuses,
        )
    }

    /// Pause/seal stops only the retained runtime census. It does not create,
    /// start, or stop a credential producer; the owner first waits an in-flight
    /// producer to its retained terminal execution, without replaying it.
    pub(crate) fn stop_generation_runtime(
        &self,
        state: &mut LockedMaintenance,
        operation: &str,
        kind: GenerationOperation,
    ) -> Result<ComposeReceipt> {
        let replacing = self.generation_roles(kind)?;
        let before = self.observe_transition(false, Some(&replacing))?;
        let statuses = self.status()?;
        require(statuses.iter().all(|row| {
            row["Service"]
                .as_str()
                .and_then(|role| before.containers.get(role))
                .is_some_and(|identity| {
                    !identity.setup
                        || ["created", "exited"].contains(&row["State"].as_str().unwrap_or(""))
                })
        }))?;
        let selected: BTreeSet<_> = before
            .containers
            .iter()
            .filter(|(_, identity)| !identity.setup)
            .map(|(role, _)| role.clone())
            .collect();
        require(!selected.is_empty())?;
        let mut command = vec!["stop", "--timeout", "60"];
        command.extend(selected.iter().map(String::as_str));
        let mut writer = Evidence::Maintenance(state, Some(RuntimeOperationOwner::Generation));
        self.generation_intent(
            &mut writer,
            operation,
            &command,
            &before,
            &selected.iter().cloned().collect::<Vec<_>>(),
        )?;
        let result = self.compose(&command, false, Duration::from_secs(300));
        let resources = self.observe_transition(false, Some(&replacing));
        let statuses = self.status();
        let complete = matches!((&resources, &statuses), (Ok(resources), Ok(rows)) if generation_runtime_observation(resources, rows, &selected, &replacing, true));
        self.receipt(
            &mut writer,
            operation,
            &result,
            complete,
            resources,
            statuses,
        )
    }

    /// A preparation without a helper intent has no replacement authority.
    /// Stop its exact retained runtime census without allowing even a single
    /// changed or missing container ID through a generation transition view.
    pub(crate) fn stop_retained_generation_runtime(
        &self,
        state: &mut LockedMaintenance,
        operation: &str,
    ) -> Result<ComposeReceipt> {
        require(
            !self.cleanup_only
                && self.generation_transition.is_none()
                && self.inputs.prior.is_some()
                && self.inputs.services.is_empty(),
        )?;
        let before = self.observe(false)?;
        require(completed_setups(&before, &self.status()?))?;
        let selected: BTreeSet<_> = before
            .containers
            .iter()
            .filter(|(_, identity)| !identity.setup)
            .map(|(role, _)| role.clone())
            .collect();
        require(!selected.is_empty())?;
        let mut command = vec!["stop", "--timeout", "60"];
        command.extend(selected.iter().map(String::as_str));
        let mut writer = Evidence::Maintenance(state, Some(RuntimeOperationOwner::Generation));
        self.generation_intent(
            &mut writer,
            operation,
            &command,
            &before,
            &selected.iter().cloned().collect::<Vec<_>>(),
        )?;
        let result = self.compose(&command, false, Duration::from_secs(300));
        let resources = self.observe(false);
        let statuses = self.status();
        let complete = matches!((&resources, &statuses), (Ok(resources), Ok(rows))
            if generation_runtime_observation(resources, rows, &selected, &BTreeSet::new(), true));
        self.receipt(
            &mut writer,
            operation,
            &result,
            complete,
            resources,
            statuses,
        )
    }

    /// Quiesce only the already-authorized replacement consumers before a
    /// stale-attempt baseline is captured. Infrastructure and all setup jobs
    /// are excluded. A missing consumer is completed later with no-start.
    pub(crate) fn stop_generation_consumers(
        &self,
        state: &mut LockedMaintenance,
        operation: &str,
    ) -> Result<Option<ComposeReceipt>> {
        let replacing = self.generation_roles(GenerationOperation::Activate)?;
        require(replacing.iter().all(|role| {
            !["openbao", "openbao-unseal", "installer-acme-http01"].contains(&role.as_str())
        }))?;
        let before = self.observe_transition(false, Some(&replacing))?;
        let rows = self.status()?;
        require(completed_setups(&before, &rows))?;
        let selected: BTreeSet<_> = replacing
            .iter()
            .filter(|role| before.containers.contains_key(*role))
            .cloned()
            .collect();
        if selected.is_empty() {
            return Ok(None);
        }
        let mut command = vec!["stop", "--timeout", "60"];
        command.extend(selected.iter().map(String::as_str));
        let mut writer = Evidence::Maintenance(state, Some(RuntimeOperationOwner::Generation));
        self.generation_intent(
            &mut writer,
            operation,
            &command,
            &before,
            &selected.iter().cloned().collect::<Vec<_>>(),
        )?;
        let result = self.compose(&command, false, Duration::from_secs(300));
        let resources = self.observe_transition(false, Some(&replacing));
        let statuses = self.status();
        let complete = matches!((&resources, &statuses), (Ok(resources), Ok(rows))
            if generation_runtime_observation(resources, rows, &selected, &replacing, true));
        self.receipt(
            &mut writer,
            operation,
            &result,
            complete,
            resources,
            statuses,
        )
        .map(Some)
    }

    /// Record an exact owned census for supersession. Runtime services may be
    /// stopped; this is a native read, never an activation or health claim.
    /// The caller authenticates the preceding create-only transaction first.
    pub(crate) fn checkpoint_generation_baseline(
        mut self,
        state: &mut LockedMaintenance,
        operation: &str,
        stopped: &BTreeSet<String>,
    ) -> Result<ComposeReceipt> {
        require(
            !self.cleanup_only
                && self.generation_transition.is_none()
                && self.inputs.prior.is_some()
                && self.inputs.services.is_empty()
                && stopped.iter().all(|role| {
                    self.prior()
                        .containers
                        .get(role)
                        .is_some_and(|identity| !identity.setup)
                        && !["openbao", "openbao-unseal", "installer-acme-http01"]
                            .contains(&role.as_str())
                }),
        )?;
        self.observe(false)?;
        self.bindings = self.generation_checkpoint_bindings()?;
        self.recheck()?;
        let mut writer = Evidence::Maintenance(state, Some(RuntimeOperationOwner::Generation));
        self.begin(
            &mut writer,
            operation,
            &["ps", "--all", "--no-trunc", "--format", "json"],
        )?;
        let resources = self.observe(false);
        let statuses = self.status();
        let result = statuses
            .as_ref()
            .map(|_| String::new())
            .map_err(Clone::clone);
        let complete = matches!((&resources, &statuses), (Ok(resources), Ok(rows))
            if generation_baseline_observation(resources, rows, stopped));
        self.receipt(
            &mut writer,
            operation,
            &result,
            complete,
            resources,
            statuses,
        )
    }

    fn generation_intent(
        &self,
        writer: &mut Evidence<'_>,
        operation: &str,
        command: &[&str],
        before: &ProjectResources,
        selected: &[String],
    ) -> Result<()> {
        self.write(
            writer,
            operation,
            "intent",
            &json!({
                "schema":"elevenid.installer-compose-intent/v1", "project":self.inputs.project,
                "engine_id":self.binding.engine_id,"configuration_sha256":self.configuration_sha256,
                "input_files":self.bindings,"command":command,"prior_resources":before,
                "selected_services":selected,"automatic_retry":false,"installation_ready":false,
            }),
        )
    }

    /// Create without starting. A resumed transaction selects only old or
    /// missing IDs; an already-created replacement is never recreated.
    pub(crate) fn create_generation_replacements(
        &self,
        state: &mut LockedMaintenance,
        operation: &str,
        kind: GenerationOperation,
    ) -> Result<ComposeReceipt> {
        let selected = self.generation_roles(kind)?;
        let before = self.observe_transition(false, Some(&selected))?;
        let prior = self.prior();
        let remaining: Vec<_> = selected
            .iter()
            .filter(|role| {
                before.containers.get(*role).is_none_or(|current| {
                    prior
                        .containers
                        .get(*role)
                        .is_some_and(|old| old.id == current.id)
                })
            })
            .cloned()
            .collect();
        require(!remaining.is_empty())?;
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
        self.generation_intent(&mut writer, operation, &command, &before, &remaining)?;
        self.recheck()?;
        let mut arguments = self.arguments(&command, false)?;
        arguments.extend(remaining);
        let result = self.docker.run_checked_with_timeout(
            &arguments.iter().map(String::as_str).collect::<Vec<_>>(),
            Duration::from_secs(180),
        );
        self.recheck()?;
        let resources = self.observe_transition(false, Some(&selected));
        let statuses = self.status();
        let complete = matches!((&resources, &statuses), (Ok(resources), Ok(rows))
            if generation_created(resources, rows, &prior, &selected));
        self.receipt(
            &mut writer,
            operation,
            &result,
            complete,
            resources,
            statuses,
        )
    }

    /// Record a real native read after a lost create response. The original
    /// uncertain command receipt is preserved as a separate historical fact.
    pub(crate) fn observe_created_generation(
        &self,
        state: &mut LockedMaintenance,
        operation: &str,
        kind: GenerationOperation,
    ) -> Result<ComposeReceipt> {
        let selected = self.generation_roles(kind)?;
        let resources = self.observe_transition(false, Some(&selected));
        let statuses = self.status();
        let complete = matches!((&resources, &statuses), (Ok(resources), Ok(rows))
            if generation_created(resources, rows, &self.prior(), &selected));
        require(complete)?;
        let mut writer = Evidence::Maintenance(state, Some(RuntimeOperationOwner::Generation));
        self.generation_intent(
            &mut writer,
            operation,
            &["ps", "--all", "--no-trunc", "--format", "json"],
            &self.prior(),
            &self.inputs.services,
        )?;
        self.receipt(
            &mut writer,
            operation,
            &Ok(String::new()),
            complete,
            resources,
            statuses,
        )
    }

    /// Only a never-started, retained replacement ID may start. A running or
    /// exited producer is waited/observed, so a lost response never remints.
    pub(crate) fn start_generation_candidate(
        &self,
        state: &mut LockedMaintenance,
        operation: &str,
        container_id: &str,
    ) -> Result<ComposeReceipt> {
        let selected = self.generation_roles(GenerationOperation::Candidate)?;
        let before = self.observe_transition(false, Some(&selected))?;
        let identity = before
            .containers
            .get("installer-generation")
            .ok_or(REFUSED)?;
        require(
            identity.id == container_id
                && identity.id != self.prior().containers["installer-generation"].id,
        )?;
        let rows = self.status()?;
        require(
            rows.iter()
                .filter(|row| row["Service"] == "installer-generation")
                .count()
                == 1
                && rows.iter().any(|row| {
                    row["Service"] == "installer-generation"
                        && row["ID"] == container_id
                        && row["State"] == "created"
                }),
        )?;
        let mut writer = Evidence::Maintenance(state, Some(RuntimeOperationOwner::Generation));
        let command = ["start", "installer-generation"];
        self.generation_intent(
            &mut writer,
            operation,
            &command,
            &before,
            &self.inputs.services,
        )?;
        let result = self.compose(&command, false, Duration::from_secs(60));
        let resources = self.observe_transition(false, Some(&selected));
        let statuses = self.status();
        let complete = matches!((&resources, &statuses), (Ok(resources), Ok(rows))
            if resources.containers.get("installer-generation").is_some_and(|identity| identity.id == container_id)
                && rows.iter().any(|row| row["Service"] == "installer-generation" && row["ID"] == container_id && ["running","exited"].contains(&row["State"].as_str().unwrap_or(""))));
        self.receipt(
            &mut writer,
            operation,
            &result,
            complete,
            resources,
            statuses,
        )
    }

    /// Waiting changes no container state. A timeout leaves the same helper and
    /// output directory available for the next invocation under the same lock.
    pub(crate) fn wait_generation_candidate(
        &self,
        state: &mut LockedMaintenance,
        operation: &str,
        container_id: &str,
    ) -> Result<ComposeReceipt> {
        let selected = self.generation_roles(GenerationOperation::Candidate)?;
        let before = self.observe_transition(false, Some(&selected))?;
        require(
            before
                .containers
                .get("installer-generation")
                .is_some_and(|identity| {
                    identity.id == container_id
                        && self.prior().containers["installer-generation"].id != container_id
                }),
        )?;
        let statuses = self.status()?;
        require(statuses.iter().any(|row| {
            row["Service"] == "installer-generation"
                && row["ID"] == container_id
                && ["running", "exited"].contains(&row["State"].as_str().unwrap_or(""))
        }))?;
        let mut writer = Evidence::Maintenance(state, Some(RuntimeOperationOwner::Generation));
        let command = ["wait", "installer-generation"];
        self.generation_intent(
            &mut writer,
            operation,
            &command,
            &before,
            &self.inputs.services,
        )?;
        let result = self.compose(&command, false, Duration::from_secs(MAX_WAIT));
        let resources = self.observe_transition(false, Some(&selected));
        let statuses = self.status();
        let complete = matches!((&resources, &statuses), (Ok(resources), Ok(rows))
            if resources.containers.get("installer-generation").is_some_and(|identity| identity.id == container_id)
                && completed_setups(resources, rows));
        self.receipt(
            &mut writer,
            operation,
            &result,
            complete,
            resources,
            statuses,
        )
    }

    /// Keep the authenticated OpenBao custody anchor across generation pruning.
    /// It can be inherited only through the prior receipt, rather than explicit
    /// Compose inputs, and is still needed to admit its private helper mounts.
    fn generation_checkpoint_bindings(&self) -> Result<BTreeMap<PathBuf, String>> {
        let mut bindings: BTreeMap<_, _> = self
            .inputs
            .files
            .iter()
            .chain(std::iter::once(&self.inputs.environment))
            .chain(&self.inputs.bound_inputs)
            .map(|file| (file.path.clone(), file.sha256.clone()))
            .collect();
        let custody = self
            .inputs
            .installation
            .join("evidence")
            .join(OPENBAO_CUSTODY);
        if let Some(hash) = self
            .inputs
            .prior
            .as_ref()
            .ok_or(REFUSED)?
            .input_files
            .get(&custody)
        {
            require(
                self.bindings.get(&custody) == Some(hash)
                    && bindings.get(&custody).is_none_or(|current| current == hash),
            )?;
            bindings.insert(custody, hash.clone());
        }
        Ok(bindings)
    }

    /// A fresh native checkpoint prevents prior dotenv paths from accumulating
    /// forever in each successor receipt. The generation owner separately binds
    /// the previous receipt in its immutable lineage before calling this method.
    pub(crate) fn checkpoint_generation(
        mut self,
        state: &mut LockedMaintenance,
        operation: &str,
    ) -> Result<ComposeReceipt> {
        require(
            !self.cleanup_only && self.inputs.prior.is_some() && self.inputs.services.is_empty(),
        )?;
        self.observe(false)?;
        self.bindings = self.generation_checkpoint_bindings()?;
        self.recheck()?;
        let mut writer = Evidence::Maintenance(state, Some(RuntimeOperationOwner::Generation));
        self.begin(
            &mut writer,
            operation,
            &["ps", "--all", "--no-trunc", "--format", "json"],
        )?;
        let resources = self.observe(false);
        let statuses = self.status();
        let result = statuses
            .as_ref()
            .map(|_| String::new())
            .map_err(Clone::clone);
        let complete = matches!((&resources, &statuses), (Ok(resources), Ok(rows)) if completed(resources, rows));
        self.receipt(
            &mut writer,
            operation,
            &result,
            complete,
            resources,
            statuses,
        )
    }
}

fn generation_baseline_observation(
    resources: &ProjectResources,
    rows: &[Value],
    stopped: &BTreeSet<String>,
) -> bool {
    completed_setups(resources, rows)
        && rows.iter().all(|row| {
            row["Service"].as_str().is_some_and(|role| {
                resources.containers.get(role).is_some_and(|identity| {
                    identity.setup
                        || row["State"].as_str().is_some_and(|state| {
                            ["created", "exited", "running"].contains(&state)
                                && (!stopped.contains(role) || state != "running")
                        })
                })
            })
        })
}

fn generation_runtime_observation(
    resources: &ProjectResources,
    rows: &[Value],
    selected: &BTreeSet<String>,
    replacing: &BTreeSet<String>,
    stopped: bool,
) -> bool {
    let mut seen = BTreeSet::new();
    !selected.is_empty()
        && rows.len() == resources.containers.len()
        && rows.iter().all(|row| {
            let Some(role) = row["Service"].as_str() else {
                return false;
            };
            let Some(identity) = resources.containers.get(role) else {
                return false;
            };
            seen.insert(role)
                && row["ID"] == identity.id
                && if identity.setup {
                    if replacing.contains(role) {
                        ["created", "running", "exited"]
                            .contains(&row["State"].as_str().unwrap_or(""))
                            && (!stopped || row["State"] != "running")
                    } else {
                        row["State"] == "exited"
                            && row["ExitCode"] == 0
                            && identity
                                .setup_execution
                                .as_ref()
                                .is_some_and(|v| v.completed_without_restart)
                    }
                } else if selected.contains(role) {
                    if stopped {
                        ["created", "exited"].contains(&row["State"].as_str().unwrap_or(""))
                    } else {
                        row["State"] == "running"
                            && (!identity.health_required || row["Health"] == "healthy")
                    }
                } else {
                    ["created", "running", "exited", "paused", "restarting"]
                        .contains(&row["State"].as_str().unwrap_or(""))
                }
        })
}

fn generation_created(
    resources: &ProjectResources,
    rows: &[Value],
    prior: &ProjectResources,
    selected: &BTreeSet<String>,
) -> bool {
    let mut seen = BTreeSet::new();
    rows.len() == resources.containers.len()
        && rows.iter().all(|row| {
            row["Service"].as_str().is_some_and(|role| {
                seen.insert(role)
                    && resources
                        .containers
                        .get(role)
                        .is_some_and(|identity| row["ID"] == identity.id)
            })
        })
        && selected.iter().all(|role| {
            resources.containers.get(role).is_some_and(|current| {
                prior
                    .containers
                    .get(role)
                    .is_some_and(|old| old.id != current.id)
                    && rows
                        .iter()
                        .filter(|row| row["Service"] == role.as_str())
                        .count()
                        == 1
                    && rows.iter().any(|row| {
                        row["Service"] == role.as_str()
                            && row["ID"] == current.id
                            && ["created", "running", "exited"]
                                .contains(&row["State"].as_str().unwrap_or(""))
                    })
            })
        })
}

fn completed_setups(resources: &ProjectResources, rows: &[Value]) -> bool {
    let mut normalized = rows.to_vec();
    for row in &mut normalized {
        if row["Service"]
            .as_str()
            .and_then(|role| resources.containers.get(role))
            .is_some_and(|identity| !identity.setup)
        {
            if !row["State"].as_str().is_some_and(|state| {
                ["running", "created", "exited", "restarting", "paused"].contains(&state)
            }) {
                return false;
            }
            row["State"] = json!("running");
            row["Health"] = json!("healthy");
        }
    }
    completed(resources, &normalized)
}

#[cfg(test)]
#[path = "installer_compose_generation_tests.rs"]
mod tests;
