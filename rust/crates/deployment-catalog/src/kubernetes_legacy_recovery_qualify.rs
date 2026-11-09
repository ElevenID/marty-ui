//! Fresh native qualification of a completed private stage and closed Secret plan.
//! No credential is issued here. Token lookups and same-key signature probes are
//! journaled independently; the caller must preserve this evidence before use.

use super::{staging, *};
use base64::{engine::general_purpose::STANDARD, Engine};

pub(super) const SCHEMA: &str = "marty.kubernetes-legacy-recovery-qualified-plan/v1";
pub(super) const PLAN_SECONDS: u64 = 300;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Qualification {
    pub(super) schema: String,
    pub(super) context: Context,
    pub(super) inspection: PathBuf,
    pub(super) staged: PathBuf,
    pub(super) secrets: PathBuf,
    pub(super) output: PathBuf,
}

fn bindings(files: &Generation) -> Value {
    let entries: BTreeMap<_, _> = files
        .iter()
        .map(|(name, (bytes, mode))| (name, json!({"sha256":sha256(bytes),"mode":mode})))
        .collect();
    json!(entries)
}

/// Close this qualification's private evidence before publishing its plan.
/// The plan is deliberately absent while this inventory is read and rechecked.
fn journal_bindings(output: &Path) -> Result<Value> {
    private_directory(output)?;
    let mut expected = BTreeSet::from(["attempt.json".to_owned()]);
    let mut records = BTreeMap::new();
    for index in 0..51 {
        for (kind, maximum) in [("request", MAX_FILE + 1), ("response", 2 * MAX_FILE + 1)] {
            let name = format!("{kind}-{index:03}.json");
            expected.insert(name.clone());
            let bytes = read_bounded(&output.join(&name), &[0o600], false, maximum)?.0;
            records.insert(name, sha256(&bytes));
        }
    }
    let actual: BTreeSet<_> = fs::read_dir(output)
        .map_err(|_| REFUSAL)?
        .map(|entry| {
            entry
                .map_err(|_| REFUSAL)?
                .file_name()
                .into_string()
                .map_err(|_| REFUSAL)
        })
        .collect::<Result<_>>()?;
    if actual != expected {
        return Err(REFUSAL);
    }
    Ok(json!(records))
}

/// A native issuance response is retained verbatim before interpretation. This
/// replay reads evidence; it never reissues an operation or accepts stdin receipts.
fn captured(path: &Path) -> Result<Value> {
    let envelope = staging::private_report(path)?;
    if envelope.as_object().ok_or(REFUSAL)?.len() != 4
        || envelope["received"] != true
        || envelope["status"] != 200
        || envelope["complete"] != true
    {
        return Err(REFUSAL);
    }
    let raw = STANDARD
        .decode(text(&envelope, "bodyBase64")?)
        .map_err(|_| REFUSAL)?;
    if raw.is_empty() || raw.len() > 64 * 1024 {
        return Err(REFUSAL);
    }
    crate::installer_json::decode(&raw).map_err(|_| REFUSAL)
}

pub(super) async fn qualify_with(
    api: &impl staging::StageApi,
    request: &Qualification,
) -> Result<Value> {
    if request.schema != SCHEMA {
        return Err(REFUSAL);
    }
    let binding = binding(&request.context)?;
    let (leaves, tokens) = staging::inventory(&binding)?;
    private_directory(&request.staged)?;
    private_directory(&request.output)?;
    for input in [
        &request.context.current,
        &request.context.root_token_file,
        &request.inspection,
        &request.staged,
        &request.secrets,
    ] {
        if input.starts_with(&request.output) || request.output.starts_with(input) {
            return Err(REFUSAL);
        }
    }
    if fs::read_dir(&request.output)
        .map_err(|_| REFUSAL)?
        .next()
        .is_some()
    {
        return Err(REFUSAL);
    }
    let original = generation(&request.context.current)?;
    let candidate_path = request.staged.join("candidate");
    let candidate = generation(&candidate_path)?;
    let inspection_bytes = staging::private_report_bytes(&request.inspection)?;
    let inspection = crate::installer_json::decode(&inspection_bytes).map_err(|_| REFUSAL)?;
    let complete_path = request.staged.join("complete.json");
    let attempt_path = request.staged.join("attempt.json");
    let complete_bytes = staging::private_report_bytes(&complete_path)?;
    let complete = crate::installer_json::decode(&complete_bytes).map_err(|_| REFUSAL)?;
    let attempt = staging::private_report(&attempt_path)?;
    let expected_binding = serde_json::to_value(&binding).map_err(|_| REFUSAL)?;
    let replacements: Vec<_> = leaves
        .iter()
        .map(|leaf| &leaf.file)
        .chain(tokens.iter().map(|token| &token.file))
        .collect();
    let inspection_hash = sha256(&inspection_bytes);
    let journal = staging::journal_bindings(&request.staged, true)?;
    staging::replacement_inputs(
        &request.staged,
        &candidate,
        &replacements.iter().copied().collect(),
    )?;
    if complete
        != json!({"schema":staging::STAGE_SCHEMA,"binding":binding,
        "status":"staged-not-activated","candidate":"candidate","replacementCount":51,
        "inputBindings":bindings(&candidate),"completedRequests":120,"journalBindings":journal,"activation":false})
        || attempt
            != json!({"schema":staging::STAGE_SCHEMA,"binding":binding,
            "inspectionSha256":inspection_hash,"replacementFiles":replacements,"activation":false})
    {
        return Err(REFUSAL);
    }
    let observed = staging::private_report(&request.secrets)?;
    // The planner rejects any extra/missing/mutated input before root is sent.
    let native_plan = activation::plan(&original, &candidate, &binding, &observed)?;
    let mut created_tokens = BTreeMap::new();
    let mut index = 36usize;
    for spec in &tokens {
        let created = captured(&request.staged.join(format!("response-{index:03}.json")))?;
        let value = std::str::from_utf8(&candidate[&spec.file].0).map_err(|_| REFUSAL)?;
        if created["auth"]["client_token"] != value {
            return Err(REFUSAL);
        }
        created_tokens.insert(spec.file.clone(), created);
        index += 2 + match &spec.proof {
            staging::Proof::Tls(_) => 1,
            staging::Proof::KeycloakSigning => 2,
            _ => 0,
        };
    }
    if index != 120 {
        return Err(REFUSAL);
    }
    staging::same_report(&inspection, &inspect_with(api, &request.context).await?)?;
    let root_bytes = read_input(&request.context.root_token_file, &[0o400, 0o600], false)?.0;
    if sha256(&root_bytes) != request.context.retained_root_sha256 {
        return Err(REFUSAL);
    }
    let root = std::str::from_utf8(&root_bytes).map_err(|_| REFUSAL)?;
    let started = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| REFUSAL)?
        .as_secs();
    staging::persist(
        &request.output.join("attempt.json"),
        &json!({"schema":SCHEMA,
        "binding":binding,"inspectionSha256":inspection_hash,"startedAtUnixSeconds":started,
        "currentInputs":bindings(&original),"candidateInputs":bindings(&candidate),
        "credentialsIssued":false,"activation":false}),
        MAX_GENERATION,
    )?;
    let result: Result<Value> = async {
        for leaf in &leaves {
            staging::retained_profile(leaf,&original[&leaf.file].0)?;
            let issuer = &inspection["observed"][if leaf.mount == "workload-pki" {"workloadIssuer"} else {"keycloakIssuer"}];
            let public = text(&inspection["observed"]["keys"][&leaf.key]["keys"]["1"],"public_key")?;
            let pem = std::str::from_utf8(&candidate[&leaf.file].0).map_err(|_| REFUSAL)?;
            staging::replacement_leaf(&json!({"data":{"certificate":pem}}),&original[&leaf.file].0,
                text(issuer,"certificate")?.as_bytes(),public)?;
        }
        let mut proofs = staging::Journal {output:&request.output,next:0};
        for spec in &tokens {
            let value = std::str::from_utf8(&candidate[&spec.file].0).map_err(|_| REFUSAL)?;
            let lookup = proofs.post(api,"qualify-existing-candidate-token","auth/token/lookup",
                &json!({"token":value}),root).await?;
            crate::application_authority::legacy_recovery_leaf(&created_tokens[&spec.file],&lookup,value,&spec.policies,TTL)?;
            staging::prove(api,&mut proofs,spec,value,&inspection).await?;
        }
        let qualification_journal = journal_bindings(&request.output)?;
        staging::same_report(&inspection,&inspect_with(api,&request.context).await?)?;
        if original != generation(&request.context.current)? || candidate != generation(&candidate_path)?
            || root_bytes != read_input(&request.context.root_token_file,&[0o400,0o600],false)?.0
            || complete_bytes != staging::private_report_bytes(&complete_path)?
            || attempt != staging::private_report(&attempt_path)?
            || inspection_bytes != staging::private_report_bytes(&request.inspection)?
            || journal != staging::journal_bindings(&request.staged,true)?
            || qualification_journal != journal_bindings(&request.output)?
            || observed != staging::private_report(&request.secrets)? { return Err(REFUSAL); }
        staging::replacement_inputs(&request.staged,&candidate,&replacements.iter().copied().collect())?;
        let qualified = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| REFUSAL)?.as_secs();
        // Each credential was proved in this interval. Bound elapsed work as
        // well as the plan's subsequent use to prevent stale local evidence.
        if qualified < started || qualified - started > PLAN_SECONDS || proofs.next != 51 { return Err(REFUSAL); }
        let plan = json!({"schema":SCHEMA,"binding":expected_binding,"status":"qualified-not-activated",
            "qualifiedAtUnixSeconds":qualified,"validBeforeUnixSeconds":qualified.checked_add(PLAN_SECONDS).ok_or(REFUSAL)?,
            "inspectionSha256":inspection_hash,"stagingReceiptSha256":sha256(&complete_bytes),
            "qualificationJournalBindings":qualification_journal,
            "credentialsQualified":true,"credentialsIssued":false,"activation":false,"nativePlan":native_plan});
        staging::persist(&request.output.join("plan.json"),&plan,MAX_GENERATION)?;
        Ok(json!({"schema":SCHEMA,"status":"qualified-not-activated","credentialsQualified":true,
            "credentialsIssued":false,"activation":false,"secretCount":34,"replacementCount":51,
            "validBeforeUnixSeconds":plan["validBeforeUnixSeconds"],"privatePlanWritten":true,
            "privatePlanSha256":sha256(&staging::private_report_bytes(&request.output.join("plan.json"))?)}))
    }.await;
    result.map_err(|_| staging::RECOVERY)
}
