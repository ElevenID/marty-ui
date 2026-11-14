//! Admit completed predecessors without relabeling bootstrap or importing live
//! credentials as authority. Artifact signatures are checked by the existing
//! transport owner; this owner independently checks its bounded, private
//! evidence, each original-to-successor plan, and the observed live preimage.
//! Historical qualification is provenance, never a fresh credential TTL proof.

use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};

pub(super) const SCHEMA: &str = "marty.kubernetes-legacy-recovery-lineage/v1";
const MAX_STEPS: usize = 8;
const MAX_BYTES: usize = 64 * 1024 * 1024;

#[derive(Default)]
struct Evidence {
    files: BTreeMap<PathBuf, (Vec<u8>, u32)>,
    generations: BTreeMap<PathBuf, Generation>,
    bytes: usize,
}

impl Evidence {
    fn read(&mut self, path: &Path, maximum: usize) -> Result<Vec<u8>> {
        let item = read_bounded(path, &[0o600], false, maximum)?;
        self.remember(path, &item)?;
        Ok(item.0)
    }

    fn remember(&mut self, path: &Path, item: &(Vec<u8>, u32)) -> Result<()> {
        if let Some(previous) = self.files.get(path) {
            if previous != item {
                return Err(REFUSAL);
            }
        } else {
            self.bytes = self.bytes.checked_add(item.0.len()).ok_or(REFUSAL)?;
            if self.bytes > MAX_BYTES {
                return Err(REFUSAL);
            }
            self.files.insert(path.to_owned(), item.clone());
        }
        Ok(())
    }

    fn record(&mut self, path: &Path) -> Result<(Vec<u8>, Value)> {
        let bytes = self.read(path, MAX_GENERATION + 1)?;
        let value = crate::installer_json::decode(&bytes).map_err(|_| REFUSAL)?;
        Ok((bytes, value))
    }

    fn generation(&mut self, path: &Path) -> Result<Generation> {
        let value = generation(path)?;
        for (name, item) in &value {
            self.remember(&path.join(name), item)?;
        }
        self.generations.insert(path.to_owned(), value.clone());
        Ok(value)
    }

    fn journal(&mut self, directory: &Path, count: usize) -> Result<Value> {
        let mut result = BTreeMap::new();
        for index in 0..count {
            for kind in ["request", "response"] {
                let name = format!("{kind}-{index:03}.json");
                let bytes = self.read(&directory.join(&name), 128 * 1024 + 1)?;
                result.insert(name, sha256(&bytes));
            }
        }
        Ok(json!(result))
    }

    fn recheck(&self) -> Result<()> {
        for (path, expected) in &self.generations {
            if generation(path)? != *expected {
                return Err(REFUSAL);
            }
        }
        for (path, expected) in &self.files {
            if read_bounded(path, &[expected.1], true, expected.0.len())? != *expected {
                return Err(REFUSAL);
            }
        }
        Ok(())
    }
}

fn release(value: &Value, binding: &Binding) -> Result<()> {
    let object = value.as_object().ok_or(REFUSAL)?;
    if object.len() != 8
        || !hex(text(value, "runtimeSourceSha")?, 40)
        || value["chartSourceSha"] != binding.chart_source_sha
        || !reference(text(value, "tag")?)
        || value["buildRunId"].as_u64().is_none_or(|n| n == 0)
        || value["buildRunAttempt"].as_u64().is_none_or(|n| n == 0)
        || ["inventorySha256", "imageLockSha256", "operatorSha256"]
            .iter()
            .any(|name| value[*name].as_str().is_none_or(|s| !hex(s, 64)))
    {
        return Err(REFUSAL);
    }
    Ok(())
}

fn bindings(generation: &Generation) -> Value {
    json!(generation
        .iter()
        .map(|(name, (bytes, mode))| (name, json!({"sha256":sha256(bytes),"mode":mode})))
        .collect::<BTreeMap<_, _>>())
}

fn patch_digest(value: &Value) -> Result<String> {
    fn ordered(value: &Value) -> Value {
        match value {
            Value::Array(values) => Value::Array(values.iter().map(ordered).collect()),
            Value::Object(values) => {
                let sorted: BTreeMap<_, _> = values
                    .iter()
                    .map(|(key, value)| (key, ordered(value)))
                    .collect();
                json!(sorted)
            }
            _ => value.clone(),
        }
    }
    // Existing Python patch-intent records bind compact sorted JSON plus LF.
    // The closed patch contains only ASCII Kubernetes keys and base64 values.
    let mut bytes = serde_json::to_vec(&ordered(value)).map_err(|_| REFUSAL)?;
    if !bytes.is_ascii() {
        return Err(REFUSAL);
    }
    bytes.push(b'\n');
    Ok(sha256(&bytes))
}

fn secret_list(value: &Value, binding: &Binding) -> Result<BTreeMap<String, Value>> {
    if value["apiVersion"] != "v1" || value["kind"] != "SecretList" {
        return Err(REFUSAL);
    }
    let mut result = BTreeMap::new();
    for secret in value["items"].as_array().ok_or(REFUSAL)? {
        let name = text(&secret["metadata"], "name")?;
        if secret["apiVersion"] != "v1"
            || secret["kind"] != "Secret"
            || secret["type"] != "Opaque"
            || secret["metadata"]["namespace"] != binding.namespace
            || !uuid(text(&secret["metadata"], "uid")?)
            || text(&secret["metadata"], "resourceVersion")?.is_empty()
            || secret["metadata"].get("deletionTimestamp").is_some()
            || secret.get("immutable").is_some_and(|v| v != false)
            || secret.get("stringData").is_some()
            || !secret["data"].is_object()
            || result.insert(name.to_owned(), secret.clone()).is_some()
        {
            return Err(REFUSAL);
        }
    }
    if result.keys().cloned().collect::<Vec<_>>() != activation::target_names(binding)? {
        return Err(REFUSAL);
    }
    Ok(result)
}

fn same_publication(
    current: &BTreeMap<String, Value>,
    previous: &BTreeMap<String, Value>,
) -> Result<()> {
    if current.keys().ne(previous.keys())
        || current.iter().any(|(name, actual)| {
            actual["metadata"]["uid"] != previous[name]["metadata"]["uid"]
                || actual["data"] != previous[name]["data"]
        })
    {
        return Err(REFUSAL);
    }
    Ok(())
}

fn without_server_metadata(mut value: Value) -> Result<Value> {
    let metadata = value["metadata"].as_object_mut().ok_or(REFUSAL)?;
    metadata.remove("resourceVersion");
    metadata.remove("managedFields");
    Ok(value)
}

fn postimages(
    evidence: &mut Evidence,
    directory: &Path,
    plan: &Value,
    plan_hash: &str,
    preimages: &BTreeMap<String, Value>,
    binding: &Binding,
) -> Result<BTreeMap<String, Value>> {
    let mut after = BTreeMap::new();
    for (index, entry) in plan["nativePlan"]["secrets"]
        .as_array()
        .ok_or(REFUSAL)?
        .iter()
        .enumerate()
    {
        let name = text(entry, "name")?;
        let original = preimages.get(name).ok_or(REFUSAL)?;
        let (_, intent) = evidence.record(&directory.join(format!("intent-{index:02}.json")))?;
        let attempted = intent["attemptedAtUnixSeconds"].as_u64().ok_or(REFUSAL)?;
        if attempted < plan["qualifiedAtUnixSeconds"].as_u64().ok_or(REFUSAL)?
            || attempted >= plan["validBeforeUnixSeconds"].as_u64().ok_or(REFUSAL)?
            || intent
                != json!({"schema":"marty.kubernetes-legacy-secret-patch-intent/v1",
                "binding":binding,"name":name,"uid":entry["uid"],"resourceVersion":entry["resourceVersion"],
                "privatePlanSha256":plan_hash,
                "patchSha256":patch_digest(&entry["patch"])?,
                "validBeforeUnixSeconds":plan["validBeforeUnixSeconds"],"attemptedAtUnixSeconds":attempted})
        {
            return Err(REFUSAL);
        }
        let (_, response) =
            evidence.record(&directory.join(format!("response-{index:02}.json")))?;
        if response["completed"] != true || response["bounded"] != true || response["exitCode"] != 0
        {
            return Err(REFUSAL);
        }
        let encoded = text(&response, "stdoutBase64")?;
        let raw = STANDARD.decode(encoded).map_err(|_| REFUSAL)?;
        if raw.len() > 2 * 1024 * 1024 || STANDARD.encode(&raw) != encoded {
            return Err(REFUSAL);
        }
        let observed = crate::installer_json::decode(&raw).map_err(|_| REFUSAL)?;
        let mut expected = original.clone();
        for patch in entry["patch"].as_array().ok_or(REFUSAL)?.iter().skip(3) {
            // The complete patch was already reconstructed by the closed planner.
            let key = text(patch, "path")?
                .strip_prefix("/data/")
                .ok_or(REFUSAL)?
                .replace("~1", "/")
                .replace("~0", "~");
            expected["data"][&key] = patch["value"].clone();
        }
        if observed["metadata"]["resourceVersion"] == original["metadata"]["resourceVersion"]
            || text(&observed["metadata"], "resourceVersion")?.is_empty()
            || without_server_metadata(observed.clone())? != without_server_metadata(expected)?
        {
            return Err(REFUSAL);
        }
        let (_, verified) =
            evidence.record(&directory.join(format!("verified-{index:02}.json")))?;
        if verified
            != json!({"name":name,"uid":entry["uid"],
            "resourceVersion":observed["metadata"]["resourceVersion"],"responseSha256":sha256(&raw)})
        {
            return Err(REFUSAL);
        }
        after.insert(name.to_owned(), observed);
    }
    Ok(after)
}

/// Python authenticates each selected release closure and builds this private
/// transport image. No input path or release assertion is obtained from a
/// caller-written completion selector. The manifest is rechecked throughout.
pub(super) fn verify(context: &Context) -> Result<Option<Value>> {
    let Some(directory) = &context.predecessors else {
        return Ok(None);
    };
    private_directory(directory)?;
    let binding = binding(context)?;
    let mut evidence = Evidence::default();
    let (_, manifest) = evidence.record(&directory.join("manifest.json"))?;
    let steps = manifest["steps"].as_array().ok_or(REFUSAL)?;
    if manifest["schema"] != SCHEMA
        || manifest["binding"] != json!(binding)
        || manifest.as_object().ok_or(REFUSAL)?.len() != 4
        || steps.is_empty()
        || steps.len() > MAX_STEPS
    {
        return Err(REFUSAL);
    }
    release(&manifest["originalRuntime"], &binding)?;
    if manifest["originalRuntime"]["runtimeSourceSha"] != LEGACY_RUNTIME {
        return Err(REFUSAL);
    }
    let mut current = evidence.generation(&directory.join("original"))?;
    let original_inputs = bindings(&current);
    let mut summaries = Vec::new();
    let mut previous = None;
    for (index, step) in steps.iter().enumerate() {
        release(&step["recoveryRuntime"], &binding)?;
        if step.as_object().ok_or(REFUSAL)?.len() != 3 {
            return Err(REFUSAL);
        }
        let path = directory.join(format!("step-{index:02}"));
        let native = path.join("evidence");
        let candidate = evidence.generation(&native.join("stage/candidate"))?;
        let (completion_bytes, completion) =
            evidence.record(&path.join("recovery-complete.json"))?;
        let (source_bytes, source) = evidence.record(&path.join("source-authenticated.json"))?;
        if step["completionSha256"] != sha256(&completion_bytes)
            || step["sourceAuthenticationSha256"] != sha256(&source_bytes)
            || source["schema"] != "marty.kubernetes-legacy-recovery-sources/v1"
            || source["recoveryRuntime"] != step["recoveryRuntime"]
            || source.as_object().ok_or(REFUSAL)?.len() != 3
            || !source["files"].is_object()
        {
            return Err(REFUSAL);
        }
        let (plan_bytes, plan) = evidence.record(&native.join("qualification/plan.json"))?;
        let plan_hash = sha256(&plan_bytes);
        let (preimage_bytes, preimage_list) = evidence.record(&native.join("secrets.json"))?;
        let preimages = secret_list(&preimage_list, &binding)?;
        if let Some(previous) = &previous {
            same_publication(&preimages, previous)?;
        }
        let expected_plan = activation::plan(&current, &candidate, &binding, &preimage_list)?;
        let (inspection_bytes, inspection) = evidence.record(&native.join("inspection.json"))?;
        let (stage_bytes, stage) = evidence.record(&native.join("stage/complete.json"))?;
        let (_, attempt) = evidence.record(&native.join("stage/attempt.json"))?;
        let (leaves, tokens) = staging::inventory(&binding)?;
        let replacements: Vec<_> = leaves
            .iter()
            .map(|leaf| &leaf.file)
            .chain(tokens.iter().map(|token| &token.file))
            .collect();
        for name in &replacements {
            if evidence.read(&native.join("stage/inputs").join(name), MAX_FILE)?
                != candidate[*name].0
            {
                return Err(REFUSAL);
            }
        }
        let prefix = json!({"schema":SCHEMA,"binding":binding,"originalInputBindings":original_inputs,"steps":summaries});
        let inherited = if index == 0 { None } else { Some(&prefix) };
        if inspection["schema"] != super::SCHEMA
            || inspection["status"] != "inspected-not-staged"
            || inspection["mutationAvailable"] != false
            || inspection["binding"] != json!(binding)
            || inspection["inputBindings"] != bindings(&current)
            || inspection.get("predecessorChain") != inherited
            || stage
                != json!({"schema":staging::STAGE_SCHEMA,"binding":binding,
                "status":"staged-not-activated","candidate":"candidate","replacementCount":51,
                "inputBindings":bindings(&candidate),"completedRequests":120,
                "journalBindings":evidence.journal(&native.join("stage"),120)?,"activation":false})
            || attempt
                != json!({"schema":staging::STAGE_SCHEMA,"binding":binding,
                "inspectionSha256":sha256(&inspection_bytes),"replacementFiles":replacements,"activation":false})
        {
            return Err(REFUSAL);
        }
        let qualified = plan["qualifiedAtUnixSeconds"].as_u64().ok_or(REFUSAL)?;
        let deadline = plan["validBeforeUnixSeconds"].as_u64().ok_or(REFUSAL)?;
        if deadline.checked_sub(qualified) != Some(qualification::PLAN_SECONDS)
            || plan
                != json!({"schema":qualification::SCHEMA,"binding":binding,"status":"qualified-not-activated",
                "qualifiedAtUnixSeconds":qualified,"validBeforeUnixSeconds":deadline,
                "inspectionSha256":sha256(&inspection_bytes),"stagingReceiptSha256":sha256(&stage_bytes),
                "qualificationJournalBindings":evidence.journal(&native.join("qualification"),51)?,
                "credentialsQualified":true,"credentialsIssued":false,"activation":false,"nativePlan":expected_plan})
        {
            return Err(REFUSAL);
        }
        let (_, qualification_attempt) =
            evidence.record(&native.join("qualification/attempt.json"))?;
        let started = qualification_attempt["startedAtUnixSeconds"]
            .as_u64()
            .ok_or(REFUSAL)?;
        if qualified
            .checked_sub(started)
            .is_none_or(|duration| duration > qualification::PLAN_SECONDS)
            || qualification_attempt
                != json!({"schema":qualification::SCHEMA,"binding":binding,
                "inspectionSha256":sha256(&inspection_bytes),"startedAtUnixSeconds":started,
                "currentInputs":bindings(&current),"candidateInputs":bindings(&candidate),
                "credentialsIssued":false,"activation":false})
        {
            return Err(REFUSAL);
        }
        let (_, requested) = evidence.record(&path.join("recovery-requested.json"))?;
        let (_, activation) =
            evidence.record(&path.join("activation/activation-requested.json"))?;
        let mut expected_completion = json!({"schema":"marty.kubernetes-legacy-recovery-completion/v1","binding":binding,
            "originalRuntime":manifest["originalRuntime"],"recoveryRuntime":step["recoveryRuntime"],
            "status":"existing-secrets-activated","credentialsIssued":true,"activation":true,
            "verifiedSecretCount":34,"workloadsRestarted":false,"privatePlanSha256":plan_hash,"podRemoved":true});
        if index > 0 {
            expected_completion["predecessorChain"] = prefix.clone();
        }
        if completion != expected_completion
            || requested["schema"] != "marty.kubernetes-legacy-recovery-request/v1"
            || requested["binding"] != json!(binding)
            || requested["originalRuntime"] != manifest["originalRuntime"]
            || requested["recoveryRuntime"] != step["recoveryRuntime"]
            || requested["mode"] != "activate-existing-secrets"
            || requested["automaticReplay"] != false
            || requested.get("predecessorChain") != inherited
            || activation
                != json!({"schema":"marty.kubernetes-legacy-secret-activation/v1","binding":binding,
                "privatePlanSha256":plan_hash,"preimagesSha256":sha256(&preimage_bytes),"secretCount":34,
                "replacementCount":51,"atomicAcrossSecrets":false,"validBeforeUnixSeconds":deadline})
        {
            return Err(REFUSAL);
        }
        previous = Some(postimages(
            &mut evidence,
            &path.join("activation"),
            &plan,
            &plan_hash,
            &preimages,
            &binding,
        )?);
        summaries.push(json!({"recoveryRuntime":step["recoveryRuntime"],"completionSha256":sha256(&completion_bytes),
            "sourceAuthenticationSha256":sha256(&source_bytes),"privatePlanSha256":plan_hash,
            "candidateInputs":bindings(&candidate)}));
        current = candidate;
    }
    let (_, live) = evidence.record(&directory.join("live-secrets.json"))?;
    same_publication(
        &secret_list(&live, &binding)?,
        previous.as_ref().ok_or(REFUSAL)?,
    )?;
    if current != generation(&context.current)? {
        return Err(REFUSAL);
    }
    evidence.recheck()?;
    Ok(Some(
        json!({"schema":SCHEMA,"binding":binding,"originalInputBindings":original_inputs,"steps":summaries}),
    ))
}

pub fn inspect(request: &[u8]) -> Result<Value> {
    let context = decode_context(request)?;
    verify(&context)?.ok_or(REFUSAL)
}
