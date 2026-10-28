//! Strict installer record decoding and binding. No I/O or cryptography occurs
//! here: callers authenticate the exact input bytes and invoke a pinned verifier
//! successfully before applying the certificate-output checks below.
use serde::{de, Deserialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub type Result<T> = std::result::Result<T, String>;
pub const REPOSITORY: &str = "ElevenID/marty-ui";
pub const REF: &str = "refs/heads/main";
pub const ISSUER: &str = "https://token.actions.githubusercontent.com";
pub const PROMOTION_WORKFLOW: &str = ".github/workflows/installer-promote.yml";
pub const ACCEPTANCE_WORKFLOW: &str = ".github/workflows/installer-acceptance.yml";
pub const MAX_RECORD: usize = 65536;
const SAFE_INTEGER: u64 = 1 << 53;

fn require(value: bool, error: &str) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(error.into())
    }
}
fn pattern(value: &str, expression: &str) -> bool {
    regex::Regex::new(expression)
        .expect("static policy regex")
        .is_match(value)
}
fn sha(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn positive(value: u64) -> bool {
    value > 0 && value < SAFE_INTEGER
}
pub fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Return the release tier after exact syntax and calendar-date validation.
pub fn release_tier(tag: &str) -> Result<&'static str> {
    let regex = regex::Regex::new(r"\Av(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-nightly\.(20[0-9]{6})\.([1-9][0-9]*))?\z").unwrap();
    let captures = regex.captures(tag).ok_or("invalid installer release tag")?;
    if let Some(date) = captures.get(4) {
        chrono::NaiveDate::parse_from_str(date.as_str(), "%Y%m%d")
            .map_err(|_| "invalid nightly calendar date")?;
        Ok("nightly")
    } else {
        Ok("stable")
    }
}
pub fn build_workflow(tag: &str) -> Result<&'static str> {
    Ok(if release_tier(tag)? == "nightly" {
        ".github/workflows/nightly-release.yml"
    } else {
        ".github/workflows/cd.yml"
    })
}

// serde's typed structs reject duplicate fields, but ordinary maps do not.
// Decode recursively once so duplicate image names and verifier fields fail too.

fn decode(bytes: &[u8], limit: usize) -> Result<Value> {
    require(
        !bytes.is_empty() && bytes.len() <= limit,
        "installer JSON size exceeds bounds",
    )?;
    crate::installer_json::decode(bytes).map_err(|_| "invalid or ambiguous installer JSON".into())
}
fn typed<T: de::DeserializeOwned>(value: Value) -> Result<T> {
    serde_json::from_value(value).map_err(|_| "installer record fields or types differ".into())
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub name: String,
    pub sha256: String,
    pub size: u64,
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    pub schema: String,
    pub repository: String,
    pub source_sha: String,
    pub release_tag: String,
    pub platform: String,
    pub build_run_id: u64,
    pub build_run_attempt: u64,
    pub artifacts: Vec<Artifact>,
    pub images: BTreeMap<String, String>,
}
impl Inventory {
    pub fn artifact(&self, name: &str) -> Result<&Artifact> {
        self.artifacts
            .iter()
            .find(|a| a.name == name)
            .ok_or_else(|| "required installer artifact absent".into())
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub sha256: String,
    pub run_id: u64,
    pub run_attempt: u64,
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Acceptance {
    pub staged: Evidence,
    pub published: Evidence,
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Admission {
    pub schema: String,
    pub repository: String,
    pub source_sha: String,
    pub release_tag: String,
    pub platform: String,
    pub status: String,
    pub inventory_sha256: String,
    pub operator_sha256: String,
    pub build_run_id: u64,
    pub build_run_attempt: u64,
    pub promotion_source_sha: String,
    pub promotion_run_id: u64,
    pub promotion_run_attempt: u64,
    pub acceptance: Acceptance,
}
/// A bounded authorization to exercise a candidate, never consumer admission.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CandidatePhase {
    Staged,
    Published,
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CandidateAuthorization {
    pub schema: String,
    pub repository: String,
    pub scope: String,
    pub source_ref: String,
    pub source_sha: String,
    pub release_tag: String,
    pub platform: String,
    pub inventory_sha256: String,
    pub operator_sha256: String,
    pub build_run_id: u64,
    pub build_run_attempt: u64,
    pub phase: CandidatePhase,
    pub harness_source_sha: String,
    pub workflow: String,
    pub run_id: u64,
    pub run_attempt: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: String,
}
/// Independently selected harness invocation and candidate, never populated by
/// copying claims from the authorization under verification.
#[derive(Clone, Debug)]
pub struct CandidateContext {
    pub operator_sha: String,
    pub source_sha: String,
    pub release_tag: String,
    pub phase: CandidatePhase,
    pub nonce: String,
    pub harness_source_sha: String,
    pub run_id: u64,
    pub run_attempt: u64,
}

/// Parse only. The caller must authenticate these exact bytes against the
/// harness workflow/source/run certificate and enforce nonce consumption.
pub fn parse_candidate_authorization(bytes: &[u8], now: u64) -> Result<CandidateAuthorization> {
    let a: CandidateAuthorization = typed(decode(bytes, MAX_RECORD)?)?;
    require(
        a.schema == "elevenid.installer-candidate-authorization/v1"
            && a.repository == REPOSITORY
            && a.scope == "acceptance-only"
            && a.source_ref == REF
            && a.platform == "linux/amd64"
            && a.workflow == ACCEPTANCE_WORKFLOW,
        "candidate authorization identity differs",
    )?;
    candidate(
        &a.source_sha,
        &a.release_tag,
        a.build_run_id,
        a.build_run_attempt,
    )?;
    require(
        sha(&a.inventory_sha256, 64)
            && sha(&a.operator_sha256, 64)
            && sha(&a.harness_source_sha, 40)
            && sha(&a.nonce, 64)
            && positive(a.run_id)
            && positive(a.run_attempt),
        "invalid candidate authorization binding",
    )?;
    require(
        positive(now)
            && positive(a.issued_at)
            && a.issued_at <= now
            && a.expires_at < SAFE_INTEGER
            && a.expires_at > now
            && a.expires_at > a.issued_at
            && a.expires_at - a.issued_at <= 3600,
        "candidate authorization is expired or has invalid lifetime",
    )?;
    Ok(a)
}

/// Bind an authenticated acceptance-only authorization to exact candidate
/// bytes and the independently observed running operator. This performs no
/// cryptographic verification, execution, or durable replay prevention.
pub fn bind_candidate_authorization(
    authorization_bytes: &[u8],
    inventory_bytes: &[u8],
    expected: &CandidateContext,
    now: u64,
) -> Result<(CandidateAuthorization, Inventory)> {
    let a = parse_candidate_authorization(authorization_bytes, now)?;
    let inv = parse_inventory(inventory_bytes)?;
    require(
        a.source_sha == expected.source_sha
            && a.release_tag == expected.release_tag
            && a.phase == expected.phase
            && a.nonce == expected.nonce
            && a.harness_source_sha == expected.harness_source_sha
            && a.run_id == expected.run_id
            && a.run_attempt == expected.run_attempt
            && inv.source_sha == a.source_sha
            && inv.release_tag == a.release_tag
            && inv.build_run_id == a.build_run_id
            && inv.build_run_attempt == a.build_run_attempt
            && sha256(inventory_bytes) == a.inventory_sha256
            && inv.artifact("marty-deploy-linux-amd64")?.sha256 == a.operator_sha256
            && a.operator_sha256 == expected.operator_sha,
        "candidate authorization bytes, phase or producer differ",
    )?;
    Ok((a, inv))
}

/// Stable cross-language context digest: sorted compact JSON, no trailing LF,
/// and the wire field `operator_sha256` (not the Rust member name).
pub fn candidate_context_sha256(expected: &CandidateContext) -> Result<String> {
    require(
        sha(&expected.source_sha, 40)
            && sha(&expected.operator_sha, 64)
            && sha(&expected.harness_source_sha, 40)
            && sha(&expected.nonce, 64)
            && positive(expected.run_id)
            && positive(expected.run_attempt),
        "invalid controller context",
    )?;
    release_tier(&expected.release_tag)?;
    let phase = match expected.phase {
        CandidatePhase::Staged => "staged",
        CandidatePhase::Published => "published",
    };
    let values: BTreeMap<&str, Value> = [
        ("source_sha", Value::from(expected.source_sha.clone())),
        ("release_tag", Value::from(expected.release_tag.clone())),
        (
            "operator_sha256",
            Value::from(expected.operator_sha.clone()),
        ),
        (
            "harness_source_sha",
            Value::from(expected.harness_source_sha.clone()),
        ),
        ("nonce", Value::from(expected.nonce.clone())),
        ("phase", Value::from(phase)),
        ("run_id", Value::from(expected.run_id)),
        ("run_attempt", Value::from(expected.run_attempt)),
    ]
    .into_iter()
    .collect();
    Ok(sha256(
        &serde_json::to_vec(&values).map_err(|_| "cannot encode controller context")?,
    ))
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ControllerConsumption {
    pub schema: String,
    pub repository: String,
    pub scope: String,
    pub source_ref: String,
    pub workflow: String,
    pub authorization_sha256: String,
    pub context_sha256: String,
    pub nonce: String,
    pub source_sha: String,
    pub release_tag: String,
    pub operator_sha256: String,
    pub inventory_sha256: String,
    pub build_run_id: u64,
    pub build_run_attempt: u64,
    pub harness_source_sha: String,
    pub run_id: u64,
    pub run_attempt: u64,
    pub phase: CandidatePhase,
    pub guest_id: String,
    pub disk_id: String,
    pub engine_id: String,
    pub installation_id: String,
    pub consumed_at: u64,
}

fn canonical_v4(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| {
        id.to_string() == value
            && id.get_version_num() == 4
            && id.get_variant() == uuid::Variant::RFC4122
    })
}

/// Structural validation only. The exact bytes require the acceptance workflow's
/// signature/provenance. A receipt claims a controller dispatch was durably
/// consumed outside the guest; this module cannot prove persistence or global
/// one-use semantics. Guest/disk identity must be established by the controller.
pub fn parse_controller_consumption(bytes: &[u8], now: u64) -> Result<ControllerConsumption> {
    let c: ControllerConsumption = typed(decode(bytes, MAX_RECORD)?)?;
    require(
        c.schema == "elevenid.installer-controller-consumption/v1"
            && c.repository == REPOSITORY
            && c.scope == "controller-dispatch-consumed"
            && c.source_ref == REF
            && c.workflow == ACCEPTANCE_WORKFLOW,
        "controller consumption identity differs",
    )?;
    candidate(
        &c.source_sha,
        &c.release_tag,
        c.build_run_id,
        c.build_run_attempt,
    )?;
    require(
        [
            &c.authorization_sha256,
            &c.context_sha256,
            &c.nonce,
            &c.operator_sha256,
            &c.inventory_sha256,
            &c.disk_id,
        ]
        .into_iter()
        .all(|s| sha(s, 64))
            && sha(&c.harness_source_sha, 40)
            && positive(c.run_id)
            && positive(c.run_attempt)
            && positive(now)
            && positive(c.consumed_at)
            && c.consumed_at <= now
            && canonical_v4(&c.guest_id)
            && canonical_v4(&c.installation_id)
            && pattern(&c.engine_id, r"\A[A-Za-z0-9][A-Za-z0-9:-]{7,127}\z"),
        "invalid controller consumption binding",
    )?;
    Ok(c)
}

/// Bind only, never authenticate or consume. The caller verifies this exact
/// receipt against expected harness workflow/source/run/attempt and independently
/// authenticates controller/guest identity before applying runtime mutations.
pub fn bind_controller_consumption(
    bytes: &[u8],
    authorization_bytes: &[u8],
    inventory_bytes: &[u8],
    expected: &CandidateContext,
    expected_engine: &str,
    now: u64,
) -> Result<ControllerConsumption> {
    let (a, _) = bind_candidate_authorization(authorization_bytes, inventory_bytes, expected, now)?;
    let c = parse_controller_consumption(bytes, now)?;
    require(
        c.authorization_sha256 == sha256(authorization_bytes)
            && c.context_sha256 == candidate_context_sha256(expected)?
            && c.inventory_sha256 == sha256(inventory_bytes)
            && c.source_sha == a.source_sha
            && c.release_tag == a.release_tag
            && c.operator_sha256 == a.operator_sha256
            && c.nonce == a.nonce
            && c.build_run_id == a.build_run_id
            && c.build_run_attempt == a.build_run_attempt
            && c.workflow == a.workflow
            && c.harness_source_sha == a.harness_source_sha
            && c.run_id == a.run_id
            && c.run_attempt == a.run_attempt
            && c.phase == a.phase
            && c.engine_id == expected_engine
            && c.consumed_at >= a.issued_at
            && c.consumed_at < a.expires_at,
        "controller consumption differs from candidate or target",
    )?;
    Ok(c)
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Channel {
    pub schema: String,
    pub repository: String,
    pub channel: String,
    pub generation: u64,
    pub previous_sha256: Option<String>,
    pub source_sha: String,
    pub release_tag: String,
    pub admission_sha256: String,
    pub promotion_source_sha: String,
    pub promotion_run_id: u64,
    pub promotion_run_attempt: u64,
    pub issued_at: u64,
    pub expires_at: u64,
}
pub fn artifact_limit(name: &str) -> Option<u64> {
    match name {
        "install.sh" | "prepared-selfhost-images.json" => Some(65536),
        "marty-deploy-linux-amd64" => Some(512 * 1024 * 1024),
        "prepared-selfhost-bundle.zip" => Some(256 * 1024 * 1024),
        _ => None,
    }
}
fn candidate(source: &str, tag: &str, run: u64, attempt: u64) -> Result<()> {
    require(
        sha(source, 40) && positive(run) && positive(attempt),
        "invalid release source or producer",
    )?;
    release_tier(tag)?;
    Ok(())
}
pub fn parse_inventory(bytes: &[u8]) -> Result<Inventory> {
    let inv: Inventory = typed(decode(bytes, MAX_RECORD)?)?;
    require(
        inv.schema == "elevenid.installer-inventory/v1"
            && inv.repository == REPOSITORY
            && inv.platform == "linux/amd64",
        "inventory identity differs",
    )?;
    candidate(
        &inv.source_sha,
        &inv.release_tag,
        inv.build_run_id,
        inv.build_run_attempt,
    )?;
    require(inv.artifacts.len() == 4, "installer artifact count differs")?;
    let mut seen = BTreeSet::new();
    for entry in &inv.artifacts {
        let limit = artifact_limit(&entry.name).ok_or("unexpected installer artifact")?;
        require(
            seen.insert(&entry.name)
                && sha(&entry.sha256, 64)
                && positive(entry.size)
                && entry.size <= limit,
            "invalid or duplicate installer artifact",
        )?;
    }
    require(
        inv.images.len() > 1 && inv.images.contains_key("openbao_didcomm_image"),
        "incomplete image inventory",
    )?;
    for (name, image) in &inv.images {
        require(
            pattern(name, r"\A[a-z0-9][a-z0-9_-]*\z")
                && pattern(image, r"\A[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}\z"),
            "image is not digest pinned",
        )?;
    }
    Ok(inv)
}
pub fn parse_admission(bytes: &[u8]) -> Result<Admission> {
    let a: Admission = typed(decode(bytes, MAX_RECORD)?)?;
    require(
        a.schema == "elevenid.installer-admission/v1"
            && a.repository == REPOSITORY
            && a.platform == "linux/amd64"
            && a.status == "accepted",
        "admission identity differs",
    )?;
    candidate(
        &a.source_sha,
        &a.release_tag,
        a.build_run_id,
        a.build_run_attempt,
    )?;
    require(
        sha(&a.inventory_sha256, 64)
            && sha(&a.operator_sha256, 64)
            && sha(&a.promotion_source_sha, 40)
            && positive(a.promotion_run_id)
            && positive(a.promotion_run_attempt),
        "invalid admission binding",
    )?;
    for evidence in [&a.acceptance.staged, &a.acceptance.published] {
        require(
            sha(&evidence.sha256, 64)
                && positive(evidence.run_id)
                && positive(evidence.run_attempt),
            "invalid acceptance reference",
        )?;
    }
    Ok(a)
}
pub fn parse_channel(bytes: &[u8], now: u64) -> Result<Channel> {
    let raw = decode(bytes, MAX_RECORD)?;
    require(
        raw.get("previous_sha256").is_some(),
        "channel predecessor field missing",
    )?;
    let c: Channel = typed(raw)?;
    require(
        c.schema == "elevenid.installer-channel/v1"
            && c.repository == REPOSITORY
            && release_tier(&c.release_tag)? == c.channel,
        "channel identity differs",
    )?;
    require(
        sha(&c.source_sha, 40)
            && sha(&c.promotion_source_sha, 40)
            && sha(&c.admission_sha256, 64)
            && positive(c.generation)
            && positive(c.promotion_run_id)
            && positive(c.promotion_run_attempt),
        "invalid channel binding",
    )?;
    require(
        if c.generation == 1 {
            c.previous_sha256.is_none()
        } else {
            c.previous_sha256.as_deref().is_some_and(|v| sha(v, 64))
        },
        "invalid predecessor",
    )?;
    require(
        now < SAFE_INTEGER
            && c.issued_at <= now
            && c.expires_at < SAFE_INTEGER
            && c.expires_at > now
            && c.expires_at > c.issued_at
            && c.expires_at - c.issued_at <= 604800,
        "channel is expired or has invalid lifetime",
    )?;
    Ok(c)
}

/// Bind authenticated records to exact inventory bytes and observed operator
/// digest. Expected source/tag come from the independently admitted selection.
pub fn bind_release(
    admission_bytes: &[u8],
    inventory_bytes: &[u8],
    operator_sha: &str,
    expected_source: &str,
    expected_tag: &str,
) -> Result<(Admission, Inventory)> {
    let a = parse_admission(admission_bytes)?;
    let inv = parse_inventory(inventory_bytes)?;
    require(
        a.source_sha == expected_source
            && a.release_tag == expected_tag
            && inv.source_sha == a.source_sha
            && inv.release_tag == a.release_tag
            && inv.build_run_id == a.build_run_id
            && inv.build_run_attempt == a.build_run_attempt
            && sha256(inventory_bytes) == a.inventory_sha256
            && inv.artifact("marty-deploy-linux-amd64")?.sha256 == a.operator_sha256
            && a.operator_sha256 == operator_sha,
        "admitted release bytes or producer differ",
    )?;
    Ok((a, inv))
}
pub fn bind_channel(
    channel_bytes: &[u8],
    admission_bytes: &[u8],
    expected_channel: &str,
    now: u64,
) -> Result<Channel> {
    let c = parse_channel(channel_bytes, now)?;
    let a = parse_admission(admission_bytes)?;
    require(
        c.channel == expected_channel
            && c.admission_sha256 == sha256(admission_bytes)
            && c.source_sha == a.source_sha
            && c.release_tag == a.release_tag,
        "channel admission differs",
    )?;
    Ok(c)
}

/// Validate JSON emitted by a SUCCESSFUL pinned gh attestation verifier. This
/// cannot establish signature validity by itself. Official extra verifier and
/// certificate metadata is permitted; duplicate keys and conflicting legacy
/// identity fields are not. Record producers above have closed schemas.
pub fn verify_gh_certificate(
    output: &[u8],
    workflow: &str,
    source_sha: &str,
    run_id: u64,
    attempt: u64,
) -> Result<()> {
    require(
        pattern(workflow, r"\A\.github/workflows/[A-Za-z0-9_-]+\.ya?ml\z")
            && sha(source_sha, 40)
            && positive(run_id)
            && positive(attempt),
        "invalid expected certificate identity",
    )?;
    let result = decode(output, 4 * 1024 * 1024)?;
    let items = result
        .as_array()
        .ok_or("expected verified attestation array")?;
    require(
        items.len() == 1 && items[0].get("attestation").is_some_and(Value::is_object),
        "expected one verified attestation",
    )?;
    let cert = items[0]
        .pointer("/verificationResult/signature/certificate")
        .and_then(Value::as_object)
        .ok_or("verified certificate missing")?;
    let invocation =
        format!("https://github.com/{REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}");
    let signer = format!("https://github.com/{REPOSITORY}/{workflow}@{REF}");
    for (key, expected) in [
        ("issuer", ISSUER),
        ("runnerEnvironment", "github-hosted"),
        (
            "sourceRepositoryURI",
            "https://github.com/ElevenID/marty-ui",
        ),
        ("sourceRepositoryIdentifier", "1140864197"),
        ("sourceRepositoryDigest", source_sha),
        ("sourceRepositoryRef", REF),
        ("buildSignerURI", signer.as_str()),
        ("runInvocationURI", invocation.as_str()),
    ] {
        require(
            cert.get(key).and_then(Value::as_str) == Some(expected),
            "verified certificate identity differs",
        )?;
    }
    for (key, expected) in [
        ("githubWorkflowRepository", REPOSITORY),
        ("githubWorkflowSHA", source_sha),
        ("githubWorkflowRef", REF),
    ] {
        if let Some(value) = cert.get(key) {
            require(
                value.as_str() == Some(expected),
                "legacy certificate identity differs",
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn bytes(v: &Value) -> Vec<u8> {
        serde_json::to_vec(v).unwrap()
    }
    fn inventory() -> Value {
        json!({"schema":"elevenid.installer-inventory/v1","repository":REPOSITORY,"platform":"linux/amd64",
          "source_sha":"a".repeat(40),"release_tag":"v1.2.3-nightly.20261025.42","build_run_id":42,"build_run_attempt":1,
          "artifacts":[
            {"name":"install.sh","sha256":"b".repeat(64),"size":10},
            {"name":"marty-deploy-linux-amd64","sha256":"c".repeat(64),"size":20},
            {"name":"prepared-selfhost-bundle.zip","sha256":"d".repeat(64),"size":30},
            {"name":"prepared-selfhost-images.json","sha256":"e".repeat(64),"size":40}],
          "images":{"gateway":format!("ghcr.io/elevenid/app@sha256:{}","f".repeat(64)),
          "openbao_didcomm_image":format!("ghcr.io/elevenid/plugin@sha256:{}","f".repeat(64))}})
    }
    fn admission(inv: &[u8]) -> Value {
        json!({"schema":"elevenid.installer-admission/v1","repository":REPOSITORY,"platform":"linux/amd64","status":"accepted",
         "source_sha":"a".repeat(40),"release_tag":"v1.2.3-nightly.20261025.42","inventory_sha256":sha256(inv),
         "operator_sha256":"c".repeat(64),"build_run_id":42,"build_run_attempt":1,
         "promotion_source_sha":"b".repeat(40),"promotion_run_id":99,"promotion_run_attempt":2,
         "acceptance":{"staged":{"sha256":"d".repeat(64),"run_id":90,"run_attempt":1},
         "published":{"sha256":"e".repeat(64),"run_id":91,"run_attempt":2}}})
    }
    fn channel(a: &[u8]) -> Value {
        json!({"schema":"elevenid.installer-channel/v1","repository":REPOSITORY,"channel":"nightly","generation":1,
         "previous_sha256":null,"source_sha":"a".repeat(40),"release_tag":"v1.2.3-nightly.20261025.42",
         "admission_sha256":sha256(a),"promotion_source_sha":"f".repeat(40),"promotion_run_id":100,
         "promotion_run_attempt":1,"issued_at":1000,"expires_at":2000})
    }
    fn authorization(inv: &[u8]) -> Value {
        json!({"schema":"elevenid.installer-candidate-authorization/v1",
            "repository":REPOSITORY,"scope":"acceptance-only","source_ref":REF,"platform":"linux/amd64",
            "source_sha":"a".repeat(40),"release_tag":"v1.2.3-nightly.20261025.42",
            "inventory_sha256":sha256(inv),"operator_sha256":"c".repeat(64),
            "build_run_id":42,"build_run_attempt":1,"phase":"staged",
            "harness_source_sha":"b".repeat(40),"workflow":ACCEPTANCE_WORKFLOW,
            "run_id":90,"run_attempt":2,"issued_at":1000,"expires_at":4600,
            "nonce":"d".repeat(64)})
    }
    fn candidate_context() -> CandidateContext {
        CandidateContext {
            operator_sha: "c".repeat(64),
            source_sha: "a".repeat(40),
            release_tag: "v1.2.3-nightly.20261025.42".into(),
            phase: CandidatePhase::Staged,
            nonce: "d".repeat(64),
            harness_source_sha: "b".repeat(40),
            run_id: 90,
            run_attempt: 2,
        }
    }
    #[test]
    fn python_candidate_fixture_binds_exact_serialized_bytes() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/installer-candidate-records.json"
        ))
        .unwrap();
        let inventory = fixture["inventory"].as_str().unwrap().as_bytes();
        let authorization = fixture["authorization"].as_str().unwrap().as_bytes();
        let expected = CandidateContext {
            operator_sha: "a085d8a20cddaa36a743b4016b4e1f135cc0c25b7d5abf69285c68c054a5aed8".into(),
            source_sha: "a".repeat(40),
            release_tag: "v1.2.3".into(),
            phase: CandidatePhase::Staged,
            nonce: "e".repeat(64),
            harness_source_sha: "c".repeat(40),
            run_id: 99,
            run_attempt: 3,
        };
        assert_eq!(
            candidate_context_sha256(&expected).unwrap(),
            "fea75ea294741f68adcde307b631428cc7884016123abd4324462426fabbba6e"
        );
        let a: Value = serde_json::from_slice(authorization).unwrap();
        let mut receipt = json!({
            "schema":"elevenid.installer-controller-consumption/v1", "repository":REPOSITORY,
            "scope":"controller-dispatch-consumed", "source_ref":REF, "workflow":ACCEPTANCE_WORKFLOW,
            "authorization_sha256":sha256(authorization), "context_sha256":candidate_context_sha256(&expected).unwrap(),
            "inventory_sha256":sha256(inventory), "guest_id":"12345678-1234-4234-8234-123456789abc",
            "disk_id":"d".repeat(64), "engine_id":"test-engine-12345678",
            "installation_id":"22345678-1234-4234-8234-123456789abc", "consumed_at":100000
        });
        for field in [
            "nonce",
            "source_sha",
            "release_tag",
            "operator_sha256",
            "build_run_id",
            "build_run_attempt",
            "harness_source_sha",
            "run_id",
            "run_attempt",
            "phase",
        ] {
            receipt[field] = a[field].clone();
        }
        let bind = |r: &Value| {
            bind_controller_consumption(
                &bytes(r),
                authorization,
                inventory,
                &expected,
                "test-engine-12345678",
                100000,
            )
        };
        bind(&receipt).unwrap();
        for (field, value) in [
            ("schema", json!("bad")),
            ("scope", json!("acceptance-only")),
            ("authorization_sha256", json!("b".repeat(64))),
            ("context_sha256", json!("b".repeat(64))),
            ("inventory_sha256", json!("b".repeat(64))),
            ("source_sha", json!("b".repeat(40))),
            ("nonce", json!("b".repeat(64))),
            ("operator_sha256", json!("b".repeat(64))),
            ("build_run_id", json!(43)),
            ("build_run_attempt", json!(3)),
            ("harness_source_sha", json!("b".repeat(40))),
            ("run_id", json!(100)),
            ("run_attempt", json!(4)),
            ("phase", json!("published")),
            ("engine_id", json!("different-engine")),
            ("guest_id", json!("12345678-1234-1234-8234-123456789abc")),
            (
                "installation_id",
                json!("22345678-1234-4234-0234-123456789abc"),
            ),
            ("disk_id", json!("bad")),
            ("consumed_at", json!(99999)),
            ("consumed_at", json!(100001)),
            ("consumed_at", json!(true)),
            ("run_id", json!(SAFE_INTEGER)),
            ("extra", json!(1)),
        ] {
            let mut changed = receipt.clone();
            changed[field] = value;
            assert!(bind(&changed).is_err(), "{field}");
        }
        let raw = String::from_utf8(bytes(&receipt)).unwrap();
        let duplicate = raw.replacen('{', "{\"scope\":\"bad\",", 1);
        assert!(parse_controller_consumption(duplicate.as_bytes(), 100000).is_err());
        assert!(parse_admission(&bytes(&receipt)).is_err());
        assert!(parse_channel(&bytes(&receipt), 100000).is_err());
        assert!(bind_controller_consumption(
            &bytes(&receipt),
            authorization,
            inventory,
            &expected,
            "test-engine-12345678",
            103600
        )
        .is_err());
        assert_eq!(fixture["now"], json!(100000));
        let (a, inv) =
            bind_candidate_authorization(authorization, inventory, &expected, 100000).unwrap();
        assert_eq!(
            a.inventory_sha256,
            "57728fd27d81cf3523b3aef77d3e072cf50c64e7a6ea44fdf8060da6858d6b56"
        );
        assert_eq!((inv.build_run_id, inv.build_run_attempt), (42, 2));
        assert!(parse_admission(authorization).is_err());
        assert!(parse_channel(authorization, 100000).is_err());
        let mut reformatted = inventory.to_vec();
        reformatted.push(b' ');
        assert!(
            bind_candidate_authorization(authorization, &reformatted, &expected, 100000).is_err()
        );
    }
    #[test]
    fn candidate_authorization_is_separate_and_binds_exact_candidate() {
        let inv = bytes(&inventory());
        let original = authorization(&inv);
        let bind = |a: &Value, inv: &[u8], phase| {
            let context = CandidateContext {
                phase,
                ..candidate_context()
            };
            bind_candidate_authorization(&bytes(a), inv, &context, 1500)
        };
        let (a, _) = bind(&original, &inv, CandidatePhase::Staged).unwrap();
        assert_eq!(a.harness_source_sha, "b".repeat(40));
        let mut published = original.clone();
        published["phase"] = json!("published");
        bind(&published, &inv, CandidatePhase::Published).unwrap();
        assert!(bind(&original, &inv, CandidatePhase::Published).is_err());
        assert!(parse_admission(&bytes(&original)).is_err());
        assert!(parse_channel(&bytes(&original), 1500).is_err());
        assert!(parse_candidate_authorization(&bytes(&admission(&inv)), 1500).is_err());
        let mut changed = inv.clone();
        changed.push(b' ');
        assert!(bind(&original, &changed, CandidatePhase::Staged).is_err());
        for (field, value) in [
            ("source_sha", json!("e".repeat(40))),
            ("release_tag", json!("v1.2.4")),
            ("build_run_id", json!(43)),
            ("build_run_attempt", json!(2)),
            ("inventory_sha256", json!("e".repeat(64))),
            ("operator_sha256", json!("e".repeat(64))),
            ("nonce", json!("e".repeat(64))),
            ("harness_source_sha", json!("e".repeat(40))),
            ("run_id", json!(91)),
            ("run_attempt", json!(3)),
        ] {
            let mut changed = original.clone();
            changed[field] = value;
            assert!(
                bind(&changed, &inv, CandidatePhase::Staged).is_err(),
                "{field}"
            );
        }
        for (operator, source, tag) in [
            ("f".repeat(64), "a".repeat(40), "v1.2.3-nightly.20261025.42"),
            ("c".repeat(64), "f".repeat(40), "v1.2.3-nightly.20261025.42"),
            ("c".repeat(64), "a".repeat(40), "v1.2.4"),
        ] {
            let context = CandidateContext {
                operator_sha: operator,
                source_sha: source,
                release_tag: tag.into(),
                ..candidate_context()
            };
            assert!(bind_candidate_authorization(&bytes(&original), &inv, &context, 1500).is_err());
        }
        for field in ["nonce", "harness", "run", "attempt"] {
            let mut context = candidate_context();
            match field {
                "nonce" => context.nonce = "e".repeat(64),
                "harness" => context.harness_source_sha = "e".repeat(40),
                "run" => context.run_id += 1,
                _ => context.run_attempt += 1,
            }
            assert!(bind_candidate_authorization(&bytes(&original), &inv, &context, 1500).is_err());
        }
    }
    #[test]
    fn candidate_authorization_rejects_identity_time_and_ambiguous_records() {
        let original = authorization(&bytes(&inventory()));
        for (field, value) in [
            ("schema", json!("elevenid.installer-admission/v1")),
            ("repository", json!("other/repo")),
            ("scope", json!("accepted")),
            ("source_ref", json!("refs/heads/other")),
            ("platform", json!("linux/arm64")),
            ("workflow", json!(PROMOTION_WORKFLOW)),
            ("source_sha", json!("A".repeat(40))),
            ("release_tag", json!("latest")),
            ("harness_source_sha", json!("bad")),
            ("inventory_sha256", json!("bad")),
            ("operator_sha256", json!("bad")),
            ("nonce", json!("D".repeat(64))),
            ("phase", json!("accepted")),
            ("run_id", json!(0)),
            ("run_attempt", json!(SAFE_INTEGER)),
            ("build_run_id", json!(true)),
            ("build_run_attempt", json!(1.0)),
            ("issued_at", json!(1501)),
            ("issued_at", json!(-1)),
            ("issued_at", json!(0)),
            ("expires_at", json!(1500)),
            ("expires_at", json!(4601)),
            ("expires_at", json!(SAFE_INTEGER)),
            ("extra", json!(false)),
        ] {
            let mut changed = original.clone();
            changed[field] = value;
            assert!(
                parse_candidate_authorization(&bytes(&changed), 1500).is_err(),
                "{field}"
            );
        }
        assert!(parse_candidate_authorization(&bytes(&original), 1000).is_ok());
        assert!(parse_candidate_authorization(&bytes(&original), 4599).is_ok());
        assert!(parse_candidate_authorization(&bytes(&original), 999).is_err());
        assert!(parse_candidate_authorization(&bytes(&original), 4600).is_err());
        assert!(parse_candidate_authorization(&bytes(&original), SAFE_INTEGER).is_err());
        assert!(parse_candidate_authorization(&bytes(&original), 0).is_err());
        let mut zero_epoch = original.clone();
        zero_epoch["issued_at"] = json!(0);
        zero_epoch["expires_at"] = json!(3600);
        for now in [0, 1] {
            assert!(parse_candidate_authorization(&bytes(&zero_epoch), now).is_err());
        }
        for key in original.as_object().unwrap().keys() {
            let mut missing = original.clone();
            missing.as_object_mut().unwrap().remove(key);
            assert!(
                parse_candidate_authorization(&bytes(&missing), 1500).is_err(),
                "{key}"
            );
        }
        let duplicate = String::from_utf8(bytes(&original)).unwrap().replacen(
            '{',
            "{\"nonce\":\"duplicate\",",
            1,
        );
        assert!(parse_candidate_authorization(duplicate.as_bytes(), 1500).is_err());
        assert!(parse_candidate_authorization(&vec![b' '; MAX_RECORD + 1], 1500).is_err());
    }
    #[test]
    fn exact_records_bind_without_conflating_promotion_source() {
        let inv = bytes(&inventory());
        let a = bytes(&admission(&inv));
        let (accepted, _) = bind_release(
            &a,
            &inv,
            &"c".repeat(64),
            &"a".repeat(40),
            "v1.2.3-nightly.20261025.42",
        )
        .unwrap();
        assert_eq!(accepted.promotion_source_sha, "b".repeat(40));
        let c = bind_channel(&bytes(&channel(&a)), &a, "nightly", 1500).unwrap();
        assert_eq!(c.promotion_source_sha, "f".repeat(40));
        let mut changed = inv.clone();
        changed.push(b' ');
        assert!(bind_release(
            &a,
            &changed,
            &"c".repeat(64),
            &"a".repeat(40),
            "v1.2.3-nightly.20261025.42"
        )
        .is_err());
        assert!(bind_release(
            &a,
            &inv,
            &"f".repeat(64),
            &"a".repeat(40),
            "v1.2.3-nightly.20261025.42"
        )
        .is_err());
        assert!(bind_channel(&bytes(&channel(&a)), &a, "stable", 1500).is_err());
    }
    #[test]
    fn closed_records_reject_types_duplicates_unknowns_and_limits() {
        for value in [
            json!(true),
            json!(1.0),
            json!(0),
            json!(-1),
            json!(SAFE_INTEGER),
        ] {
            let mut inv = inventory();
            inv["build_run_id"] = value;
            assert!(parse_inventory(&bytes(&inv)).is_err());
        }
        let inv = inventory();
        let mut bad = inv.clone();
        bad["artifacts"][0] = bad["artifacts"][1].clone();
        assert!(parse_inventory(&bytes(&bad)).is_err());
        bad = inv.clone();
        bad["artifacts"][0]["size"] = json!(65537);
        assert!(parse_inventory(&bytes(&bad)).is_err());
        bad = inv.clone();
        bad["artifacts"][0]["extra"] = json!(true);
        assert!(parse_inventory(&bytes(&bad)).is_err());
        bad = inv.clone();
        bad["images"]["gateway"] = json!("image:latest");
        assert!(parse_inventory(&bytes(&bad)).is_err());
        let raw = String::from_utf8(bytes(&inv)).unwrap();
        let duplicate = raw.replace("\"images\":{", "\"images\":{\"gateway\":\"bad\",");
        assert!(parse_inventory(duplicate.as_bytes()).is_err());
        let duplicate = raw.replacen('{', "{\"schema\":\"bad\",", 1);
        assert!(parse_inventory(duplicate.as_bytes()).is_err());
        assert!(parse_inventory(&vec![b' '; MAX_RECORD + 1]).is_err());
    }
    #[test]
    fn admission_and_channel_mutations_are_refused() {
        let inv = bytes(&inventory());
        let original = admission(&inv);
        for (key, value) in [
            ("status", json!("failed")),
            ("promotion_source_sha", json!("bad")),
            ("platform", json!("linux/arm64")),
            ("surprise", json!(1)),
        ] {
            let mut a = original.clone();
            a[key] = value;
            assert!(parse_admission(&bytes(&a)).is_err());
        }
        let mut a = original.clone();
        a["acceptance"]["published"]["run_attempt"] = json!(true);
        assert!(parse_admission(&bytes(&a)).is_err());
        let original = channel(&bytes(&original));
        for (key, value) in [
            ("channel", json!("stable")),
            ("issued_at", json!(1501)),
            ("expires_at", json!(1500)),
            ("expires_at", json!(605801)),
            ("generation", json!(2)),
            ("generation", json!(SAFE_INTEGER)),
        ] {
            let mut c = original.clone();
            c[key] = value;
            assert!(parse_channel(&bytes(&c), 1500).is_err());
        }
        let mut c = original;
        c.as_object_mut().unwrap().remove("previous_sha256");
        assert!(parse_channel(&bytes(&c), 1500).is_err());
        assert!(release_tier("v1.2.3-nightly.20260230.1").is_err());
        assert!(release_tier("v01.2.3").is_err());
    }
    fn verified_output() -> Value {
        json!([{"attestation":{},"verificationResult":{"signature":{"certificate":{
          "issuer":ISSUER,"runnerEnvironment":"github-hosted","sourceRepositoryURI":"https://github.com/ElevenID/marty-ui",
          "sourceRepositoryIdentifier":"1140864197","sourceRepositoryDigest":"a".repeat(40),"sourceRepositoryRef":REF,
          "buildSignerURI":format!("https://github.com/{REPOSITORY}/{PROMOTION_WORKFLOW}@{REF}"),
          "runInvocationURI":format!("https://github.com/{REPOSITORY}/actions/runs/42/attempts/2")}}}}])
    }
    #[test]
    fn verifies_actual_invocation_fields_and_refuses_wrong_run_or_certificate() {
        let original = verified_output();
        let verify = |v: &Value| {
            verify_gh_certificate(&bytes(v), PROMOTION_WORKFLOW, &"a".repeat(40), 42, 2)
        };
        verify(&original).unwrap();
        for field in [
            "issuer",
            "runnerEnvironment",
            "sourceRepositoryURI",
            "sourceRepositoryIdentifier",
            "sourceRepositoryDigest",
            "sourceRepositoryRef",
            "buildSignerURI",
            "runInvocationURI",
        ] {
            let mut value = original.clone();
            value[0]["verificationResult"]["signature"]["certificate"][field] = json!("wrong");
            assert!(verify(&value).is_err());
        }
        assert!(verify_gh_certificate(
            &bytes(&original),
            PROMOTION_WORKFLOW,
            &"a".repeat(40),
            42,
            1
        )
        .is_err());
        let mut bad = original.clone();
        bad[0]["verificationResult"]["signature"]["certificate"]["githubWorkflowSHA"] =
            json!("b".repeat(40));
        assert!(verify(&bad).is_err());
        assert!(verify(&json!([original[0], original[0]])).is_err());
        assert!(verify(&json!([{"verificationResult":{}}])).is_err());
        let raw = String::from_utf8(bytes(&original))
            .unwrap()
            .replace("\"certificate\":{", "\"certificate\":{\"issuer\":\"bad\",");
        assert!(
            verify_gh_certificate(raw.as_bytes(), PROMOTION_WORKFLOW, &"a".repeat(40), 42, 2)
                .is_err()
        );
    }
}
