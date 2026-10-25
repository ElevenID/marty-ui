//! Strict installer record decoding and binding. No I/O or cryptography occurs
//! here: callers authenticate the exact input bytes and invoke a pinned verifier
//! successfully before applying the certificate-output checks below.
use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

pub type Result<T> = std::result::Result<T, String>;
pub const REPOSITORY: &str = "ElevenID/marty-ui";
pub const REF: &str = "refs/heads/main";
pub const ISSUER: &str = "https://token.actions.githubusercontent.com";
pub const PROMOTION_WORKFLOW: &str = ".github/workflows/installer-promote.yml";
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
struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = Unique;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("unambiguous JSON")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Unique, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| Unique(Value::Number(n)))
                    .ok_or_else(|| E::custom("nonfinite number"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut values = Vec::new();
                while let Some(Unique(v)) = seq.next_element()? {
                    values.push(v);
                }
                Ok(Unique(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(de::Error::custom("duplicate JSON field"));
                    }
                    let Unique(value) = map.next_value()?;
                    values.insert(key, value);
                }
                Ok(Unique(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(UniqueVisitor)
    }
}
fn decode(bytes: &[u8], limit: usize) -> Result<Value> {
    require(
        !bytes.is_empty() && bytes.len() <= limit,
        "installer JSON size exceeds bounds",
    )?;
    serde_json::from_slice::<Unique>(bytes)
        .map(|v| v.0)
        .map_err(|_| "invalid or ambiguous installer JSON".into())
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
