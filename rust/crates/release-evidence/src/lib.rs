//! Shared release-run validation and lossless deployment evidence transport.
//! Run-validator input comes from the authenticated repository-scoped Actions API.
//! Run validation checks identity, not publication: callers must also verify the
//! signed manifest and its exact release/version/source component binding.

use serde::Deserialize;

pub mod deployment_bundle;

pub const MAX_RUN_BYTES: usize = 1024 * 1024;
const REPOSITORY: &str = "ElevenID/marty-ui";

#[derive(Deserialize)]
struct Repository {
    full_name: String,
}

#[derive(Deserialize)]
struct ReleaseRun {
    id: u64,
    name: String,
    path: String,
    event: String,
    head_branch: String,
    head_sha: String,
    status: String,
    conclusion: String,
    repository: Repository,
    head_repository: Repository,
}

fn is_source(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_version(value: &str) -> bool {
    let parts: Vec<_> = value.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

/// Returns only the validated source SHA; errors never echo API/argument data.
pub fn validate_release_run(
    bytes: &[u8],
    run_id: u64,
    version: &str,
    expected_source: Option<&str>,
) -> Result<String, &'static str> {
    if run_id == 0
        || !is_version(version)
        || expected_source.is_some_and(|source| !is_source(source))
    {
        return Err("invalid expected release identity");
    }
    if bytes.len() > MAX_RUN_BYTES {
        return Err("release run response exceeds size limit");
    }
    let run: ReleaseRun =
        serde_json::from_slice(bytes).map_err(|_| "invalid release run response")?;
    if run.id != run_id
        || run.repository.full_name != REPOSITORY
        || run.head_repository.full_name != REPOSITORY
    {
        return Err("release run repository or ID mismatch");
    }
    if run.status != "completed"
        || run.conclusion != "success"
        || run.name != "Stack release"
        || run.path != ".github/workflows/cd.yml"
    {
        return Err("release run is not a successful stack workflow");
    }
    // Current digest-first releases dispatch on protected main. Preserve
    // historical tag-push evidence, but only for this exact requested version.
    let current = run.event == "workflow_dispatch" && run.head_branch == "main";
    let historical = run.event == "push" && run.head_branch == format!("v{version}");
    if !current && !historical {
        return Err("release run trigger or ref mismatch");
    }
    if !is_source(&run.head_sha) || expected_source.is_some_and(|source| source != run.head_sha) {
        return Err("release run source mismatch");
    }
    Ok(run.head_sha)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    const SOURCE: &str = "1866528ab859ea7007ca34671ad80a62131fd79d";
    const RUN_ID: u64 = 33937499784;

    fn published_215() -> Value {
        // Allowlisted fields read from the actual successful beta215 run.
        serde_json::from_str(include_str!("../tests/fixtures/published-1.1.215.json")).unwrap()
    }

    fn check(run: &Value) -> Result<String, &'static str> {
        validate_release_run(
            &serde_json::to_vec(run).unwrap(),
            RUN_ID,
            "1.1.215",
            Some(SOURCE),
        )
    }

    #[test]
    fn actual_digest_first_release_and_exact_historical_tag_are_accepted() {
        let mut run = published_215();
        assert_eq!(check(&run), Ok(SOURCE.into()));
        assert_eq!(
            validate_release_run(&serde_json::to_vec(&run).unwrap(), RUN_ID, "1.1.215", None),
            Ok(SOURCE.into())
        );
        run["event"] = json!("push");
        run["head_branch"] = json!("v1.1.215");
        assert_eq!(check(&run), Ok(SOURCE.into()));
    }

    #[test]
    fn run_identity_trigger_source_and_repository_substitutions_are_rejected() {
        for (field, value) in [
            ("id", json!(RUN_ID + 1)),
            ("id", json!("33937499784")),
            ("name", json!("Other workflow")),
            ("path", json!(".github/workflows/other.yml")),
            ("event", json!("pull_request")),
            ("event", json!("push")),
            ("head_branch", json!("feature")),
            ("head_branch", json!("v1.1.215")),
            ("head_sha", json!("a".repeat(40))),
            ("head_sha", json!(SOURCE.to_uppercase())),
            ("head_sha", json!("bad")),
            ("status", json!("in_progress")),
            ("conclusion", json!("failure")),
            ("conclusion", json!("cancelled")),
            ("conclusion", Value::Null),
            ("repository", json!({"full_name": "Other/marty-ui"})),
            ("head_repository", json!({"full_name": "Other/marty-ui"})),
        ] {
            let mut run = published_215();
            run[field] = value;
            assert!(check(&run).is_err(), "must reject changed {field}");
        }
        let mut historical = published_215();
        historical["event"] = json!("push");
        historical["head_branch"] = json!("v1.1.214");
        assert!(check(&historical).is_err());
        for field in published_215().as_object().unwrap().keys() {
            let mut run = published_215();
            run.as_object_mut().unwrap().remove(field);
            assert!(check(&run).is_err(), "must reject missing {field}");
        }
    }

    #[test]
    fn malformed_or_unbounded_inputs_fail_closed_without_echoing_them() {
        for bytes in [
            b"not-json".to_vec(),
            b"[]".to_vec(),
            vec![b' '; MAX_RUN_BYTES + 1],
        ] {
            assert!(validate_release_run(&bytes, RUN_ID, "1.1.215", None).is_err());
        }
        let bytes = serde_json::to_vec(&published_215()).unwrap();
        for version in ["", "v1.1.215", "1.1", "1.1.215\n", "1.x.215"] {
            assert!(validate_release_run(&bytes, RUN_ID, version, None).is_err());
        }
        assert!(validate_release_run(&bytes, 0, "1.1.215", None).is_err());
        assert!(validate_release_run(&bytes, RUN_ID, "1.1.215", Some("private-value")).is_err());
    }
}
