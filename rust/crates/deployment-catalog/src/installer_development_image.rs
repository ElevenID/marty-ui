//! One explicitly unsigned Signing Keys image for a fresh development scope.
//! The authenticated fixture inventory and every bootstrap image stay unchanged.

use crate::{
    installer_compose::{BoundFile, ComposeInputs},
    installer_release::sha256,
    installer_runtime::DockerRunner,
    installer_state::{ExecutionScope, LockedInspection},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::Path;

type Result<T> = std::result::Result<T, String>;
pub(crate) const ARTIFACT_RECORD: &str = "development-signing-image-artifact.json";
pub(crate) const BINDING_RECORD: &str = "development-signing-image-binding.json";
pub(crate) const LAYER_RECORD: &str = "development-signing-image.compose.json";
#[cfg(test)]
pub(crate) const ARCHIVE: &str = "development-signing-keys.oci.tar";
pub(crate) const ROLE: &str = "signing-keys";
pub(crate) const HELPER_IDENTITY: &str = "unknown:unsigned-installer-development";
const REFUSED: &str = "Unsigned development Signing Keys image binding refused";

fn require(value: bool) -> Result<()> {
    value.then_some(()).ok_or_else(|| REFUSED.into())
}
pub(crate) fn digest(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn image_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|v| digest(v, 64))
}
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_value(crate::installer_json::decode(bytes).map_err(|_| REFUSED)?)
        .map_err(|_| REFUSED.into())
}

/// Produced by the existing bounded OCI inspector's closed development profile.
/// These are unsigned local build facts, never release or publisher authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Artifact {
    pub schema: String,
    pub role: String,
    pub source_sha: String,
    pub source_tree_sha: String,
    pub dockerfile_sha256: String,
    pub build_metadata_sha256: String,
    pub archive_sha256: String,
    pub archive_size: u64,
    pub manifest_digest: String,
    pub config_digest: String,
    pub platform: String,
    pub version: String,
    pub archive_tag: String,
}
impl Artifact {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        let artifact: Self = decode(bytes)?;
        artifact.validate()?;
        Ok(artifact)
    }
    fn validate(&self) -> Result<()> {
        require(
            self.schema == "elevenid.installer-development-signing-image/v1"
                && self.role == ROLE
                && digest(&self.source_sha, 40)
                && digest(&self.source_tree_sha, 40)
                && self.dockerfile_sha256
                    == sha256(include_bytes!("../../../services/signing-keys/Dockerfile"))
                && digest(&self.build_metadata_sha256, 64)
                && digest(&self.archive_sha256, 64)
                && (1..=536870912).contains(&self.archive_size)
                && image_digest(&self.manifest_digest)
                && image_digest(&self.config_digest)
                && self.platform == "linux/amd64"
                && self.version == format!("unsigned-installer-development-{}", self.source_sha)
                && self.archive_tag
                    == format!("installer-development-signing-keys-{}", self.source_sha),
        )
    }
    #[cfg(test)]
    pub(crate) fn verify_archive(&self, path: &Path) -> Result<()> {
        self.validate()?;
        crate::installer_verify::check_private_asset(path, &self.archive_sha256, self.archive_size)
    }
}

/// Persisted native image observation. A tag is never lifecycle authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DevelopmentImage {
    pub artifact_sha256: String,
    pub artifact: Artifact,
    pub image_id: String,
    pub descriptor_digest: Option<String>,
}
impl DevelopmentImage {
    fn validate(&self) -> Result<()> {
        self.artifact.validate()?;
        require(
            digest(&self.artifact_sha256, 64)
                && image_digest(&self.image_id)
                && self.descriptor_digest.as_deref().is_none_or(image_digest)
                && (self.image_id == self.artifact.config_digest
                    || self.descriptor_digest.as_deref()
                        == Some(self.artifact.manifest_digest.as_str())),
        )
    }
    #[cfg(test)]
    pub(crate) fn from_inspected(artifact_bytes: &[u8], observed: &Value) -> Result<Self> {
        let artifact = Artifact::parse(artifact_bytes)?;
        let binding = Self {
            artifact_sha256: sha256(artifact_bytes),
            artifact,
            image_id: observed["Id"].as_str().ok_or(REFUSED)?.into(),
            descriptor_digest: observed
                .get("Descriptor")
                .filter(|v| !v.is_null())
                .map(|v| v["digest"].as_str().map(str::to_owned).ok_or(REFUSED))
                .transpose()?,
        };
        binding.validate_inspected(observed)?;
        Ok(binding)
    }
    pub(crate) fn validate_inspected(&self, observed: &Value) -> Result<()> {
        self.validate()?;
        let config = &observed["Config"];
        let env = config["Env"].as_array().ok_or(REFUSED)?;
        for (name, expected) in [
            ("MARTY_UI_SHA", &self.artifact.source_sha),
            ("MARTY_RELEASE_VERSION", &self.artifact.version),
        ] {
            let values: Vec<_> = env
                .iter()
                .filter_map(Value::as_str)
                .filter(|value| value.starts_with(&format!("{name}=")))
                .collect();
            require(values == [format!("{name}={expected}")])?;
        }
        require(
            observed["Id"] == self.image_id
                && observed["Os"] == "linux"
                && observed["Architecture"] == "amd64"
                && observed
                    .get("Descriptor")
                    .filter(|v| !v.is_null())
                    .and_then(|v| v["digest"].as_str())
                    == self.descriptor_digest.as_deref()
                && config["User"] == "10001:10001"
                && config["Entrypoint"] == json!(["/usr/local/bin/marty-signing-keys"])
                && env
                    .iter()
                    .filter_map(Value::as_str)
                    .all(|value| !value.starts_with("SERVICE_NAME="))
                && config["Labels"]["org.opencontainers.image.source"]
                    == "https://github.com/ElevenID/marty-ui"
                && config["Labels"]["org.opencontainers.image.revision"]
                    == self.artifact.source_sha
                && config["Labels"]["org.opencontainers.image.version"] == self.artifact.version,
        )
    }
    pub(crate) fn inspect(&self, docker: &DockerRunner) -> Result<()> {
        let values: Vec<Value> = decode(
            docker
                .run_checked(&["image", "inspect", &self.image_id])?
                .as_bytes(),
        )?;
        require(values.len() == 1)?;
        self.validate_inspected(&values[0])
    }
    pub(crate) fn permits(&self, role: &str, reference: &str) -> bool {
        role == ROLE && reference == self.image_id
    }
    pub(crate) fn require_scope(&self, journal: &crate::installer_state::Journal) -> Result<()> {
        let ExecutionScope::UnsignedDevelopment(scope) = journal.execution_scope() else {
            return Err(REFUSED.into());
        };
        require(scope.artifact_sha256 == self.artifact_sha256)
    }
    pub(crate) fn layer_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(
            &json!({"services": {ROLE: {"image": self.image_id, "pull_policy": "never"}}}),
        )
        .map_err(|_| REFUSED.into())
    }
    pub(crate) fn bind_inputs(&self, inputs: &mut ComposeInputs) -> Result<()> {
        self.validate()?;
        require(inputs.development_image.is_none())?;
        inputs.approved_images.insert(self.image_id.clone());
        inputs.development_image = Some(self.clone());
        inputs.files.push(self.layer_file(&inputs.installation)?);
        inputs.bound_inputs.extend([
            BoundFile {
                path: inputs.installation.join("evidence").join(ARTIFACT_RECORD),
                sha256: self.artifact_sha256.clone(),
            },
            BoundFile {
                path: inputs.installation.join("evidence").join(BINDING_RECORD),
                sha256: sha256(&serde_json::to_vec(self).map_err(|_| REFUSED)?),
            },
        ]);
        Ok(())
    }
    pub(crate) fn layer_file(&self, installation: &Path) -> Result<BoundFile> {
        Ok(BoundFile {
            path: installation.join("evidence").join(LAYER_RECORD),
            sha256: sha256(&self.layer_bytes()?),
        })
    }
    pub(crate) fn require_inputs(&self, inputs: &ComposeInputs) -> Result<()> {
        self.validate()?;
        let layer = self.layer_file(&inputs.installation)?;
        let binding_sha = sha256(&serde_json::to_vec(self).map_err(|_| REFUSED)?);
        require(
            inputs.approved_images.contains(&self.image_id)
                && inputs
                    .files
                    .last()
                    .is_some_and(|file| file.path == layer.path && file.sha256 == layer.sha256)
                && inputs.bound_inputs.iter().any(|file| {
                    file.path == inputs.installation.join("evidence").join(ARTIFACT_RECORD)
                        && file.sha256 == self.artifact_sha256
                })
                && inputs.bound_inputs.iter().any(|file| {
                    file.path == inputs.installation.join("evidence").join(BINDING_RECORD)
                        && file.sha256 == binding_sha
                }),
        )
    }
}

/// Reload the same journal-bound unsigned authority for lifecycle, trust and KMS.
/// No ordinary/candidate installation can acquire authority by adding a sidecar.
pub(crate) fn load(view: &LockedInspection) -> Result<Option<DevelopmentImage>> {
    require(env!("MARTY_DEPLOY_BUILD_IDENTITY") == HELPER_IDENTITY)?;
    let artifact = view.diagnostic_record(ARTIFACT_RECORD, true)?;
    let binding = view.diagnostic_record(BINDING_RECORD, true)?;
    let ExecutionScope::UnsignedDevelopment(scope) = view.journal().execution_scope() else {
        require(artifact.is_none() && binding.is_none())?;
        return Ok(None);
    };
    let fixture_bytes = view.read_evidence("installer-inventory.json")?;
    let fixture = crate::installer_release::parse_inventory(&fixture_bytes)?;
    require(
        sha256(&fixture_bytes) == scope.fixture.inventory_sha256
            && fixture.build_run_id == scope.fixture.build_run_id
            && fixture.build_run_attempt == scope.fixture.build_run_attempt,
    )?;
    let image = decode_binding(
        &scope.artifact_sha256,
        &artifact.ok_or(REFUSED)?,
        &binding.ok_or(REFUSED)?,
    )?;
    Ok(Some(image))
}

fn decode_binding(expected: &str, artifact: &[u8], binding: &[u8]) -> Result<DevelopmentImage> {
    require(sha256(artifact) == expected)?;
    let image: DevelopmentImage = decode(binding)?;
    image.validate()?;
    require(image.artifact == Artifact::parse(artifact)? && image.artifact_sha256 == expected)?;
    Ok(image)
}

#[cfg(test)]
pub(crate) fn test_fixture() -> DevelopmentImage {
    let source = "a".repeat(40);
    let artifact = Artifact {
        schema: "elevenid.installer-development-signing-image/v1".into(),
        role: ROLE.into(),
        source_sha: source.clone(),
        source_tree_sha: "b".repeat(40),
        dockerfile_sha256: sha256(include_bytes!("../../../services/signing-keys/Dockerfile")),
        build_metadata_sha256: "c".repeat(64),
        archive_sha256: sha256(b"private OCI fixture"),
        archive_size: b"private OCI fixture".len() as u64,
        manifest_digest: format!("sha256:{}", "d".repeat(64)),
        config_digest: format!("sha256:{}", "e".repeat(64)),
        platform: "linux/amd64".into(),
        version: format!("unsigned-installer-development-{source}"),
        archive_tag: format!("installer-development-signing-keys-{source}"),
    };
    DevelopmentImage {
        artifact_sha256: sha256(&serde_json::to_vec(&artifact).unwrap()),
        image_id: artifact.config_digest.clone(),
        descriptor_digest: None,
        artifact,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn inspected(binding: &DevelopmentImage) -> Value {
        json!({"Id":binding.image_id,"Os":"linux","Architecture":"amd64", "RepoDigests":[],
            "Config":{"User":"10001:10001","Entrypoint":["/usr/local/bin/marty-signing-keys"],
                "Env":[format!("MARTY_UI_SHA={}",binding.artifact.source_sha),
                    format!("MARTY_RELEASE_VERSION={}",binding.artifact.version)],
                "Labels":{"org.opencontainers.image.source":"https://github.com/ElevenID/marty-ui",
                    "org.opencontainers.image.revision":binding.artifact.source_sha,
                    "org.opencontainers.image.version":binding.artifact.version}}})
    }

    #[test]
    fn development_artifact_rejects_wrong_role_source_platform_and_unbound_build_facts() {
        let value = serde_json::to_value(test_fixture().artifact).unwrap();
        Artifact::parse(&serde_json::to_vec(&value).unwrap()).unwrap();
        for (field, wrong) in [
            ("schema", json!("elevenid.verification-candidate/v1")),
            ("role", json!("gateway")),
            ("source_sha", json!("unknown")),
            ("source_tree_sha", json!("A".repeat(40))),
            ("dockerfile_sha256", json!("0".repeat(64))),
            ("build_metadata_sha256", json!("")),
            ("archive_sha256", json!("bad")),
            ("archive_size", json!(0)),
            ("archive_size", json!(536870913u64)),
            ("manifest_digest", json!("tag:latest")),
            ("config_digest", json!(false)),
            ("platform", json!("linux/arm64")),
            ("version", json!("nightly")),
            ("archive_tag", json!("candidate-other")),
            ("publisher_authenticated", json!(true)),
        ] {
            let mut changed = value.clone();
            changed[field] = wrong;
            assert!(
                Artifact::parse(&serde_json::to_vec(&changed).unwrap()).is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn development_native_identity_accepts_config_or_exact_descriptor_without_repository_aliases() {
        let binding = test_fixture();
        let bytes = serde_json::to_vec(&binding.artifact).unwrap();
        let observed = inspected(&binding);
        assert_eq!(
            DevelopmentImage::from_inspected(&bytes, &observed).unwrap(),
            binding
        );
        assert!(crate::installer_compose::validate_image_digest(
            &observed,
            &format!(
                "ghcr.io/elevenid/marty-ui-oss/services@{}",
                binding.artifact.manifest_digest
            )
        )
        .is_err());
        let mut observed = observed;
        observed["Id"] = json!(format!("sha256:{}", "f".repeat(64)));
        assert!(DevelopmentImage::from_inspected(&bytes, &observed).is_err());
        observed["Descriptor"] = json!({"digest":binding.artifact.manifest_digest});
        let native = DevelopmentImage::from_inspected(&bytes, &observed).unwrap();
        assert_eq!(native.image_id, format!("sha256:{}", "f".repeat(64)));
        observed["Descriptor"]["digest"] = json!(format!("sha256:{}", "0".repeat(64)));
        assert!(DevelopmentImage::from_inspected(&bytes, &observed).is_err());
    }

    #[test]
    fn development_native_identity_rejects_image_platform_code_and_entrypoint_drift() {
        let binding = test_fixture();
        let bytes = serde_json::to_vec(&binding.artifact).unwrap();
        let valid = inspected(&binding);
        for (path, wrong) in [
            ("/Id", json!(format!("sha256:{}", "f".repeat(64)))),
            ("/Os", json!("windows")),
            ("/Architecture", json!("arm64")),
            ("/Config/User", json!("0:0")),
            ("/Config/Entrypoint", json!(["/bin/sh"])),
            (
                "/Config/Labels/org.opencontainers.image.revision",
                json!("b".repeat(40)),
            ),
            (
                "/Config/Labels/org.opencontainers.image.source",
                json!("https://example.invalid/fork"),
            ),
            (
                "/Config/Labels/org.opencontainers.image.version",
                json!("development"),
            ),
            (
                "/Config/Env",
                json!([
                    format!("MARTY_UI_SHA={}", binding.artifact.source_sha),
                    format!("MARTY_RELEASE_VERSION={}", binding.artifact.version),
                    "SERVICE_NAME=verification"
                ]),
            ),
            (
                "/Config/Env",
                json!([
                    format!("MARTY_UI_SHA={}", binding.artifact.source_sha),
                    format!("MARTY_UI_SHA={}", binding.artifact.source_sha),
                    format!("MARTY_RELEASE_VERSION={}", binding.artifact.version)
                ]),
            ),
        ] {
            let mut changed = valid.clone();
            *changed.pointer_mut(path).unwrap() = wrong;
            assert!(
                DevelopmentImage::from_inspected(&bytes, &changed).is_err(),
                "{path}"
            );
        }
    }

    #[test]
    fn development_readback_binds_exact_artifact_bytes_and_native_identity() {
        let image = test_fixture();
        let artifact = serde_json::to_vec(&image.artifact).unwrap();
        let binding = serde_json::to_vec(&image).unwrap();
        assert_eq!(
            decode_binding(&image.artifact_sha256, &artifact, &binding).unwrap(),
            image
        );
        assert!(decode_binding(&"0".repeat(64), &artifact, &binding).is_err());
        let mut rewritten = artifact.clone();
        rewritten.push(b'\n');
        assert!(decode_binding(&image.artifact_sha256, &rewritten, &binding).is_err());
        for field in ["image_id", "artifact_sha256"] {
            let mut changed = serde_json::to_value(&image).unwrap();
            changed[field] = json!(format!("sha256:{}", "0".repeat(64)));
            assert!(decode_binding(
                &image.artifact_sha256,
                &artifact,
                &serde_json::to_vec(&changed).unwrap()
            )
            .is_err());
        }
        let mut changed = serde_json::to_value(&image).unwrap();
        changed["artifact"]["build_metadata_sha256"] = json!("0".repeat(64));
        assert!(decode_binding(
            &image.artifact_sha256,
            &artifact,
            &serde_json::to_vec(&changed).unwrap()
        )
        .is_err());
    }

    #[test]
    fn development_archive_hash_is_checked_before_import_and_layer_changes_one_role() {
        let image = test_fixture();
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let archive = root.path().join("image.oci.tar");
        std::fs::write(&archive, b"private OCI fixture").unwrap();
        std::fs::set_permissions(&archive, std::fs::Permissions::from_mode(0o600)).unwrap();
        image.artifact.verify_archive(&archive).unwrap();
        std::fs::write(&archive, b"private OCI changed").unwrap();
        assert!(image.artifact.verify_archive(&archive).is_err());
        assert_eq!(
            serde_json::from_slice::<Value>(&image.layer_bytes().unwrap()).unwrap(),
            json!({"services":{"signing-keys":{"image":image.image_id,"pull_policy":"never"}}})
        );
        assert!(image.permits("signing-keys", &image.image_id));
        assert!(!image.permits("gateway", &image.image_id));
        assert!(!image.permits("installer-tls", &image.image_id));
    }
}
