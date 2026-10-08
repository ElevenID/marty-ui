//! Sensitive passport artifact schema. Encryption is provided only by managed KMS.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::passport_signer::SignedMaterial;

#[derive(Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PassportSensitiveArtifact {
    pub applicant: Value,
    pub mrz: BTreeMap<String, String>,
    pub data_groups: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_material: Option<SignedMaterial>,
}
