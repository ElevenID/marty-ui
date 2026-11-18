use crate::{
    service::ApplicationEvent, Applicant, Application, Biometric, CheckStatus, Evidence,
    EvidenceStatus, VettingCheck,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct StoreDocument {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<String>,
    #[serde(default)]
    pub applicants: Vec<Applicant>,
    #[serde(default)]
    pub applications: Vec<Application>,
    #[serde(default)]
    pub biometrics: BTreeMap<String, Vec<Biometric>>,
    #[serde(default)]
    pub checks: Vec<VettingCheck>,
    #[serde(default)]
    pub evidence: Vec<Evidence>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pending_application_events: Vec<ApplicationEvent>,
}

impl StoreDocument {
    pub fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        serde_json::from_slice(bytes).map_err(StoreError::Malformed)
    }

    pub fn encode(&self) -> Result<Vec<u8>, StoreError> {
        serde_json::to_vec(self).map_err(StoreError::Malformed)
    }

    pub fn applicant(&self, id: &str) -> Option<&Applicant> {
        self.applicants.iter().find(|item| item.id == id)
    }

    pub fn applicant_for_user(&self, user_id: &str, organization_id: &str) -> Option<&Applicant> {
        self.applicants.iter().find(|item| {
            item.organization_id == organization_id
                && (item.user_id.as_deref() == Some(user_id)
                    || item.oidc_subject.as_deref() == Some(user_id))
        })
    }

    pub fn applicants_for_organization(&self, organization_id: &str) -> Vec<&Applicant> {
        self.applicants
            .iter()
            .filter(|item| item.organization_id == organization_id)
            .collect()
    }

    pub fn application(&self, id: &str) -> Option<&Application> {
        self.applications.iter().find(|item| item.id == id)
    }

    pub fn applications_for_applicant(&self, applicant_id: &str) -> Vec<&Application> {
        self.applications
            .iter()
            .filter(|item| item.applicant_id == applicant_id)
            .collect()
    }

    pub fn applications_for_organization(&self, organization_id: &str) -> Vec<&Application> {
        self.applications
            .iter()
            .filter(|item| item.organization_id == organization_id)
            .collect()
    }

    pub fn evidence_for_application(
        &self,
        application_id: &str,
        include_deleted: bool,
    ) -> Vec<&Evidence> {
        let mut evidence: Vec<_> = self
            .evidence
            .iter()
            .filter(|item| {
                item.application_id == application_id
                    && (include_deleted || item.status != EvidenceStatus::Deleted)
            })
            .collect();
        evidence.sort_by_key(|item| item.created_at);
        evidence
    }

    pub fn save_applicant(&mut self, applicant: Applicant) {
        replace_or_insert(&mut self.applicants, applicant, |item| &item.id);
    }

    pub fn save_application(&mut self, application: Application) {
        replace_or_insert(&mut self.applications, application, |item| &item.id);
    }

    pub fn save_evidence(&mut self, evidence: Evidence) {
        replace_or_insert(&mut self.evidence, evidence, |item| &item.id);
    }

    pub fn save_biometric(&mut self, biometric: Biometric) {
        let items = self
            .biometrics
            .entry(biometric.applicant_id.clone())
            .or_default();
        replace_or_insert(items, biometric, |item| &item.id);
    }

    pub fn save_check(&mut self, check: VettingCheck) {
        replace_or_insert(&mut self.checks, check, |item| &item.id);
    }

    pub fn checks_for_application(&self, application_id: &str) -> Vec<&VettingCheck> {
        let mut checks: Vec<_> = self
            .checks
            .iter()
            .filter(|item| item.application_id == application_id)
            .collect();
        checks.sort_by_key(|item| item.order);
        checks
    }

    pub fn pending_checks(&self, check_type: Option<crate::CheckType>) -> Vec<&VettingCheck> {
        self.checks
            .iter()
            .filter(|item| {
                matches!(
                    item.status,
                    CheckStatus::NotStarted
                        | CheckStatus::Pending
                        | CheckStatus::InProgress
                        | CheckStatus::RequiresManualReview
                ) && check_type.is_none_or(|expected| item.check_type == expected)
            })
            .collect()
    }
}

fn replace_or_insert<T, F>(items: &mut Vec<T>, value: T, id: F)
where
    F: Fn(&T) -> &str,
{
    if let Some(index) = items.iter().position(|item| id(item) == id(&value)) {
        items[index] = value;
    } else {
        items.push(value);
    }
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("applicant store is malformed: {0}")]
    Malformed(serde_json::Error),
}
