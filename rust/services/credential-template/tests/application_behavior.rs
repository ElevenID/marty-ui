use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use chrono::{TimeZone, Utc};
use marty_credential_template::{
    application::{
        ControlPlaneError, CreateTemplateCommand, CredentialTemplateApplication,
        CredentialTemplateControlPlane, CredentialTemplateRepository, IssuerIdentity,
        UpdateTemplateCommand, UpdateTemplatePatch,
    },
    ClaimDefinition, ClaimType, CredentialFormat, CredentialTemplate,
    CredentialTemplateRepositoryError, DisplayStyle, PrivacyPosture, TemplateStatus,
};

#[derive(Default)]
struct MemoryRepository {
    templates: Mutex<BTreeMap<String, CredentialTemplate>>,
    fail_internal: bool,
}

#[async_trait]
impl CredentialTemplateRepository for MemoryRepository {
    async fn save(
        &self,
        template: &CredentialTemplate,
    ) -> Result<(), CredentialTemplateRepositoryError> {
        self.templates
            .lock()
            .unwrap()
            .insert(template.id.clone(), template.clone());
        Ok(())
    }

    async fn by_id(
        &self,
        template_id: &str,
    ) -> Result<Option<CredentialTemplate>, CredentialTemplateRepositoryError> {
        Ok(self.templates.lock().unwrap().get(template_id).cloned())
    }

    async fn by_organization(
        &self,
        organization_id: &str,
        status: Option<TemplateStatus>,
    ) -> Result<Vec<CredentialTemplate>, CredentialTemplateRepositoryError> {
        Ok(self
            .templates
            .lock()
            .unwrap()
            .values()
            .filter(|template| {
                template.organization_id == organization_id
                    && status.is_none_or(|status| template.status == status)
            })
            .cloned()
            .collect())
    }

    async fn all_internal(
        &self,
        status: Option<TemplateStatus>,
    ) -> Result<Vec<CredentialTemplate>, CredentialTemplateRepositoryError> {
        if self.fail_internal {
            return Err(CredentialTemplateRepositoryError::InvalidData {
                field: "forced",
                value: "repository unavailable".to_owned(),
            });
        }
        Ok(self
            .templates
            .lock()
            .unwrap()
            .values()
            .filter(|template| status.is_none_or(|status| template.status == status))
            .cloned()
            .collect())
    }

    async fn delete(&self, template_id: &str) -> Result<bool, CredentialTemplateRepositoryError> {
        Ok(self.templates.lock().unwrap().remove(template_id).is_some())
    }
}

struct ControlPlane {
    deny_membership: bool,
    deny_revocation: bool,
    deny_trust: bool,
}

#[async_trait]
impl CredentialTemplateControlPlane for ControlPlane {
    async fn require_membership(
        &self,
        user_id: &str,
        organization_id: &str,
    ) -> Result<(), ControlPlaneError> {
        if self.deny_membership || user_id != "user-1" || organization_id != "org-1" {
            Err(ControlPlaneError::MembershipRequired)
        } else {
            Ok(())
        }
    }

    async fn require_wallet_admin(
        &self,
        user_id: &str,
        organization_id: &str,
    ) -> Result<(), ControlPlaneError> {
        self.require_membership(user_id, organization_id).await
    }

    async fn require_destination_admin(
        &self,
        user_id: &str,
        organization_id: &str,
    ) -> Result<(), ControlPlaneError> {
        self.require_membership(user_id, organization_id).await
    }

    async fn organization_display_name(
        &self,
        organization_id: &str,
    ) -> Result<Option<String>, ControlPlaneError> {
        Ok((organization_id == "org-1").then(|| "Example Organization".to_owned()))
    }

    async fn resolve_active_issuer(
        &self,
        organization_id: &str,
        requested_issuer_did: Option<&str>,
        credential_format: &str,
    ) -> Result<IssuerIdentity, ControlPlaneError> {
        assert_eq!(organization_id, "org-1");
        assert_eq!(credential_format, "sd_jwt_vc");
        Ok(IssuerIdentity {
            issuer_did: requested_issuer_did
                .unwrap_or("did:web:issuer.example")
                .to_owned(),
            issuer_algorithm: "ES256".to_owned(),
        })
    }

    async fn require_active_revocation_profile(
        &self,
        organization_id: &str,
        revocation_profile_id: Option<&str>,
    ) -> Result<(), ControlPlaneError> {
        assert_eq!(organization_id, "org-1");
        if self.deny_revocation || revocation_profile_id != Some("revocation-1") {
            Err(ControlPlaneError::InvalidRevocationProfile(
                "inactive".to_owned(),
            ))
        } else {
            Ok(())
        }
    }

    async fn require_trust_profile_accepts_issuer(
        &self,
        trust_profile_id: Option<&str>,
        issuer_did: &str,
    ) -> Result<(), ControlPlaneError> {
        assert_eq!(issuer_did, "did:web:issuer.example");
        if self.deny_trust || trust_profile_id != Some("trust-1") {
            Err(ControlPlaneError::TrustProfileRejected(
                "issuer rejected".to_owned(),
            ))
        } else {
            Ok(())
        }
    }
}

fn claim(name: &str) -> ClaimDefinition {
    ClaimDefinition {
        id: format!("claim-{name}"),
        name: name.to_owned(),
        display_name: name.replace('_', " "),
        description: None,
        claim_type: ClaimType::String,
        required: true,
        selectively_disclosable: true,
        derivable: false,
        derived_from: None,
        pattern: None,
        enum_values: None,
        min_value: None,
        max_value: None,
        mdoc_namespace: None,
        mdoc_element_identifier: None,
        display_icon: None,
    }
}

fn command() -> CreateTemplateCommand {
    CreateTemplateCommand {
        user_id: "user-1".to_owned(),
        organization_id: "org-1".to_owned(),
        name: "Employee Badge".to_owned(),
        description: Some("Employee identity".to_owned()),
        credential_type: "EmployeeBadge".to_owned(),
        vct: Some("https://issuer.example/EmployeeBadge".to_owned()),
        doctype: None,
        claims: vec![claim("family_name")],
        privacy_posture: PrivacyPosture::SelectiveDisclosure,
        selective_disclosure_fields: vec!["family_name".to_owned()],
        zk_predicate_claims: Vec::new(),
        derived_attributes: Vec::new(),
        display_style: None,
        validity_rules: None,
        supported_formats: vec![CredentialFormat::SdJwtVc],
        application_template_id: None,
        trust_profile_id: Some("trust-1".to_owned()),
        revocation_profile_id: Some("revocation-1".to_owned()),
        compliance_profile: None,
        compliance_profile_id: "compliance-1".to_owned(),
        issuer_did: None,
        credential_payload_format: Some("w3c_vcdm_v2_sd_jwt".to_owned()),
        now: Utc.with_ymd_and_hms(2026, 8, 21, 12, 0, 0).unwrap(),
    }
}

fn build_application(
    control_plane: ControlPlane,
) -> (Arc<MemoryRepository>, CredentialTemplateApplication) {
    let repository = Arc::new(MemoryRepository::default());
    let application =
        CredentialTemplateApplication::new(repository.clone(), Arc::new(control_plane));
    (repository, application)
}

#[tokio::test]
async fn create_update_and_list_are_tenant_bound_and_lossless() {
    let (repository, application) = build_application(ControlPlane {
        deny_membership: false,
        deny_revocation: false,
        deny_trust: false,
    });
    let created = application
        .create_template(command())
        .await
        .expect("valid template creation");
    assert_eq!(created.status, TemplateStatus::Draft);
    assert_eq!(
        created.issuer_did.as_deref(),
        Some("did:web:issuer.example")
    );
    assert_eq!(created.credential_payload_format, "SD_JWT_VC");

    let updated = application
        .update_template(UpdateTemplateCommand {
            user_id: "user-1".to_owned(),
            template_id: created.id.clone(),
            patch: UpdateTemplatePatch {
                claims: Some(vec![claim("given_name"), claim("family_name")]),
                display_style: Some(DisplayStyle {
                    background_color: "#000000".to_owned(),
                    ..DisplayStyle::default()
                }),
                ..UpdateTemplatePatch::default()
            },
            now: Utc.with_ymd_and_hms(2026, 8, 21, 13, 0, 0).unwrap(),
        })
        .await
        .expect("draft update");
    assert_eq!(updated.claims.len(), 2);
    assert_eq!(updated.display_style.background_color, "#000000");
    assert_eq!(
        application
            .list_templates("user-1", "org-1", Some(TemplateStatus::Draft), 100, 0)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(repository.templates.lock().unwrap().len(), 1);
    assert!(application
        .get_template("other-user", &created.id)
        .await
        .is_err());
}

#[tokio::test]
async fn activation_requires_live_revocation_trust_and_issuer_checks() {
    let (_, application) = build_application(ControlPlane {
        deny_membership: false,
        deny_revocation: false,
        deny_trust: false,
    });
    let created = application.create_template(command()).await.unwrap();
    let activated = application
        .activate_template(
            "user-1",
            &created.id,
            Utc.with_ymd_and_hms(2026, 8, 21, 14, 0, 0).unwrap(),
        )
        .await
        .expect("activation dependencies are valid");
    assert_eq!(activated.status, TemplateStatus::Active);
    assert!(application
        .update_template(UpdateTemplateCommand {
            user_id: "user-1".to_owned(),
            template_id: activated.id,
            patch: UpdateTemplatePatch {
                name: Some("Changed".to_owned()),
                ..UpdateTemplatePatch::default()
            },
            now: Utc::now(),
        })
        .await
        .is_err());

    let (_, denied) = build_application(ControlPlane {
        deny_membership: false,
        deny_revocation: true,
        deny_trust: false,
    });
    let draft = denied.create_template(command()).await.unwrap();
    assert!(denied
        .activate_template("user-1", &draft.id, Utc::now())
        .await
        .is_err());
}

#[tokio::test]
async fn versioning_and_deletion_preserve_released_state_rules() {
    let (_, application) = build_application(ControlPlane {
        deny_membership: false,
        deny_revocation: false,
        deny_trust: false,
    });
    let draft = application.create_template(command()).await.unwrap();
    let version = application
        .new_version("user-1", &draft.id, Utc::now())
        .await
        .expect("managed issuer permits versioning");
    assert_ne!(version.id, draft.id);
    assert_eq!(version.version, 2);
    application
        .delete_template("user-1", &draft.id)
        .await
        .expect("draft deletion");

    let active = application.create_template(command()).await.unwrap();
    let active = application
        .activate_template("user-1", &active.id, Utc::now())
        .await
        .unwrap();
    assert!(application
        .delete_template("user-1", &active.id)
        .await
        .is_err());
    let deprecated = application
        .deprecate_template("user-1", &active.id, Utc::now())
        .await
        .unwrap();
    assert_eq!(deprecated.status, TemplateStatus::Deprecated);
}

#[tokio::test]
async fn provider_failures_never_persist_a_template() {
    let (repository, application) = build_application(ControlPlane {
        deny_membership: true,
        deny_revocation: false,
        deny_trust: false,
    });
    assert!(application.create_template(command()).await.is_err());
    assert!(repository.templates.lock().unwrap().is_empty());
}

#[tokio::test]
async fn internal_metadata_fails_closed_when_the_repository_is_unavailable() {
    let repository = Arc::new(MemoryRepository {
        templates: Mutex::new(BTreeMap::new()),
        fail_internal: true,
    });
    let application = CredentialTemplateApplication::new(
        repository,
        Arc::new(ControlPlane {
            deny_membership: false,
            deny_revocation: false,
            deny_trust: false,
        }),
    );
    let error = application
        .credential_configurations_internal()
        .await
        .expect_err("repository failure must not become an empty metadata success");
    assert!(matches!(
        error,
        marty_credential_template::application::CredentialTemplateApplicationError::Repository(_)
    ));
}
