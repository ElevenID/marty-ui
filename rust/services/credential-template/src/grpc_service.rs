use std::sync::Arc;

use chrono::Utc;
use mmf_security::{SecurityError, ServiceTokenAuthenticator};
use serde_json::Value;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::{
    application::{
        ControlPlaneError, CreateTemplateCommand, CredentialTemplateApplication,
        CredentialTemplateApplicationError, UpdateTemplateCommand, UpdateTemplatePatch,
    },
    credential_template_proto::{
        credential_template_service_server::CredentialTemplateService, ActivateTemplateRequest,
        ClaimDefinition as ClaimDefinitionMessage, CreateTemplateRequest, DeleteTemplateRequest,
        DeleteTemplateResponse, DeprecateTemplateRequest,
        DerivedAttribute as DerivedAttributeMessage, DisplayStyle as DisplayStyleMessage,
        GetCredentialConfigurationsRequest, GetCredentialConfigurationsResponse,
        GetTemplateRequest, GetWalletRequest, HealthCheckRequest, HealthCheckResponse,
        ListTemplatesRequest, ListTemplatesResponse, ListWalletsRequest, ListWalletsResponse,
        NewVersionRequest, TemplateResponse, UpdateTemplateRequest,
        ValidityRules as ValidityRulesMessage, WalletRegistryEntry as WalletRegistryEntryMessage,
    },
    registry_application::CredentialTemplateRegistryApplication,
    ClaimDefinition, ClaimType, CredentialFormat, CredentialTemplate, CredentialTemplateError,
    DerivedAttribute, DisplayStyle, PrivacyPosture, TemplateStatus, ValidityRules,
    ValidityRulesInput, WalletRegistryEntry,
};

#[derive(Clone)]
pub struct CredentialTemplateGrpcService {
    application: Arc<CredentialTemplateApplication>,
    registry_application: Arc<CredentialTemplateRegistryApplication>,
    service_authenticator: Arc<ServiceTokenAuthenticator>,
}

impl CredentialTemplateGrpcService {
    pub fn new(
        application: Arc<CredentialTemplateApplication>,
        registry_application: Arc<CredentialTemplateRegistryApplication>,
        service_token: Option<String>,
        service_authentication_required: bool,
    ) -> Result<Self, SecurityError> {
        Ok(Self {
            application,
            registry_application,
            service_authenticator: Arc::new(ServiceTokenAuthenticator::new(
                service_token,
                service_authentication_required,
            )?),
        })
    }

    fn authenticate<T>(&self, request: &Request<T>) -> Result<(), Status> {
        let candidate = metadata(request, "x-service-token");
        self.service_authenticator
            .authenticate(candidate.as_deref())
            .map_err(|_| {
                Status::unauthenticated("CREDENTIAL_TEMPLATE.GRPC_SERVICE_AUTHENTICATION_REQUIRED")
            })
    }

    fn user_id<T>(&self, request: &Request<T>) -> Result<String, Status> {
        metadata(request, "x-user-id").ok_or_else(|| {
            Status::unauthenticated("CREDENTIAL_TEMPLATE.GRPC_AUTHENTICATION_REQUIRED")
        })
    }
}

#[tonic::async_trait]
impl CredentialTemplateService for CredentialTemplateGrpcService {
    async fn create_template(
        &self,
        request: Request<CreateTemplateRequest>,
    ) -> Result<Response<TemplateResponse>, Status> {
        self.authenticate(&request)?;
        let user_id = self.user_id(&request)?;
        let input = request.into_inner();
        let template = self
            .application
            .create_template(CreateTemplateCommand {
                user_id,
                organization_id: input.organization_id,
                name: input.name,
                description: optional_text(input.description),
                credential_type: input.credential_type,
                vct: optional_text(input.vct),
                doctype: optional_text(input.doctype),
                claims: input
                    .claims
                    .into_iter()
                    .map(claim_from_message)
                    .collect::<Result<Vec<_>, _>>()?,
                privacy_posture: parse_privacy(default_text(
                    &input.privacy_posture,
                    "selective_disclosure",
                ))?,
                selective_disclosure_fields: input.selective_disclosure_fields,
                zk_predicate_claims: input.zk_predicate_claims,
                derived_attributes: input
                    .derived_attributes
                    .into_iter()
                    .map(derived_attribute_from_message)
                    .collect::<Result<Vec<_>, _>>()?,
                display_style: input.display_style.map(display_style_from_message),
                validity_rules: input.validity_rules.map(validity_from_message),
                supported_formats: parse_formats_or_default(&input.supported_formats)?,
                application_template_id: optional_text(input.application_template_id),
                trust_profile_id: optional_text(input.trust_profile_id),
                revocation_profile_id: optional_text(input.revocation_profile_id),
                compliance_profile: parse_optional_json(&input.compliance_profile_json)?,
                compliance_profile_id: input.compliance_profile_id,
                issuer_did: optional_text(input.issuer_did),
                credential_payload_format: optional_text(input.credential_payload_format),
                issuance_protocol: optional_text(input.issuance_protocol),
                now: Utc::now(),
            })
            .await
            .map_err(application_status)?;
        Ok(Response::new(template_message(&template)?))
    }

    async fn get_template(
        &self,
        request: Request<GetTemplateRequest>,
    ) -> Result<Response<TemplateResponse>, Status> {
        self.authenticate(&request)?;
        let user_id = self.user_id(&request)?;
        let template = self
            .application
            .get_template(&user_id, &request.get_ref().template_id)
            .await
            .map_err(application_status)?;
        Ok(Response::new(template_message(&template)?))
    }

    async fn list_templates(
        &self,
        request: Request<ListTemplatesRequest>,
    ) -> Result<Response<ListTemplatesResponse>, Status> {
        self.authenticate(&request)?;
        let user_id = self.user_id(&request)?;
        let input = request.into_inner();
        let status = optional_text(input.status)
            .as_deref()
            .map(TemplateStatus::parse)
            .transpose()
            .map_err(domain_status)?;
        let templates = self
            .application
            .list_templates(&user_id, &input.organization_id, status, 500, 0)
            .await
            .map_err(application_status)?;
        Ok(Response::new(ListTemplatesResponse {
            templates: templates
                .iter()
                .map(template_message)
                .collect::<Result<Vec<_>, _>>()?,
        }))
    }

    async fn update_template(
        &self,
        request: Request<UpdateTemplateRequest>,
    ) -> Result<Response<TemplateResponse>, Status> {
        self.authenticate(&request)?;
        let user_id = self.user_id(&request)?;
        let input = request.into_inner();
        let mask = &input.update_mask;
        let patch = UpdateTemplatePatch {
            name: masked_text(mask, "name", input.name),
            description: masked_text(mask, "description", input.description),
            claims: masked_repeated(mask, "claims", input.claims)
                .map(|claims| {
                    claims
                        .into_iter()
                        .map(claim_from_message)
                        .collect::<Result<Vec<_>, _>>()
                })
                .transpose()?,
            privacy_posture: masked_text(mask, "privacy_posture", input.privacy_posture)
                .as_deref()
                .map(parse_privacy)
                .transpose()?,
            selective_disclosure_fields: masked_repeated(
                mask,
                "selective_disclosure_fields",
                input.selective_disclosure_fields,
            ),
            zk_predicate_claims: masked_repeated(
                mask,
                "zk_predicate_claims",
                input.zk_predicate_claims,
            ),
            derived_attributes: masked_repeated(
                mask,
                "derived_attributes",
                input.derived_attributes,
            )
            .map(|items| {
                items
                    .into_iter()
                    .map(derived_attribute_from_message)
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?,
            display_style: input.display_style.map(display_style_from_message),
            validity_rules: input.validity_rules.map(validity_input_from_message),
            supported_formats: masked_repeated(mask, "supported_formats", input.supported_formats)
                .map(|values| parse_formats_or_default(&values))
                .transpose()?,
            application_template_id: masked_text(
                mask,
                "application_template_id",
                input.application_template_id,
            ),
            trust_profile_id: masked_text(mask, "trust_profile_id", input.trust_profile_id),
            revocation_profile_id: masked_text(
                mask,
                "revocation_profile_id",
                input.revocation_profile_id,
            ),
            issuer_did: masked_text(mask, "issuer_did", input.issuer_did),
            credential_payload_format: masked_text(
                mask,
                "credential_payload_format",
                input.credential_payload_format,
            ),
            issuance_protocol: masked_text(mask, "issuance_protocol", input.issuance_protocol),
        };
        let template = self
            .application
            .update_template(UpdateTemplateCommand {
                user_id,
                template_id: input.template_id,
                patch,
                now: Utc::now(),
            })
            .await
            .map_err(application_status)?;
        Ok(Response::new(template_message(&template)?))
    }

    async fn activate_template(
        &self,
        request: Request<ActivateTemplateRequest>,
    ) -> Result<Response<TemplateResponse>, Status> {
        self.authenticate(&request)?;
        let user_id = self.user_id(&request)?;
        let template = self
            .application
            .activate_template(&user_id, &request.get_ref().template_id, Utc::now())
            .await
            .map_err(application_status)?;
        Ok(Response::new(template_message(&template)?))
    }

    async fn deprecate_template(
        &self,
        request: Request<DeprecateTemplateRequest>,
    ) -> Result<Response<TemplateResponse>, Status> {
        self.authenticate(&request)?;
        let user_id = self.user_id(&request)?;
        let template = self
            .application
            .deprecate_template(&user_id, &request.get_ref().template_id, Utc::now())
            .await
            .map_err(application_status)?;
        Ok(Response::new(template_message(&template)?))
    }

    async fn new_version(
        &self,
        request: Request<NewVersionRequest>,
    ) -> Result<Response<TemplateResponse>, Status> {
        self.authenticate(&request)?;
        let user_id = self.user_id(&request)?;
        let template = self
            .application
            .new_version(&user_id, &request.get_ref().template_id, Utc::now())
            .await
            .map_err(application_status)?;
        Ok(Response::new(template_message(&template)?))
    }

    async fn delete_template(
        &self,
        request: Request<DeleteTemplateRequest>,
    ) -> Result<Response<DeleteTemplateResponse>, Status> {
        self.authenticate(&request)?;
        let user_id = self.user_id(&request)?;
        self.application
            .delete_template(&user_id, &request.get_ref().template_id)
            .await
            .map_err(application_status)?;
        Ok(Response::new(DeleteTemplateResponse { success: true }))
    }

    async fn get_credential_configurations(
        &self,
        request: Request<GetCredentialConfigurationsRequest>,
    ) -> Result<Response<GetCredentialConfigurationsResponse>, Status> {
        self.authenticate(&request)?;
        let result = self
            .application
            .credential_configurations_internal()
            .await
            .map_err(application_status)?;
        Ok(Response::new(GetCredentialConfigurationsResponse {
            configurations_json: serde_json::to_string(&result.configurations)
                .map_err(|_| Status::internal("CREDENTIAL_TEMPLATE.SERIALIZATION_FAILED"))?,
            issuer_display_name: result.issuer_display_name.unwrap_or_default(),
        }))
    }

    async fn list_wallets(
        &self,
        request: Request<ListWalletsRequest>,
    ) -> Result<Response<ListWalletsResponse>, Status> {
        self.authenticate(&request)?;
        let input = request.get_ref();
        let organization_id = non_empty(&input.organization_id);
        let user_id = if organization_id.is_some() {
            self.user_id(&request)?
        } else {
            String::new()
        };
        let wallets = self
            .registry_application
            .list_wallets(&user_id, organization_id, input.active_only)
            .await
            .map_err(application_status)?;
        Ok(Response::new(ListWalletsResponse {
            wallets: wallets
                .iter()
                .map(wallet_message)
                .collect::<Result<Vec<_>, _>>()?,
        }))
    }

    async fn get_wallet(
        &self,
        request: Request<GetWalletRequest>,
    ) -> Result<Response<WalletRegistryEntryMessage>, Status> {
        self.authenticate(&request)?;
        let user_id = metadata(&request, "x-user-id").unwrap_or_default();
        let wallet = self
            .registry_application
            .get_wallet(&user_id, &request.get_ref().wallet_id)
            .await
            .map_err(application_status)?;
        Ok(Response::new(wallet_message(&wallet)?))
    }

    async fn health_check(
        &self,
        request: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        self.authenticate(&request)?;
        Ok(Response::new(HealthCheckResponse {
            status: "serving".to_owned(),
        }))
    }
}

fn template_message(template: &CredentialTemplate) -> Result<TemplateResponse, Status> {
    Ok(TemplateResponse {
        id: template.id.clone(),
        organization_id: template.organization_id.clone(),
        name: template.name.clone(),
        description: template.description.clone().unwrap_or_default(),
        credential_type: template.credential_type.clone(),
        vct: template.vct.clone(),
        doctype: template.doctype.clone().unwrap_or_default(),
        claims: template.claims.iter().map(claim_message).collect(),
        privacy_posture: template.privacy_posture.as_str().to_owned(),
        selective_disclosure_fields: template.selective_disclosure_fields.clone(),
        zk_predicate_claims: template.zk_predicate_claims.clone(),
        supported_formats: template
            .supported_formats
            .iter()
            .map(|format| format.public_wire().to_owned())
            .collect(),
        issuance_protocol: template.issuance_protocol.clone(),
        credential_payload_format: CredentialFormat::parse(&template.credential_payload_format)
            .map_err(domain_status)?
            .public_wire()
            .to_owned(),
        display_style: Some(display_style_message(&template.display_style)),
        validity_rules: Some(validity_message(&template.validity_rules)),
        status: template.status.as_str().to_owned(),
        version: template.version,
        created_at: template.created_at.to_rfc3339(),
        updated_at: template.updated_at.to_rfc3339(),
        wallet_configs_json: serde_json::to_string(&template.wallet_configs)
            .map_err(|_| Status::internal("CREDENTIAL_TEMPLATE.SERIALIZATION_FAILED"))?,
        issuer_algorithm: template.issuer_algorithm.clone().unwrap_or_default(),
        revocation_profile_id: template.revocation_profile_id.clone().unwrap_or_default(),
        issuer_did: template.issuer_did.clone().unwrap_or_default(),
        derived_attributes: template
            .derived_attributes
            .iter()
            .map(derived_attribute_message)
            .collect::<Result<Vec<_>, _>>()?,
        application_template_id: template.application_template_id.clone().unwrap_or_default(),
        trust_profile_id: template.trust_profile_id.clone().unwrap_or_default(),
        compliance_profile_id: template.compliance_profile_id.clone().unwrap_or_default(),
        compliance_profile_json: template
            .compliance_profile
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|_| Status::internal("CREDENTIAL_TEMPLATE.SERIALIZATION_FAILED"))?
            .unwrap_or_default(),
    })
}

fn claim_from_message(message: ClaimDefinitionMessage) -> Result<ClaimDefinition, Status> {
    Ok(ClaimDefinition {
        id: Uuid::new_v4().to_string(),
        name: message.name,
        display_name: message.display_name,
        description: optional_text(message.description),
        claim_type: ClaimType::parse(default_text(&message.claim_type, "string"))
            .map_err(domain_status)?,
        required: message.required,
        selectively_disclosable: message.selectively_disclosable,
        derivable: message.derivable || !message.derived_from.is_empty(),
        derived_from: optional_text(message.derived_from),
        pattern: optional_text(message.pattern),
        enum_values: (!message.enum_values.is_empty()).then_some(message.enum_values),
        min_value: message.min_value,
        max_value: message.max_value,
        mdoc_namespace: optional_text(message.mdoc_namespace),
        mdoc_element_identifier: optional_text(message.mdoc_element_identifier),
        display_icon: optional_text(message.display_icon),
    })
}

fn claim_message(claim: &ClaimDefinition) -> ClaimDefinitionMessage {
    ClaimDefinitionMessage {
        name: claim.name.clone(),
        display_name: claim.display_name.clone(),
        description: claim.description.clone().unwrap_or_default(),
        claim_type: claim_type_wire(claim.claim_type).to_owned(),
        required: claim.required,
        selectively_disclosable: claim.selectively_disclosable,
        derivable: claim.derivable,
        pattern: claim.pattern.clone().unwrap_or_default(),
        enum_values: claim.enum_values.clone().unwrap_or_default(),
        mdoc_namespace: claim.mdoc_namespace.clone().unwrap_or_default(),
        mdoc_element_identifier: claim.mdoc_element_identifier.clone().unwrap_or_default(),
        derived_from: claim.derived_from.clone().unwrap_or_default(),
        display_icon: claim.display_icon.clone().unwrap_or_default(),
        min_value: claim.min_value,
        max_value: claim.max_value,
    }
}

fn derived_attribute_from_message(
    message: DerivedAttributeMessage,
) -> Result<DerivedAttribute, Status> {
    Ok(DerivedAttribute {
        id: Uuid::new_v4().to_string(),
        name: message.name,
        description: optional_text(message.description),
        source_claim: message.source_claim,
        derivation_type: message.derivation_type,
        parameters: if message.parameters_json.trim().is_empty() {
            serde_json::json!({})
        } else {
            serde_json::from_str(&message.parameters_json)
                .map_err(|_| Status::invalid_argument("derived_attributes.parameters_json"))?
        },
    })
}

fn derived_attribute_message(
    attribute: &DerivedAttribute,
) -> Result<DerivedAttributeMessage, Status> {
    Ok(DerivedAttributeMessage {
        name: attribute.name.clone(),
        description: attribute.description.clone().unwrap_or_default(),
        source_claim: attribute.source_claim.clone(),
        derivation_type: attribute.derivation_type.clone(),
        parameters_json: serde_json::to_string(&attribute.parameters)
            .map_err(|_| Status::internal("CREDENTIAL_TEMPLATE.SERIALIZATION_FAILED"))?,
    })
}

fn display_style_from_message(message: DisplayStyleMessage) -> DisplayStyle {
    DisplayStyle {
        background_color: default_text(&message.background_color, "#1a1a2e").to_owned(),
        text_color: default_text(&message.text_color, "#ffffff").to_owned(),
        logo_url: optional_text(message.logo_url),
        background_image_url: optional_text(message.background_image_url),
        icon: optional_text(message.icon),
    }
}

fn display_style_message(style: &DisplayStyle) -> DisplayStyleMessage {
    DisplayStyleMessage {
        background_color: style.background_color.clone(),
        text_color: style.text_color.clone(),
        logo_url: style.logo_url.clone().unwrap_or_default(),
        background_image_url: style.background_image_url.clone().unwrap_or_default(),
        icon: style.icon.clone().unwrap_or_default(),
    }
}

fn validity_from_message(message: ValidityRulesMessage) -> ValidityRules {
    let default = ValidityRules::default();
    ValidityRules {
        default_validity_days: positive_or(
            message.default_validity_days,
            default.default_validity_days,
        ),
        max_validity_days: positive_or(message.max_validity_days, default.max_validity_days),
        renewable: message.renewable,
        renewal_window_days: positive_or(message.renewal_window_days, default.renewal_window_days),
        not_before_offset_seconds: message.not_before_offset_seconds,
        require_revalidation: message.require_revalidation,
        revalidation_interval_days: (message.revalidation_interval_days > 0)
            .then_some(message.revalidation_interval_days),
    }
}

fn validity_input_from_message(message: ValidityRulesMessage) -> ValidityRulesInput {
    ValidityRulesInput {
        default_validity_days: positive(message.default_validity_days),
        max_validity_days: positive(message.max_validity_days),
        renewable: Some(message.renewable),
        renewal_window_days: positive(message.renewal_window_days),
        not_before_offset_seconds: Some(message.not_before_offset_seconds),
        require_revalidation: Some(message.require_revalidation),
        revalidation_interval_days: positive(message.revalidation_interval_days),
        ..ValidityRulesInput::default()
    }
}

fn validity_message(rules: &ValidityRules) -> ValidityRulesMessage {
    ValidityRulesMessage {
        default_validity_days: rules.default_validity_days,
        max_validity_days: rules.max_validity_days,
        renewable: rules.renewable,
        renewal_window_days: rules.renewal_window_days,
        require_revalidation: rules.require_revalidation,
        revalidation_interval_days: rules.revalidation_interval_days.unwrap_or_default(),
        not_before_offset_seconds: rules.not_before_offset_seconds,
    }
}

fn wallet_message(wallet: &WalletRegistryEntry) -> Result<WalletRegistryEntryMessage, Status> {
    Ok(WalletRegistryEntryMessage {
        id: wallet.id.clone(),
        name: wallet.name.clone(),
        logo_url: wallet.logo_url.clone().unwrap_or_default(),
        deep_link_template: wallet.deep_link_template.clone(),
        supported_formats: wallet.supported_formats.clone(),
        supported_protocols: wallet.supported_protocols.clone(),
        platforms: wallet.platforms.clone(),
        supports_qr: wallet.supports_qr,
        supports_deeplink: wallet.supports_deeplink,
        docs_url: wallet.docs_url.clone().unwrap_or_default(),
        is_active: wallet.is_active,
        created_at: wallet.created_at.to_rfc3339(),
        updated_at: wallet.updated_at.to_rfc3339(),
        organization_id: wallet.organization_id.clone().unwrap_or_default(),
        is_override: wallet.is_override,
        override_precedence: wallet.override_precedence,
        merge_strategy: wallet.merge_strategy.as_str().to_owned(),
        credential_format: wallet.credential_format.clone().unwrap_or_default(),
        issuance_protocol: wallet.issuance_protocol.clone().unwrap_or_default(),
        compliance_profile_code: wallet.compliance_profile_code.clone().unwrap_or_default(),
        wallet_apps: wallet.wallet_apps.clone(),
        specifications: wallet.specifications.clone(),
        routing_templates_json: serde_json::to_string(&wallet.routing_templates)
            .map_err(|_| Status::internal("CREDENTIAL_TEMPLATE.SERIALIZATION_FAILED"))?,
        install_urls_json: serde_json::to_string(&wallet.install_urls)
            .map_err(|_| Status::internal("CREDENTIAL_TEMPLATE.SERIALIZATION_FAILED"))?,
        ios_scheme: wallet.ios_scheme.clone().unwrap_or_default(),
        universal_link_template: wallet.universal_link_template.clone().unwrap_or_default(),
        android_package: wallet.android_package.clone().unwrap_or_default(),
        supports_digital_credentials: wallet.supports_digital_credentials,
        supports_haip: wallet.supports_haip,
    })
}

fn parse_formats_or_default(values: &[String]) -> Result<Vec<CredentialFormat>, Status> {
    if values.is_empty() {
        return Ok(vec![CredentialFormat::SdJwtVc]);
    }
    values
        .iter()
        .map(|value| CredentialFormat::parse(value).map_err(domain_status))
        .collect()
}

fn parse_privacy(value: &str) -> Result<PrivacyPosture, Status> {
    PrivacyPosture::parse(value).map_err(domain_status)
}

fn parse_optional_json(value: &str) -> Result<Option<Value>, Status> {
    non_empty(value)
        .map(|value| {
            serde_json::from_str(value)
                .map_err(|_| Status::invalid_argument("compliance_profile_json"))
        })
        .transpose()
}

fn application_status(error: CredentialTemplateApplicationError) -> Status {
    match error {
        CredentialTemplateApplicationError::NotFound(_)
        | CredentialTemplateApplicationError::WalletNotFound(_)
        | CredentialTemplateApplicationError::DestinationNotFound(_) => {
            Status::not_found("CREDENTIAL_TEMPLATE.NOT_FOUND")
        }
        CredentialTemplateApplicationError::ControlPlane(ControlPlaneError::MembershipRequired)
        | CredentialTemplateApplicationError::ControlPlane(
            ControlPlaneError::WalletAdminRequired,
        )
        | CredentialTemplateApplicationError::ControlPlane(
            ControlPlaneError::DestinationAdminRequired,
        )
        | CredentialTemplateApplicationError::SystemWalletReadOnly
        | CredentialTemplateApplicationError::SystemDestinationReadOnly
        | CredentialTemplateApplicationError::OwnershipTransferForbidden => {
            Status::permission_denied("CREDENTIAL_TEMPLATE.ACTION_NOT_AUTHORIZED")
        }
        CredentialTemplateApplicationError::ControlPlane(ControlPlaneError::Unavailable(_))
        | CredentialTemplateApplicationError::Repository(_) => {
            Status::unavailable("CREDENTIAL_TEMPLATE.BACKEND_UNAVAILABLE")
        }
        error => Status::invalid_argument(error.to_string()),
    }
}

fn domain_status(error: CredentialTemplateError) -> Status {
    Status::invalid_argument(error.to_string())
}

fn metadata<T>(request: &Request<T>, key: &str) -> Option<String> {
    request
        .metadata()
        .get(key)
        .and_then(|value| value.to_str().ok())
        .and_then(non_empty)
        .map(str::to_owned)
}

fn optional_text(value: String) -> Option<String> {
    non_empty(&value).map(str::to_owned)
}

fn non_empty(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}

fn default_text<'a>(value: &'a str, default: &'a str) -> &'a str {
    non_empty(value).unwrap_or(default)
}

fn masked_text(mask: &[String], field: &str, value: String) -> Option<String> {
    (mask.iter().any(|item| item == field) || !value.is_empty()).then_some(value)
}

fn masked_repeated<T>(mask: &[String], field: &str, value: Vec<T>) -> Option<Vec<T>> {
    (mask.iter().any(|item| item == field) || !value.is_empty()).then_some(value)
}

fn positive(value: i32) -> Option<i32> {
    (value > 0).then_some(value)
}

fn positive_or(value: i32, default: i32) -> i32 {
    positive(value).unwrap_or(default)
}

const fn claim_type_wire(value: ClaimType) -> &'static str {
    match value {
        ClaimType::String => "string",
        ClaimType::Integer => "integer",
        ClaimType::Boolean => "boolean",
        ClaimType::Date => "date",
        ClaimType::Datetime => "datetime",
        ClaimType::Object => "object",
        ClaimType::Array => "array",
        ClaimType::Image => "image",
        ClaimType::Binary => "binary",
    }
}
