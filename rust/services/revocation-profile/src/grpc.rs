use crate::{
    domain::{
        CredentialFormat, CredentialStatus, IssuerRevocationConfig, NewProfile, ProcessRevocation,
        RevocationAutomationConfig, RevocationCheckMode, RevocationMechanism, RevocationProfile,
        RevocationTimingMode, StatusListStrategy, UpdateMode, VerifierRevocationConfig,
    },
    proto::{
        revocation_profile_service_server::RevocationProfileService as RevocationProfileGrpcApi,
        ActivateRevocationProfileRequest, AllocateIndexRequest, AllocateIndexResponse,
        CreateRevocationProfileRequest, DeleteRevocationProfileRequest,
        DeleteRevocationProfileResponse, GetRevocationProfileRequest, HealthCheckRequest,
        HealthCheckResponse, ListRevocationProfilesRequest, ListRevocationProfilesResponse,
        ProcessRevocationRequest, ProcessRevocationResponse, RevocationProfileResponse,
    },
    service::{RevocationProfileService, ServiceError},
};
use tonic::{Request, Response, Status};

#[derive(Debug, Clone)]
pub struct RevocationProfileGrpc {
    service: RevocationProfileService,
}

impl RevocationProfileGrpc {
    pub fn new(service: RevocationProfileService) -> Self {
        Self { service }
    }
}

#[tonic::async_trait]
impl RevocationProfileGrpcApi for RevocationProfileGrpc {
    async fn create_revocation_profile(
        &self,
        request: Request<CreateRevocationProfileRequest>,
    ) -> Result<Response<RevocationProfileResponse>, Status> {
        let request = request.into_inner();
        let profile = self
            .service
            .create(NewProfile {
                organization_id: request.organization_id,
                name: request.name,
                description: nonempty(request.description),
                issuer_config: request
                    .issuer_config
                    .map(parse_issuer_config)
                    .transpose()
                    .map_err(Status::invalid_argument)?,
                verifier_config: request
                    .verifier_config
                    .map(parse_verifier_config)
                    .transpose()
                    .map_err(Status::invalid_argument)?,
                automation_config: request.automation_config.map(|config| {
                    RevocationAutomationConfig {
                        auto_allocate_indices: config.auto_allocate_indices,
                        auto_publish: config.auto_publish,
                        auto_generate_status_list_credentials: config
                            .auto_generate_status_list_credentials,
                        auto_discover_endpoints: config.auto_discover_endpoints,
                        use_format_defaults: config.use_format_defaults,
                    }
                }),
                supported_formats: (!request.supported_formats.is_empty())
                    .then(|| {
                        request
                            .supported_formats
                            .iter()
                            .map(|value| parse_credential_format(value))
                            .collect::<Result<Vec<_>, _>>()
                    })
                    .transpose()
                    .map_err(Status::invalid_argument)?,
            })
            .await
            .map_err(status_from_error)?;
        Ok(Response::new(profile_to_proto(&profile)))
    }

    async fn get_revocation_profile(
        &self,
        request: Request<GetRevocationProfileRequest>,
    ) -> Result<Response<RevocationProfileResponse>, Status> {
        let profile = self
            .service
            .get(&request.into_inner().profile_id)
            .await
            .map_err(status_from_error)?;
        Ok(Response::new(profile_to_proto(&profile)))
    }

    async fn list_revocation_profiles(
        &self,
        request: Request<ListRevocationProfilesRequest>,
    ) -> Result<Response<ListRevocationProfilesResponse>, Status> {
        let profiles = self
            .service
            .list(&request.into_inner().organization_id)
            .await
            .map_err(status_from_error)?;
        Ok(Response::new(ListRevocationProfilesResponse {
            profiles: profiles.iter().map(profile_to_proto).collect(),
        }))
    }

    async fn activate_revocation_profile(
        &self,
        request: Request<ActivateRevocationProfileRequest>,
    ) -> Result<Response<RevocationProfileResponse>, Status> {
        let profile = self
            .service
            .activate(&request.into_inner().profile_id)
            .await
            .map_err(status_from_error)?;
        Ok(Response::new(profile_to_proto(&profile)))
    }

    async fn delete_revocation_profile(
        &self,
        request: Request<DeleteRevocationProfileRequest>,
    ) -> Result<Response<DeleteRevocationProfileResponse>, Status> {
        self.service
            .delete(&request.into_inner().profile_id)
            .await
            .map_err(status_from_error)?;
        Ok(Response::new(DeleteRevocationProfileResponse {
            success: true,
        }))
    }

    async fn process_revocation(
        &self,
        request: Request<ProcessRevocationRequest>,
    ) -> Result<Response<ProcessRevocationResponse>, Status> {
        let request = request.into_inner();
        let credential_status = match request.status.as_str() {
            "revoked" => CredentialStatus::Revoked,
            "suspended" => CredentialStatus::Suspended,
            "reinstated" => CredentialStatus::Reinstated,
            value => {
                return Ok(Response::new(ProcessRevocationResponse {
                    success: false,
                    error: format!("Unknown status: {value}"),
                    ..Default::default()
                }))
            }
        };
        let index = usize::try_from(request.index)
            .map_err(|_| Status::invalid_argument("index must not be negative"))?;
        let result = self
            .service
            .process_revocation(ProcessRevocation {
                profile_id: request.profile_id.clone(),
                organization_id: request.organization_id,
                credential_id: request.credential_id,
                index,
                status: credential_status,
                credential_format: request.credential_format,
            })
            .await;
        match result {
            Ok(result) => Ok(Response::new(ProcessRevocationResponse {
                success: true,
                status_list_url: result.status_list_url,
                index: i32::try_from(result.index)
                    .map_err(|_| Status::internal("allocated index exceeds protobuf range"))?,
                organization_id: result.organization_id,
                error: String::new(),
            })),
            Err(ServiceError::NotFound(_) | ServiceError::FailedPrecondition(_)) => {
                Ok(Response::new(ProcessRevocationResponse {
                    success: false,
                    error: result.unwrap_err().to_string(),
                    ..Default::default()
                }))
            }
            Err(error) => Err(status_from_error(error)),
        }
    }

    async fn allocate_index(
        &self,
        request: Request<AllocateIndexRequest>,
    ) -> Result<Response<AllocateIndexResponse>, Status> {
        let request = request.into_inner();
        let result = self
            .service
            .allocate_index(
                &request.profile_id,
                &request.organization_id,
                &request.credential_format,
            )
            .await
            .map_err(status_from_error)?;
        Ok(Response::new(AllocateIndexResponse {
            index: i32::try_from(result.index)
                .map_err(|_| Status::internal("allocated index exceeds protobuf range"))?,
            status_list_url: result.status_list_url,
            organization_id: result.organization_id,
        }))
    }

    async fn health_check(
        &self,
        _request: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        Ok(Response::new(HealthCheckResponse {
            status: "serving".into(),
            service: "revocation-profile".into(),
        }))
    }
}

fn profile_to_proto(profile: &RevocationProfile) -> RevocationProfileResponse {
    RevocationProfileResponse {
        id: profile.id.clone(),
        organization_id: profile.organization_id.clone(),
        name: profile.name.clone(),
        description: profile.description.clone().unwrap_or_default(),
        status: profile.status.as_str().into(),
        issuer_config: Some(crate::proto::IssuerRevocationConfig {
            status_list_strategy: profile.issuer_config.status_list_strategy.as_str().into(),
            status_list_base_url: profile
                .issuer_config
                .status_list_base_url
                .clone()
                .unwrap_or_default(),
            status_list_size: i32::try_from(profile.issuer_config.status_list_size)
                .unwrap_or(i32::MAX),
            update_mode: profile.issuer_config.update_mode.as_str().into(),
            batch_interval_seconds: i32::try_from(profile.issuer_config.batch_interval_seconds)
                .unwrap_or(i32::MAX),
            enable_rotation: profile.issuer_config.enable_rotation,
            rotation_threshold_percent: i32::from(profile.issuer_config.rotation_threshold_percent),
            enable_bitstring_status_list: profile.issuer_config.enable_bitstring_status_list,
            enable_token_status_list: profile.issuer_config.enable_token_status_list,
            enable_legacy_revocation_list: profile.issuer_config.enable_legacy_revocation_list,
        }),
        verifier_config: Some(crate::proto::VerifierRevocationConfig {
            check_mode: profile.verifier_config.check_mode.as_str().into(),
            timing_mode: profile.verifier_config.timing_mode.as_str().into(),
            mechanism_priority: profile
                .verifier_config
                .mechanism_priority
                .iter()
                .map(|mechanism| mechanism.as_str().to_string())
                .collect(),
            cache_status_lists: profile.verifier_config.cache_status_lists,
            cache_ttl_seconds: i32::try_from(profile.verifier_config.cache_ttl_seconds)
                .unwrap_or(i32::MAX),
            offline_grace_seconds: i32::try_from(profile.verifier_config.offline_grace_seconds)
                .unwrap_or(i32::MAX),
            check_timeout_seconds: i32::try_from(profile.verifier_config.check_timeout_seconds)
                .unwrap_or(i32::MAX),
            max_retries: i32::try_from(profile.verifier_config.max_retries).unwrap_or(i32::MAX),
            require_issuer_signature_on_status_list: profile
                .verifier_config
                .require_issuer_signature_on_status_list,
            allow_third_party_registries: profile.verifier_config.allow_third_party_registries,
        }),
        automation_config: Some(crate::proto::RevocationAutomationConfig {
            auto_allocate_indices: profile.automation_config.auto_allocate_indices,
            auto_publish: profile.automation_config.auto_publish,
            auto_generate_status_list_credentials: profile
                .automation_config
                .auto_generate_status_list_credentials,
            auto_discover_endpoints: profile.automation_config.auto_discover_endpoints,
            use_format_defaults: profile.automation_config.use_format_defaults,
        }),
        supported_formats: profile
            .supported_formats
            .iter()
            .map(|format| format.as_str().to_string())
            .collect(),
        created_at: profile.created_at.to_rfc3339(),
        updated_at: profile.updated_at.to_rfc3339(),
    }
}

fn parse_issuer_config(
    config: crate::proto::IssuerRevocationConfig,
) -> Result<IssuerRevocationConfig, String> {
    let defaults = IssuerRevocationConfig::default();
    Ok(IssuerRevocationConfig {
        status_list_strategy: match config.status_list_strategy.as_str() {
            "" | "auto" => StatusListStrategy::Auto,
            "manual" => StatusListStrategy::Manual,
            "registry" => StatusListStrategy::Registry,
            value => return Err(format!("unsupported status_list_strategy: {value}")),
        },
        status_list_base_url: nonempty(config.status_list_base_url),
        status_list_size: positive_i32_or(config.status_list_size, defaults.status_list_size)?,
        update_mode: match config.update_mode.as_str() {
            "" | "sync" => UpdateMode::Sync,
            "async" => UpdateMode::Async,
            "batch" => UpdateMode::Batch,
            value => return Err(format!("unsupported update_mode: {value}")),
        },
        batch_interval_seconds: positive_i32_or(
            config.batch_interval_seconds,
            defaults.batch_interval_seconds,
        )?,
        enable_rotation: config.enable_rotation,
        rotation_threshold_percent: if config.rotation_threshold_percent == 0 {
            defaults.rotation_threshold_percent
        } else {
            u8::try_from(config.rotation_threshold_percent)
                .map_err(|_| "rotation_threshold_percent is invalid".to_string())?
        },
        enable_bitstring_status_list: config.enable_bitstring_status_list,
        enable_token_status_list: config.enable_token_status_list,
        enable_legacy_revocation_list: config.enable_legacy_revocation_list,
    })
}

fn parse_verifier_config(
    config: crate::proto::VerifierRevocationConfig,
) -> Result<VerifierRevocationConfig, String> {
    let defaults = VerifierRevocationConfig::default();
    Ok(VerifierRevocationConfig {
        check_mode: match config.check_mode.as_str() {
            "" | "HARD_FAIL" => RevocationCheckMode::HardFail,
            "SOFT_FAIL" => RevocationCheckMode::SoftFail,
            "SKIP" => RevocationCheckMode::Skip,
            value => return Err(format!("unsupported check_mode: {value}")),
        },
        timing_mode: match config.timing_mode.as_str() {
            "" | "ALWAYS" => RevocationTimingMode::Always,
            "CACHED" => RevocationTimingMode::Cached,
            "OFFLINE_GRACE" => RevocationTimingMode::OfflineGrace,
            "DISABLED" => RevocationTimingMode::Disabled,
            value => return Err(format!("unsupported timing_mode: {value}")),
        },
        mechanism_priority: if config.mechanism_priority.is_empty() {
            defaults.mechanism_priority
        } else {
            config
                .mechanism_priority
                .iter()
                .map(|value| parse_mechanism(value))
                .collect::<Result<Vec<_>, _>>()?
        },
        cache_status_lists: config.cache_status_lists,
        cache_ttl_seconds: positive_i32_or(config.cache_ttl_seconds, defaults.cache_ttl_seconds)?,
        offline_grace_seconds: positive_i32_or(
            config.offline_grace_seconds,
            defaults.offline_grace_seconds,
        )?,
        check_timeout_seconds: positive_i32_or(
            config.check_timeout_seconds,
            defaults.check_timeout_seconds,
        )?,
        max_retries: nonnegative_i32_or(config.max_retries, defaults.max_retries)?,
        require_issuer_signature_on_status_list: config.require_issuer_signature_on_status_list,
        allow_third_party_registries: config.allow_third_party_registries,
    })
}

fn parse_mechanism(value: &str) -> Result<RevocationMechanism, String> {
    match value {
        "OCSP" => Ok(RevocationMechanism::Ocsp),
        "CRL" => Ok(RevocationMechanism::Crl),
        "BITSTRING_STATUS_LIST" => Ok(RevocationMechanism::BitstringStatusList),
        "TOKEN_STATUS_LIST" => Ok(RevocationMechanism::TokenStatusList),
        "LEGACY_REVOCATION_LIST" => Ok(RevocationMechanism::LegacyRevocationList),
        _ => Err(format!("unsupported revocation mechanism: {value}")),
    }
}

fn parse_credential_format(value: &str) -> Result<CredentialFormat, String> {
    match value {
        "SD_JWT_VC" => Ok(CredentialFormat::SdJwtVc),
        "MDOC" => Ok(CredentialFormat::Mdoc),
        "VC_JWT" => Ok(CredentialFormat::VcJwt),
        _ => Err(format!("unsupported credential format: {value}")),
    }
}

fn positive_i32_or<T>(value: i32, default: T) -> Result<T, String>
where
    T: TryFrom<i32> + Copy,
{
    if value == 0 {
        return Ok(default);
    }
    if value < 0 {
        return Err("numeric configuration must not be negative".into());
    }
    T::try_from(value).map_err(|_| "numeric configuration is too large".into())
}

fn nonnegative_i32_or<T>(value: i32, default: T) -> Result<T, String>
where
    T: TryFrom<i32> + Copy,
{
    if value == 0 {
        return Ok(default);
    }
    if value < 0 {
        return Err("numeric configuration must not be negative".into());
    }
    T::try_from(value).map_err(|_| "numeric configuration is too large".into())
}

fn nonempty(value: String) -> Option<String> {
    (!value.trim().is_empty()).then_some(value)
}

fn status_from_error(error: ServiceError) -> Status {
    match error {
        ServiceError::InvalidArgument(message) => Status::invalid_argument(message),
        ServiceError::NotFound(message) => Status::not_found(message),
        ServiceError::PermissionDenied => Status::permission_denied(error.to_string()),
        ServiceError::FailedPrecondition(message) => Status::failed_precondition(message),
        ServiceError::Storage(message) => Status::unavailable(message),
        ServiceError::Native(message) => Status::internal(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{InMemoryProfileRepository, InMemoryStatusRepository};
    use std::sync::Arc;

    fn grpc() -> RevocationProfileGrpc {
        let service = RevocationProfileService::new(
            Arc::new(InMemoryProfileRepository::default()),
            Arc::new(InMemoryStatusRepository::default()),
            "https://status.example.test",
        )
        .unwrap();
        RevocationProfileGrpc::new(service)
    }

    #[tokio::test]
    async fn grpc_rejects_unknown_enum_values() {
        let error = grpc()
            .create_revocation_profile(Request::new(CreateRevocationProfileRequest {
                organization_id: "org-a".into(),
                name: "profile".into(),
                issuer_config: Some(crate::proto::IssuerRevocationConfig {
                    update_mode: "eventually".into(),
                    ..Default::default()
                }),
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn grpc_profile_shape_matches_existing_contract() {
        let grpc = grpc();
        let created = grpc
            .create_revocation_profile(Request::new(CreateRevocationProfileRequest {
                organization_id: "org-a".into(),
                name: "profile".into(),
                description: "description".into(),
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(created.organization_id, "org-a");
        assert_eq!(created.status, "draft");
        assert_eq!(created.supported_formats, ["SD_JWT_VC", "MDOC", "VC_JWT"]);
        assert_eq!(created.issuer_config.unwrap().status_list_size, 131_072);
    }
}
