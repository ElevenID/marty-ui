//! Read-only, authenticated dependency check before a one-way beta owner change.

use tonic::{metadata::AsciiMetadataValue, Code, Request, Response, Status};

use crate::{
    config::IssuanceServiceConfig,
    credential_template_proto::{
        credential_template_service_client::CredentialTemplateServiceClient, GetTemplateRequest,
    },
    grpc_client_channel,
    organization_proto::{
        organization_service_client::OrganizationServiceClient, GetOrganizationRequest,
    },
    revocation_profile_proto::{
        revocation_profile_service_client::RevocationProfileServiceClient,
        GetRevocationProfileRequest,
    },
};

const MISSING_ID: &str = "00000000-0000-0000-0000-000000000000";

fn authenticated<T>(
    body: T,
    token: &AsciiMetadataValue,
    timeout: std::time::Duration,
) -> Request<T> {
    let mut request = Request::new(body);
    request.set_timeout(timeout);
    request
        .metadata_mut()
        .insert("x-service-token", token.clone());
    request
}

fn checked<T>(result: Result<Response<T>, Status>, name: &str) -> Result<(), String> {
    match result {
        Ok(_) => Ok(()),
        Err(status) if status.code() == Code::NotFound => Ok(()),
        Err(status) => Err(format!("{name} gRPC dependency failed: {}", status.code())),
    }
}

pub async fn probe(config: &IssuanceServiceConfig) -> Result<(), String> {
    let token = config
        .internal_service_token
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or("gRPC service token is missing")?
        .parse::<AsciiMetadataValue>()
        .map_err(|_| "gRPC service token is invalid")?;
    let timeout = config.dependency_timeout;
    let org = grpc_client_channel::endpoint(&config.organization_grpc_target, timeout)?;
    let template = grpc_client_channel::endpoint(&config.credential_template_grpc_target, timeout)?;
    let revocation =
        grpc_client_channel::endpoint(&config.revocation_profile_grpc_target, timeout)?;
    let mut org = OrganizationServiceClient::new(org.connect_lazy());
    let mut template = CredentialTemplateServiceClient::new(template.connect_lazy());
    let mut revocation = RevocationProfileServiceClient::new(revocation.connect_lazy());
    checked(
        org.get_organization(authenticated(
            GetOrganizationRequest {
                organization_id: MISSING_ID.into(),
            },
            &token,
            timeout,
        ))
        .await,
        "organization",
    )?;
    checked(
        template
            .get_template(authenticated(
                GetTemplateRequest {
                    template_id: MISSING_ID.into(),
                },
                &token,
                timeout,
            ))
            .await,
        "credential-template",
    )?;
    checked(
        revocation
            .get_revocation_profile(authenticated(
                GetRevocationProfileRequest {
                    profile_id: MISSING_ID.into(),
                },
                &token,
                timeout,
            ))
            .await,
        "revocation-profile",
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_success_or_authenticated_not_found_passes() {
        assert!(checked::<()>(Ok(Response::new(())), "organization").is_ok());
        assert!(checked::<()>(Err(Status::not_found("missing")), "organization").is_ok());
        assert!(checked::<()>(Err(Status::unauthenticated("denied")), "organization").is_err());
        assert!(checked::<()>(Err(Status::unavailable("tls")), "organization").is_err());
    }
}
