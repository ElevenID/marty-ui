#![forbid(unsafe_code)]

pub mod api_keys;
pub mod application;
pub mod audit;
pub mod authorization;
pub mod cache;
pub mod catalog;
pub mod domain;
pub mod events;
pub mod grpc_service;
pub mod http_security;
pub mod http_service;
pub mod migration;
pub mod policy_sets;
pub mod postgres;
pub mod preferences;
pub mod rbac_http;
pub mod roles;
pub mod scim;
pub mod scim_http;

pub mod organization_proto {
    tonic::include_proto!("marty.ui.organization.v1");
}

pub use api_keys::{
    validate_create_api_key, ApiKeyCreation, ApiKeyScopeType, CreateApiKeyCommand,
    RevokeApiKeyCommand, MIP_API_KEY_SCOPES,
};
pub use application::{
    evaluate_join_code, plan_direct_member_roles, plan_organization_creation,
    plan_organization_update, AcceptInvitationCommand, AddMemberDirectCommand, ApplicationWarning,
    ApplicationWarningCode, CreateOrganizationCommand, InviteMemberCommand, JoinByCodeCommand,
    JoinCodeEvaluation, JoinCodeState, JoinCodeValidation, JoinOrganizationCommand,
    MembershipPolicy, MutationResult, OrganizationApplication, OrganizationApplicationError,
    OrganizationCreationPlan, RemoveMemberCommand, SetMemberRolesCommand,
    UpdateOrganizationCommand, UpdateOrganizationPatch,
};
pub use audit::{
    normalize_audit_query, normalize_pagination, start_from_time_range, AuditEventPage,
    AuditQueryInput, NormalizedAuditQuery,
};
pub use authorization::{
    authenticate_forwarded_principal, authorize_forwarded_principal, ForwardedPrincipal,
    OrganizationAuthorizationContext, PrincipalSource,
};
pub use cache::{OrganizationCache, OrganizationCacheError, OrganizationCacheKeys};
pub use domain::{
    ApiKey, ApiKeySpec, ApiKeyStatus, AuditEvent, AuditEventQuery, ConsoleContextPreference,
    DomainError, JoinCode, JoinMechanism, Member, MemberStatus, Organization, OrganizationCreate,
    OrganizationStatus, OrganizationType, Permission, PolicySet, PolicySetSpec, PolicySetStatus,
    PolicySetType, Role, ViewMode, APPLICANT_PERMISSION_KEYS,
};
pub use events::{
    OrganizationAuditSink, OrganizationEvent, OrganizationEventError, OrganizationEventKind,
    OrganizationEventPublisher, OrganizationEventPublisherError,
};
pub use grpc_service::*;
pub use http_security::*;
pub use http_service::*;
pub use policy_sets::{
    deserialize_policy_documents, policy_set_ids_to_archive, validate_policy_documents,
    CedarPolicyDocument, CreatePolicySetCommand, UpdatePolicySetCommand, UpdatePolicySetPatch,
};
pub use preferences::{
    apply_console_preference_patch, UpdateConsolePreferenceCommand, UpdateConsolePreferencePatch,
};
pub use rbac_http::*;
pub use roles::{
    resolve_replacement_role, AddMemberRoleCommand, CreateRoleCommand, DeleteRoleCommand,
    RemoveMemberRoleCommand, UpdateRoleCommand, UpdateRolePatch,
};
pub use scim_http::*;
