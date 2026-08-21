pub mod application;
pub mod domain;
pub mod grpc_service;
pub mod http_service;
pub mod native_kernel;
pub mod persistence;
pub mod postgres;
pub mod verification;

pub use application::{
    PolicyApplication, PolicyApplicationError, PolicyAuthorization, PolicyRepository,
};
pub use domain::{
    evaluate_verified_facts_json, normalize_credential_format, AlternativeRequirement,
    ClaimConstraint, ConstraintType, CredentialRequirement, DisplayMetadata, FreshnessPolicy,
    HolderBinding, IssuerConstraints, PolicyDomainError, PolicyStatus, PresentationPolicy,
    RequestPurpose, RequestedClaim,
};
pub use grpc_service::PresentationPolicyGrpcService;
pub use http_service::{
    presentation_policy_router, EvaluatePresentationRequest, PresentationPolicyHttpState,
    PresentationVerificationError, PresentationVerificationOrchestrator,
};
pub use native_kernel::RustCredentialKernel;
pub use persistence::{PolicyRecord, PolicyRecordError, PRESENTATION_POLICY_MIGRATION};
pub use postgres::{
    migrate_presentation_policy_schema, validate_presentation_policy_schema, PostgresPolicyStore,
    PostgresPolicyStoreError,
};
pub use verification::{
    CredentialStatusEvidence, CredentialStatusResolver, CredentialVerificationContext,
    CredentialVerificationEvidence, CredentialVerificationKernel, IssuerTrustEvidence,
    PresentationTrustResolver, ResolvedTrustProfile, VerifiedFactsOrchestrator,
};

pub mod presentation_policy_proto {
    tonic::include_proto!("marty.ui.presentation_policy.v1");
}

pub const HTTP_OPERATIONS: [(&str, &str); 10] = [
    ("POST", "/v1/presentation-policies"),
    ("GET", "/v1/presentation-policies"),
    ("GET", "/v1/presentation-policies/{policy_id}"),
    ("PATCH", "/v1/presentation-policies/{policy_id}"),
    ("POST", "/v1/presentation-policies/{policy_id}/activate"),
    ("POST", "/v1/presentation-policies/{policy_id}/suspend"),
    ("POST", "/v1/presentation-policies/{policy_id}/new-version"),
    ("DELETE", "/v1/presentation-policies/{policy_id}"),
    ("POST", "/v1/presentation-policies/{policy_id}/evaluate"),
    ("POST", "/v1/presentation-policies/evaluate"),
];

pub const GRPC_METHODS: [&str; 10] = [
    "GetPolicy",
    "ListPolicies",
    "CreatePolicy",
    "UpdatePolicy",
    "ActivatePolicy",
    "SuspendPolicy",
    "NewVersionPolicy",
    "DeletePolicy",
    "EvaluatePresentation",
    "HealthCheck",
];
