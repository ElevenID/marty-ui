pub mod domain;
pub mod persistence;

pub use domain::{
    evaluate_verified_facts_json, normalize_credential_format, AlternativeRequirement,
    ClaimConstraint, ConstraintType, CredentialRequirement, DisplayMetadata, FreshnessPolicy,
    HolderBinding, IssuerConstraints, PolicyDomainError, PolicyStatus, PresentationPolicy,
    RequestPurpose, RequestedClaim,
};
pub use persistence::{PolicyRecord, PolicyRecordError, PRESENTATION_POLICY_MIGRATION};

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
