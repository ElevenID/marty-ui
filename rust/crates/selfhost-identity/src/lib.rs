//! Reviewed public self-host workload identities shared by native KMS operators.

pub struct SelfhostRole {
    pub name: &'static str,
    pub key_name: &'static str,
    pub cert_file: &'static str,
    pub token_file: &'static str,
}

// Names here are the disposable self-host contract in the production Compose
// catalog. The keys live only in this install's private OpenBao instance.
pub const SELFHOST_ROLES: &[SelfhostRole] = &[
    SelfhostRole {
        name: "signing-keys-server",
        key_name: "workload-tls-signing-keys-server",
        cert_file: "signing_keys_workload_server_cert",
        token_file: "signing_keys_tls_kms_token",
    },
    SelfhostRole {
        name: "gateway-client",
        key_name: "workload-tls-gateway-auth-client",
        cert_file: "gateway_workload_client_cert",
        token_file: "gateway_tls_kms_token",
    },
    SelfhostRole {
        name: "auth-client",
        key_name: "workload-tls-auth-client",
        cert_file: "auth_workload_client_cert",
        token_file: "auth_tls_kms_token",
    },
    SelfhostRole {
        name: "auth-server",
        key_name: "workload-tls-auth-server",
        cert_file: "auth_workload_server_cert",
        token_file: "auth_server_tls_kms_token",
    },
    SelfhostRole {
        name: "compliance-profile-client",
        key_name: "workload-tls-compliance-profile-client",
        cert_file: "compliance_profile_workload_client_cert",
        token_file: "compliance_profile_tls_kms_token",
    },
    SelfhostRole {
        name: "deployment-profile-client",
        key_name: "workload-tls-deployment-profile-client",
        cert_file: "deployment_profile_workload_client_cert",
        token_file: "deployment_profile_tls_kms_token",
    },
    SelfhostRole {
        name: "organization-server",
        key_name: "workload-tls-organization-server",
        cert_file: "org_workload_server_cert",
        token_file: "org_tls_kms_token",
    },
    SelfhostRole {
        name: "event-stream-server",
        key_name: "workload-tls-event-stream-server",
        cert_file: "es_workload_server_cert",
        token_file: "es_tls_kms_token",
    },
    SelfhostRole {
        name: "notification-server",
        key_name: "workload-tls-notification-server",
        cert_file: "notification_workload_server_cert",
        token_file: "notification_tls_kms_token",
    },
    SelfhostRole {
        name: "revocation-profile-server",
        key_name: "workload-tls-revocation-profile-server",
        cert_file: "rp_workload_server_cert",
        token_file: "rp_tls_kms_token",
    },
    SelfhostRole {
        name: "credential-template-server",
        key_name: "workload-tls-credential-template-server",
        cert_file: "ct_workload_server_cert",
        token_file: "ct_tls_kms_token",
    },
    SelfhostRole {
        name: "issuance-server",
        key_name: "workload-tls-issuance-server",
        cert_file: "issuance_workload_server_cert",
        token_file: "issuance_tls_kms_token",
    },
    SelfhostRole {
        name: "flow-client",
        key_name: "workload-tls-flow-client",
        cert_file: "flow_workload_client_cert",
        token_file: "flow_client_tls_kms_token",
    },
    SelfhostRole {
        name: "flow-server",
        key_name: "workload-tls-flow-server",
        cert_file: "flow_workload_server_cert",
        token_file: "flow_server_tls_kms_token",
    },
    SelfhostRole {
        name: "pp-server",
        key_name: "workload-tls-presentation-policy-server",
        cert_file: "pp_workload_server_cert",
        token_file: "pp_tls_kms_token",
    },
    SelfhostRole {
        name: "verification-client",
        key_name: "workload-tls-verification-client",
        cert_file: "verification_workload_client_cert",
        token_file: "verification_tls_kms_token",
    },
];
