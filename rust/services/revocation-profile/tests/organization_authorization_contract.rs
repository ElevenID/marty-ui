use crate::support::{start_organization_server, TOKEN};
use marty_revocation_profile::{Authorization, AuthorizationError, OrganizationAuthorization};

#[tokio::test]
async fn propagates_service_token_and_preserves_permission_contract() {
    let (target, shutdown) =
        start_organization_server(true, vec!["revocation-profile:view".into()]).await;
    let authorization =
        OrganizationAuthorization::connect_lazy(target, Some(TOKEN.into())).unwrap();

    authorization.check_health().await.unwrap();
    authorization
        .require_permission("user-1", "org-1", "revocation-profile", "view")
        .await
        .unwrap();
    assert_eq!(
        authorization
            .require_permission("user-1", "org-1", "revocation-profile", "delete",)
            .await,
        Err(AuthorizationError::Denied)
    );
    let _ = shutdown.send(());
}

#[tokio::test]
async fn missing_membership_is_denied_and_backend_auth_failure_is_unavailable() {
    let (target, shutdown) =
        start_organization_server(false, vec!["revocation-profile:view".into()]).await;
    let authorization =
        OrganizationAuthorization::connect_lazy(target.clone(), Some(TOKEN.into())).unwrap();
    assert_eq!(
        authorization
            .require_permission("user-1", "org-1", "revocation-profile", "view",)
            .await,
        Err(AuthorizationError::Denied)
    );

    let unauthenticated = OrganizationAuthorization::connect_lazy(target, None).unwrap();
    assert!(matches!(
        unauthenticated.check_health().await,
        Err(AuthorizationError::Unavailable(_))
    ));
    let _ = shutdown.send(());
}
