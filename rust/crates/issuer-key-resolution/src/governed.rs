//! Registry-first DID resolution. Registry adapters must obtain bindings from
//! the authenticated signing registry, never from consumer request metadata.

use async_trait::async_trait;
use marty_didcomm::DidDocument;

use crate::{
    assertion_verification_keys,
    policy::{pin_assertion_keys, validate_source_controls, DidResolutionPolicy},
    IssuerKeyResolution, IssuerKeyResolutionError, IssuerKeyResolver,
};

#[derive(Clone, Debug)]
pub struct IssuerResolutionRequest {
    pub organization_id: Option<String>,
    pub issuer_did: String,
    pub verification_method_ids: Vec<String>,
    pub credential_format: String,
    pub key_purpose: String,
    pub algorithm: String,
    pub policy: DidResolutionPolicy,
}

/// One unambiguous registry binding, accompanied by its published DID document.
/// Adapters return Invalid for absent/inactive/ambiguous/incompatible bindings;
/// Unavailable is reserved for transport or dependency outages.
#[derive(Clone, Debug)]
pub struct RegistryIssuerResolution {
    pub organization_id: String,
    pub issuer_did: String,
    pub active: bool,
    pub credential_format: String,
    pub key_purpose: String,
    pub algorithm: String,
    pub verification_method_id: String,
    pub document: DidDocument,
    pub source: String,
    pub retrieved_at: String,
    pub content_sha256: String,
}

#[async_trait]
pub trait OrganizationIssuerResolver: Send + Sync {
    async fn resolve(
        &self,
        request: &IssuerResolutionRequest,
    ) -> Result<RegistryIssuerResolution, IssuerKeyResolutionError>;
}

/// Fetch fresh material for every call. This path never reuses cached registry
/// material, so it also honors cache_ttl_seconds=0. Public adapters are responsible
/// for honoring any stricter cache constraints before returning material.
pub async fn resolve_governed_issuer(
    request: &IssuerResolutionRequest,
    registry: &dyn OrganizationIssuerResolver,
    public: &dyn IssuerKeyResolver,
) -> Result<IssuerKeyResolution, IssuerKeyResolutionError> {
    validate_source_controls(
        &request.issuer_did,
        request.organization_id.as_deref(),
        &request.verification_method_ids,
    )?;
    if [
        &request.credential_format,
        &request.key_purpose,
        &request.algorithm,
    ]
    .iter()
    .any(|value| value.trim().is_empty())
    {
        return Err(IssuerKeyResolutionError::Invalid);
    }
    if request
        .policy
        .registry_first(request.organization_id.as_deref())
    {
        // An implicit default registry policy cannot silently become public
        // resolution when its required tenant context is missing.
        if request.organization_id.is_none() {
            return Err(IssuerKeyResolutionError::Invalid);
        }
        match registry.resolve(request).await {
            Ok(binding) => return validate_registry_binding(request, binding),
            Err(error) if request.policy.permits_fallback(&error) => {}
            Err(error) => return Err(error),
        }
    }
    let mut resolution = public.resolve(&request.issuer_did).await?;
    resolution.verification_keys = pin_assertion_keys(
        &request.issuer_did,
        &request.verification_method_ids,
        &resolution.verification_keys,
    )?;
    Ok(resolution)
}

fn validate_registry_binding(
    request: &IssuerResolutionRequest,
    binding: RegistryIssuerResolution,
) -> Result<IssuerKeyResolution, IssuerKeyResolutionError> {
    if request.organization_id.as_deref() != Some(binding.organization_id.as_str())
        || binding.issuer_did != request.issuer_did
        || binding.document.id != request.issuer_did
        || !binding.active
        || binding.credential_format != request.credential_format
        || binding.key_purpose != request.key_purpose
        || binding.algorithm != request.algorithm
    {
        return Err(IssuerKeyResolutionError::Invalid);
    }
    let keys = pin_assertion_keys(
        &request.issuer_did,
        std::slice::from_ref(&binding.verification_method_id),
        &assertion_verification_keys(&binding.document)?,
    )?;
    let verification_keys =
        pin_assertion_keys(&request.issuer_did, &request.verification_method_ids, &keys)?;
    Ok(IssuerKeyResolution {
        verification_keys,
        source: binding.source,
        retrieved_at: binding.retrieved_at,
        content_sha256: binding.content_sha256,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Registry(
        Result<RegistryIssuerResolution, IssuerKeyResolutionError>,
        AtomicUsize,
    );
    #[async_trait]
    impl OrganizationIssuerResolver for Registry {
        async fn resolve(
            &self,
            _: &IssuerResolutionRequest,
        ) -> Result<RegistryIssuerResolution, IssuerKeyResolutionError> {
            self.1.fetch_add(1, Ordering::SeqCst);
            self.0.clone()
        }
    }
    struct Public(AtomicUsize);
    #[async_trait]
    impl IssuerKeyResolver for Public {
        async fn resolve(&self, _: &str) -> Result<IssuerKeyResolution, IssuerKeyResolutionError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(IssuerKeyResolution {
                verification_keys: assertion_verification_keys(&binding().document)?,
                source: "public".into(),
                retrieved_at: "fresh".into(),
                content_sha256: "hash".into(),
            })
        }
    }
    fn request() -> IssuerResolutionRequest {
        IssuerResolutionRequest {
            organization_id: Some("org-1".into()),
            issuer_did: "did:web:issuer.example".into(),
            verification_method_ids: vec!["did:web:issuer.example#key".into()],
            credential_format: "VC_JWT".into(),
            key_purpose: "vc_jwt_issuer".into(),
            algorithm: "ES256".into(),
            policy: DidResolutionPolicy::default(),
        }
    }
    fn binding() -> RegistryIssuerResolution {
        let request = request();
        let document = serde_json::from_value(json!({
            "id":request.issuer_did, "@context":["https://www.w3.org/ns/did/v1"],
            "verificationMethod":[{"id":"did:web:issuer.example#key", "controller":"did:web:issuer.example", "type":"JsonWebKey2020", "publicKeyJwk":{"kty":"EC","crv":"P-256","x":"x","y":"y"}}],
            "assertionMethod":["did:web:issuer.example#key"]
        })).unwrap();
        RegistryIssuerResolution {
            organization_id: "org-1".into(),
            issuer_did: request.issuer_did,
            active: true,
            credential_format: request.credential_format,
            key_purpose: request.key_purpose,
            algorithm: request.algorithm,
            verification_method_id: "did:web:issuer.example#key".into(),
            document,
            source: "registry".into(),
            retrieved_at: "fresh".into(),
            content_sha256: "hash".into(),
        }
    }
    #[tokio::test]
    async fn valid_scoped_binding_uses_assertion_keys_without_public_lookup() {
        let registry = Registry(Ok(binding()), AtomicUsize::new(0));
        let public = Public(AtomicUsize::new(0));
        let result = resolve_governed_issuer(&request(), &registry, &public)
            .await
            .unwrap();
        assert_eq!(result.source, "registry");
        assert_eq!(result.verification_keys.len(), 1);
        assert_eq!(registry.1.load(Ordering::SeqCst), 1);
        assert_eq!(public.0.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn public_mode_cannot_bypass_an_explicit_organization_scope() {
        let mut request = request();
        request.policy.resolver_type = crate::policy::ResolverType::PublicDid;
        let registry = Registry(Err(IssuerKeyResolutionError::Invalid), AtomicUsize::new(0));
        let public = Public(AtomicUsize::new(0));
        assert!(resolve_governed_issuer(&request, &registry, &public)
            .await
            .is_err());
        assert_eq!(registry.1.load(Ordering::SeqCst), 1);
        assert_eq!(public.0.load(Ordering::SeqCst), 0);
        request.organization_id = None;
        assert!(resolve_governed_issuer(&request, &registry, &public)
            .await
            .is_ok());
        assert_eq!(registry.1.load(Ordering::SeqCst), 1);
        assert_eq!(public.0.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn missing_registry_scope_and_wrong_method_pins_fail_before_public_lookup() {
        let registry = Registry(Ok(binding()), AtomicUsize::new(0));
        let public = Public(AtomicUsize::new(0));
        let mut missing_scope = request();
        missing_scope.organization_id = None;
        missing_scope.policy.allow_public_fallback = true;
        assert!(resolve_governed_issuer(&missing_scope, &registry, &public)
            .await
            .is_err());
        assert_eq!(registry.1.load(Ordering::SeqCst), 0);
        let mut wrong_pin = request();
        wrong_pin.verification_method_ids = vec!["did:web:issuer.example#missing".into()];
        wrong_pin.policy.allow_public_fallback = true;
        assert!(resolve_governed_issuer(&wrong_pin, &registry, &public)
            .await
            .is_err());
        assert_eq!(public.0.load(Ordering::SeqCst), 0);
    }
    #[tokio::test]
    async fn incompatible_or_inactive_bindings_never_use_even_explicit_public_fallback() {
        let mut request = request();
        request.policy.allow_public_fallback = true;
        let mut cases = Vec::new();
        let mut wrong = binding();
        wrong.organization_id = "org-2".into();
        cases.push(wrong);
        let mut wrong = binding();
        wrong.active = false;
        cases.push(wrong);
        let mut wrong = binding();
        wrong.algorithm = "RS256".into();
        cases.push(wrong);
        let mut wrong = binding();
        wrong.credential_format = "MDOC".into();
        cases.push(wrong);
        let mut wrong = binding();
        wrong.key_purpose = "authentication".into();
        cases.push(wrong);
        let mut wrong = binding();
        wrong.verification_method_id = "did:web:issuer.example#other".into();
        cases.push(wrong);
        let mut wrong = binding();
        wrong.document.id = "did:web:other.example".into();
        cases.push(wrong);
        for binding in cases {
            let public = Public(AtomicUsize::new(0));
            assert_eq!(
                resolve_governed_issuer(
                    &request,
                    &Registry(Ok(binding), AtomicUsize::new(0)),
                    &public
                )
                .await,
                Err(IssuerKeyResolutionError::Invalid)
            );
            assert_eq!(public.0.load(Ordering::SeqCst), 0);
        }
    }
    #[tokio::test]
    async fn only_explicit_outage_fallback_can_call_public_resolution() {
        for enabled in [false, true] {
            let mut request = request();
            request.policy.allow_public_fallback = enabled;
            let registry = Registry(
                Err(IssuerKeyResolutionError::Unavailable),
                AtomicUsize::new(0),
            );
            let public = Public(AtomicUsize::new(0));
            assert_eq!(
                resolve_governed_issuer(&request, &registry, &public)
                    .await
                    .is_ok(),
                enabled
            );
            assert_eq!(public.0.load(Ordering::SeqCst), usize::from(enabled));
        }
        let mut request = request();
        request.policy.allow_public_fallback = true;
        let public = Public(AtomicUsize::new(0));
        assert!(resolve_governed_issuer(
            &request,
            &Registry(Err(IssuerKeyResolutionError::Invalid), AtomicUsize::new(0)),
            &public
        )
        .await
        .is_err());
        assert_eq!(public.0.load(Ordering::SeqCst), 0);
    }
}
