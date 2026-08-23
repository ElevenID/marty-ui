//! High-level compatibility use cases formerly composed in the Python gateway.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use thiserror::Error;

use crate::{
    documents::{
        self, DocumentStore, InspectCertificateRequest, LoadDidRequest, PublishDidRequest,
    },
    kms::{self, ProviderRequest},
    profiles::{
        self, CustodyFormatRequest, FindProfilesRequest, ProfileStore, ValidateBindingRequest,
    },
    registry::RegistryStore,
};

#[derive(Clone)]
pub struct SigningCompatibilityService {
    registry: RegistryStore,
    documents: DocumentStore,
    profiles: ProfileStore,
    public_domain: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct IssuerContextRequest {
    pub organization_id: String,
    #[serde(default)]
    pub issuer_did: Option<String>,
    #[serde(default = "default_issuer_mode")]
    pub issuer_mode: String,
    #[serde(default)]
    pub credential_format: Option<String>,
    #[serde(default)]
    pub key_purpose: Option<String>,
    #[serde(default)]
    pub algorithm: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ResolveIssuerDidRequest {
    pub organization_id: String,
    pub issuer_did: String,
    #[serde(default)]
    pub verification_method_id: Option<String>,
    #[serde(default)]
    pub credential_format: Option<String>,
    #[serde(default)]
    pub key_purpose: Option<String>,
    #[serde(default)]
    pub algorithm: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ProfileIdentityRequest {
    pub organization_id: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ServiceSignRequest {
    pub organization_id: String,
    #[serde(default)]
    pub payload_b64: Option<String>,
    #[serde(default)]
    pub payload_hex: Option<String>,
    #[serde(default)]
    pub algorithm: Option<String>,
    #[serde(default)]
    pub key_reference: Option<String>,
    #[serde(default)]
    pub key_purpose: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerDidSignRequest {
    pub organization_id: String,
    pub issuer_did: String,
    pub credential_format: String,
    pub key_purpose: String,
    pub algorithm: String,
    #[serde(default)]
    pub payload_b64: Option<String>,
    #[serde(default)]
    pub payload_hex: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ProfileWriteRequest {
    pub organization_id: String,
    pub body: Value,
}

#[derive(Debug, Error)]
pub enum CompatibilityError {
    #[error("Invalid internal signing API key.")]
    Unauthorized,
    #[error("No active issuer profile is configured for this organization. Create a DID identity backed by a registered remote signing service first.")]
    ProfileNotFound,
    #[error("Issuer DID resolution is ambiguous; configure exactly one active issuer profile for this organization, DID, purpose, and format.")]
    AmbiguousProfile,
    #[error("Issuer profile references an unavailable signing service.")]
    ServiceNotFound,
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    BadRequest(String),
    #[error("Native issuer-profile backend is unavailable.")]
    Unavailable,
    #[error("{0}")]
    Invalid(String),
    #[error("{0}")]
    Conflict(String),
}

impl IntoResponse for CompatibilityError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::ProfileNotFound | Self::ServiceNotFound | Self::NotFound(_) => {
                StatusCode::NOT_FOUND
            }
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::AmbiguousProfile | Self::Conflict(_) => StatusCode::CONFLICT,
            Self::Invalid(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        };
        (status, Json(json!({"detail": self.to_string()}))).into_response()
    }
}

impl SigningCompatibilityService {
    #[must_use]
    pub fn new(
        registry: RegistryStore,
        documents: DocumentStore,
        profiles: ProfileStore,
        public_domain: Option<String>,
    ) -> Self {
        Self {
            registry,
            documents,
            profiles,
            public_domain,
        }
    }

    pub async fn issuer_context(
        &self,
        request: &IssuerContextRequest,
    ) -> Result<Value, CompatibilityError> {
        if request.organization_id.trim().is_empty() {
            return Err(CompatibilityError::Invalid(
                "organization_id is required.".into(),
            ));
        }
        let profile_document = self
            .profiles
            .list(&request.organization_id)
            .await
            .map_err(|_| CompatibilityError::Unavailable)?;
        let registry = self
            .registry
            .load(&request.organization_id)
            .await
            .map_err(|_| CompatibilityError::Unavailable)?;
        let certificates = self
            .documents
            .certificate_overrides(&request.organization_id)
            .await
            .map_err(|_| CompatibilityError::Unavailable)?;
        resolve_issuer_context(&profile_document, &registry, &certificates, request)
    }

    pub async fn resolve_issuer_did(
        &self,
        request: &ResolveIssuerDidRequest,
    ) -> Result<Value, CompatibilityError> {
        validate_resolve_request(request)?;
        let profile_document = self
            .profiles
            .list(&request.organization_id)
            .await
            .map_err(|_| CompatibilityError::Unavailable)?;
        let registry = self
            .registry
            .load(&request.organization_id)
            .await
            .map_err(|_| CompatibilityError::Unavailable)?;
        let certificates = self
            .documents
            .certificate_overrides(&request.organization_id)
            .await
            .map_err(|_| CompatibilityError::Unavailable)?;
        let did_document = self
            .load_identity_document(&request.organization_id, &request.issuer_did)
            .await?;
        resolve_issuer_identity(
            &profile_document,
            &registry,
            &certificates,
            &did_document,
            request,
        )
        .await
    }

    pub async fn profile_identity(
        &self,
        organization_id: &str,
        profile_id: &str,
        public_projection: bool,
    ) -> Result<Value, CompatibilityError> {
        let profile = self
            .profiles
            .get(organization_id, profile_id)
            .await
            .map_err(|error| match error {
                profiles::ProfileError::NotFound(_) => {
                    CompatibilityError::NotFound("Active issuer profile not found.".into())
                }
                _ => CompatibilityError::Unavailable,
            })?;
        if profile.get("status").and_then(Value::as_str) != Some("active") {
            return Err(CompatibilityError::NotFound(
                "Active issuer profile not found.".into(),
            ));
        }
        let complete_binding = [
            "issuer_did",
            "signing_service_id",
            "signing_key_reference",
            "key_purpose",
        ]
        .iter()
        .all(|field| {
            profile
                .get(*field)
                .and_then(Value::as_str)
                .is_some_and(|value| !value.trim().is_empty())
        });
        if !complete_binding {
            return Err(CompatibilityError::Conflict(
                "Issuer profile has an incomplete signing identity binding.".into(),
            ));
        }
        let issuer_did = required(&profile, "issuer_did")?;
        let key_purpose = required(&profile, "key_purpose")?;
        let resolved = self
            .resolve_issuer_did(&ResolveIssuerDidRequest {
                organization_id: organization_id.into(),
                issuer_did: issuer_did.into(),
                verification_method_id: clean(
                    profile
                        .get("verification_method_id")
                        .and_then(Value::as_str),
                ),
                credential_format: None,
                key_purpose: Some(key_purpose.into()),
                algorithm: clean(profile.get("algorithm").and_then(Value::as_str))
                    .or_else(|| Some("ES256".into())),
            })
            .await?;
        if resolved
            .pointer("/issuer_profile/id")
            .and_then(Value::as_str)
            != Some(profile_id)
        {
            return Err(CompatibilityError::Conflict(
                "Issuer profile DID binding resolved to a different identity.".into(),
            ));
        }
        if public_projection {
            let service_id = required(&profile, "signing_service_id")?;
            let registry = self
                .registry
                .load(organization_id)
                .await
                .map_err(|_| CompatibilityError::Unavailable)?;
            let certificates = self
                .documents
                .certificate_overrides(organization_id)
                .await
                .map_err(|_| CompatibilityError::Unavailable)?;
            let mut service =
                service_for(&registry, service_id).ok_or(CompatibilityError::ServiceNotFound)?;
            merge_certificate(&mut service, &certificates, service_id);
            Ok(json!({
                "issuer_profile_id": profile_id,
                "issuer_did": resolved["issuer_did"],
                "verification_method_id": resolved["verification_method_id"],
                "public_jwk": resolved["public_jwk"],
                "algorithm": profile.get("algorithm").cloned().unwrap_or_else(|| json!("ES256")),
                "x5c": resolved["issuer_x5c"],
                "certificate_expires_at": service.get("cert_expires_at").cloned().unwrap_or(Value::Null)
            }))
        } else {
            Ok(json!({
                "issuer_profile_id": profile_id,
                "issuer_did": resolved["issuer_did"],
                "verification_method_id": resolved["verification_method_id"],
                "public_jwk": resolved["public_jwk"],
                "did_document": resolved["did_document"],
                "key_purpose": profile["key_purpose"],
                "algorithm": profile.get("algorithm").cloned().unwrap_or_else(|| json!("ES256"))
            }))
        }
    }

    pub async fn sign_with_service(
        &self,
        service_id: &str,
        request: &ServiceSignRequest,
    ) -> Result<Value, CompatibilityError> {
        if request.organization_id.trim().is_empty() {
            return Err(CompatibilityError::Invalid(
                "organization_id is required.".into(),
            ));
        }
        let registry = self
            .registry
            .load(&request.organization_id)
            .await
            .map_err(|_| CompatibilityError::Unavailable)?;
        let mut service = service_for(&registry, service_id).ok_or_else(|| {
            CompatibilityError::NotFound(format!("Service '{service_id}' not found."))
        })?;
        let payload = signing_payload(
            request.payload_b64.as_deref(),
            request.payload_hex.as_deref(),
        )?;
        let key_reference = clean(request.key_reference.as_deref())
            .or_else(|| clean(service.get("key_reference").and_then(Value::as_str)));
        if let Some(reference) = &key_reference {
            service.insert("key_reference".into(), Value::String(reference.clone()));
        }
        authorize_signing_binding(
            &registry,
            &service,
            service_id,
            key_reference.as_deref(),
            request.key_purpose.as_deref(),
            request.algorithm.as_deref(),
        )?;
        if request.key_purpose.as_deref() == Some("lti_tool_signing") {
            let profiles = self
                .profiles
                .list(&request.organization_id)
                .await
                .map_err(|_| CompatibilityError::Unavailable)?;
            reject_credential_profile_key_reuse(
                &profiles,
                service_id,
                key_reference.as_deref().unwrap_or_default(),
            )?;
        }
        let algorithm = selected_algorithm(&service, request.algorithm.as_deref())?;
        service.insert("algorithm".into(), Value::String(algorithm.clone()));
        let signed = kms::sign(kms::SignRequest {
            service_config: Value::Object(service),
            payload_b64: URL_SAFE_NO_PAD.encode(&payload),
        })
        .await
        .map_err(map_kms_error)?;
        let signature = decode_base64(&signed.signature_b64, "provider signature")?;
        let mut response = json!({
            "ok": true,
            "service_id": service_id,
            "algorithm": algorithm,
            "payload_length": payload.len(),
            "signature_encoding": signed.signature_encoding,
            "signature_b64": signed.signature_b64,
            "signature_hex": encode_hex(&signature),
            "signed_at": chrono::Utc::now().to_rfc3339()
        });
        if let Some(raw_b64) = signed.transcoded_signature_b64 {
            let raw = decode_base64(&raw_b64, "transcoded provider signature")?;
            response["signature_raw_b64"] = Value::String(raw_b64);
            response["signature_raw_hex"] = Value::String(encode_hex(&raw));
        }
        Ok(response)
    }

    pub async fn sign_with_issuer_did(
        &self,
        request: &IssuerDidSignRequest,
    ) -> Result<Value, CompatibilityError> {
        if request.credential_format.trim().is_empty() {
            return Err(CompatibilityError::Invalid(
                "credential_format is required for DID-mediated signing.".into(),
            ));
        }
        if request.key_purpose.trim().is_empty() {
            return Err(CompatibilityError::Invalid(
                "key_purpose is required for DID-mediated signing.".into(),
            ));
        }
        if request.algorithm.trim().is_empty() {
            return Err(CompatibilityError::Invalid(
                "algorithm is required for DID-mediated signing.".into(),
            ));
        }
        let identity = self
            .resolve_issuer_did(&ResolveIssuerDidRequest {
                organization_id: request.organization_id.clone(),
                issuer_did: request.issuer_did.clone(),
                verification_method_id: None,
                credential_format: Some(request.credential_format.clone()),
                key_purpose: Some(request.key_purpose.clone()),
                algorithm: Some(request.algorithm.clone()),
            })
            .await?;
        let profile = identity
            .get("issuer_profile")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                CompatibilityError::Conflict(
                    "Issuer DID resolved without an active profile.".into(),
                )
            })?;
        let service_id =
            required(&Value::Object(profile.clone()), "signing_service_id")?.to_owned();
        let key_reference =
            required(&Value::Object(profile.clone()), "signing_key_reference")?.to_owned();
        let profile_purpose = required(&Value::Object(profile.clone()), "key_purpose")?.to_owned();
        let profile_algorithm = profile
            .get("algorithm")
            .and_then(Value::as_str)
            .unwrap_or("ES256")
            .to_owned();
        if request.algorithm != profile_algorithm {
            return Err(CompatibilityError::Conflict(
                "Signing algorithm must match the DID-resolved issuer profile binding.".into(),
            ));
        }
        let mut signed = self
            .sign_with_service(
                &service_id,
                &ServiceSignRequest {
                    organization_id: request.organization_id.clone(),
                    payload_b64: request.payload_b64.clone(),
                    payload_hex: request.payload_hex.clone(),
                    algorithm: Some(profile_algorithm),
                    key_reference: Some(key_reference),
                    key_purpose: Some(profile_purpose),
                },
            )
            .await?;
        let body = signed
            .as_object_mut()
            .expect("signing response is an object");
        body.remove("service_id");
        for field in ["issuer_did", "verification_method_id", "public_jwk"] {
            body.insert(field.into(), identity[field].clone());
        }
        Ok(signed)
    }

    pub async fn create_profile(
        &self,
        request: &ProfileWriteRequest,
    ) -> Result<Value, CompatibilityError> {
        let mut profile = profiles::normalize_profile(
            &request.organization_id,
            profiles::NormalizeProfileRequest {
                body: request.body.clone(),
                existing: None,
                now: None,
                profile_id: None,
            },
        )
        .map_err(map_profile_error)?;
        let registry = self
            .registry
            .load(&request.organization_id)
            .await
            .map_err(|_| CompatibilityError::Unavailable)?;
        let service_id = required(&profile, "signing_service_id")?.to_owned();
        let mut service =
            service_for(&registry, &service_id).ok_or(CompatibilityError::ServiceNotFound)?;
        complete_profile_binding(&mut profile, &mut service).await?;
        profiles::validate_binding(&ValidateBindingRequest {
            profile: profile.clone(),
            service: Value::Object(service.clone()),
            registry: registry.clone(),
        })
        .map_err(map_profile_error)?;

        let duplicate = self
            .profiles
            .find_duplicate(
                &request.organization_id,
                profiles::DuplicateProfileRequest {
                    profile: profile.clone(),
                    service_key_reference: clean(
                        service.get("key_reference").and_then(Value::as_str),
                    ),
                },
            )
            .await
            .map_err(map_profile_error)?;
        let (mut profile, created) = match duplicate.profile {
            Some(profile) if duplicate.found => (profile, false),
            _ => (profile, true),
        };
        let before_publication = profile.clone();
        self.ensure_did_web_verification_method(
            &request.organization_id,
            &service_id,
            &service,
            &mut profile,
        )
        .await?;
        if !created && profile != before_publication {
            profile["updated_at"] = Value::String(chrono::Utc::now().to_rfc3339());
        }
        self.registry
            .bind_profile(&request.organization_id, &profile)
            .await
            .map_err(|error| CompatibilityError::Invalid(error.to_string()))?;
        let profile_id = required(&profile, "id")?.to_owned();
        let profile = self
            .profiles
            .put(&request.organization_id, &profile_id, profile)
            .await
            .map_err(map_profile_error)?;
        Ok(json!({"ok": true, "profile": profile, "created": created}))
    }

    pub async fn update_profile(
        &self,
        profile_id: &str,
        request: &ProfileWriteRequest,
    ) -> Result<Value, CompatibilityError> {
        let existing = self
            .profiles
            .get(&request.organization_id, profile_id)
            .await
            .map_err(map_profile_error)?;
        let mut profile = profiles::normalize_profile(
            &request.organization_id,
            profiles::NormalizeProfileRequest {
                body: request.body.clone(),
                existing: Some(existing),
                now: None,
                profile_id: Some(profile_id.into()),
            },
        )
        .map_err(map_profile_error)?;
        let registry = self
            .registry
            .load(&request.organization_id)
            .await
            .map_err(|_| CompatibilityError::Unavailable)?;
        let service_id = required(&profile, "signing_service_id")?.to_owned();
        let mut service =
            service_for(&registry, &service_id).ok_or(CompatibilityError::ServiceNotFound)?;
        complete_profile_binding(&mut profile, &mut service).await?;
        profiles::validate_binding(&ValidateBindingRequest {
            profile: profile.clone(),
            service: Value::Object(service),
            registry,
        })
        .map_err(map_profile_error)?;
        let profile = self
            .profiles
            .put(&request.organization_id, profile_id, profile)
            .await
            .map_err(map_profile_error)?;
        Ok(json!({"ok": true, "profile": profile}))
    }

    pub async fn attach_profile_certificate(
        &self,
        profile_id: &str,
        request: &ProfileWriteRequest,
    ) -> Result<Value, CompatibilityError> {
        let identity = self
            .profile_identity(&request.organization_id, profile_id, false)
            .await?;
        let profile = self
            .profiles
            .get(&request.organization_id, profile_id)
            .await
            .map_err(map_profile_error)?;
        let service_id = required(&profile, "signing_service_id")?;
        let cert_pem = request
            .body
            .get("cert_pem")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| CompatibilityError::BadRequest("cert_pem is required.".into()))?;
        let stored = self
            .documents
            .store_certificate(
                &request.organization_id,
                service_id,
                InspectCertificateRequest {
                    cert_pem: cert_pem.into(),
                    cert_chain_pem: clean(
                        request.body.get("cert_chain_pem").and_then(Value::as_str),
                    ),
                    expected_public_jwk: Some(identity["public_jwk"].clone()),
                },
            )
            .await
            .map_err(map_document_error)?;
        if stored.x5c.is_empty() {
            return Err(CompatibilityError::Unavailable);
        }
        Ok(json!({
            "ok": true,
            "issuer_profile_id": profile_id,
            "issuer_did": identity["issuer_did"],
            "verification_method_id": identity["verification_method_id"],
            "certificate_chain_length": stored.x5c.len(),
            "certificate_expires_at": stored.cert_expires_at
        }))
    }

    async fn ensure_did_web_verification_method(
        &self,
        organization_id: &str,
        service_id: &str,
        service: &Map<String, Value>,
        profile: &mut Value,
    ) -> Result<(), CompatibilityError> {
        let issuer_did = profile
            .get("issuer_did")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !issuer_did.starts_with("did:web:")
            || profile
                .get("verification_method_id")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty())
        {
            return Ok(());
        }
        let public_domain = self.public_domain.as_deref().ok_or_else(|| {
            CompatibilityError::Invalid(
                "An automatically published did:web issuer requires PUBLIC_DOMAIN.".into(),
            )
        })?;
        let org_slug = documents::did_web_org_slug(issuer_did, Some(public_domain)).ok_or_else(|| {
            CompatibilityError::Invalid(
                "An automatically published did:web issuer must use did:web:<PUBLIC_DOMAIN>:orgs:<slug>.".into(),
            )
        })?;
        let provider_key = kms::public_key(ProviderRequest {
            service_config: Value::Object(service.clone()),
        })
        .await
        .map_err(map_kms_error)?;
        let jwk = extract_provider_jwk(&provider_key).ok_or(CompatibilityError::Unavailable)?;
        let key_reference = clean(profile.get("signing_key_reference").and_then(Value::as_str));
        let published = self
            .documents
            .publish_did(
                organization_id,
                service_id,
                PublishDidRequest {
                    jwk: Value::Object(jwk),
                    public_domain: public_domain.into(),
                    did_id: Some(issuer_did.into()),
                    org_slug: Some(org_slug),
                    fragment: Some(documents::did_fragment(
                        service_id,
                        key_reference.as_deref(),
                    )),
                    key_reference,
                    cert_pem: None,
                    cert_chain_pem: None,
                    relationship: documents::DidVerificationRelationship::AssertionMethod,
                },
            )
            .await
            .map_err(map_document_error)?;
        let verification_method_id = published
            .verification_method
            .get("id")
            .and_then(Value::as_str)
            .ok_or(CompatibilityError::Unavailable)?;
        profile["verification_method_id"] = Value::String(verification_method_id.into());
        Ok(())
    }

    async fn load_identity_document(
        &self,
        organization_id: &str,
        issuer_did: &str,
    ) -> Result<Value, CompatibilityError> {
        let scoped = self
            .documents
            .load_did(
                organization_id,
                LoadDidRequest {
                    did_id: Some(issuer_did.into()),
                    fallback_did: Some(issuer_did.into()),
                },
            )
            .await
            .map_err(|_| CompatibilityError::Unavailable)?;
        if scoped.found {
            if scoped.document.get("id").and_then(Value::as_str) != Some(issuer_did) {
                return Err(CompatibilityError::Unavailable);
            }
            return Ok(scoped.document);
        }
        let legacy = self
            .documents
            .load_did(
                organization_id,
                LoadDidRequest {
                    did_id: None,
                    fallback_did: Some(issuer_did.into()),
                },
            )
            .await
            .map_err(|_| CompatibilityError::Unavailable)?;
        Ok(if legacy.found {
            retarget_document(&legacy.document, issuer_did)
        } else {
            empty_did_document(issuer_did)
        })
    }
}

pub fn resolve_issuer_context(
    profile_document: &Value,
    registry: &Value,
    certificates: &Value,
    request: &IssuerContextRequest,
) -> Result<Value, CompatibilityError> {
    let profiles = profile_document
        .get("profiles")
        .and_then(Value::as_array)
        .ok_or(CompatibilityError::Unavailable)?;
    let issuer_did = request
        .issuer_did
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    let selected = profiles::find_profiles(
        profiles,
        &request.organization_id,
        &FindProfilesRequest {
            active_only: true,
            issuer_did: issuer_did.clone(),
            issuer_mode: issuer_did
                .is_none()
                .then(|| normalized_or(&request.issuer_mode, "org_managed")),
            key_purpose: clean(request.key_purpose.as_deref()),
            require_signing_service: true,
            ..FindProfilesRequest::default()
        },
    );
    let profile = match selected.as_slice() {
        [] => return Err(CompatibilityError::ProfileNotFound),
        [profile] => profile,
        _ => return Err(CompatibilityError::AmbiguousProfile),
    };
    let service_id = required(profile, "signing_service_id")?;
    let mut service = registry
        .get("services")
        .and_then(Value::as_array)
        .and_then(|services| {
            services
                .iter()
                .find(|service| service.get("id").and_then(Value::as_str) == Some(service_id))
        })
        .and_then(Value::as_object)
        .cloned()
        .ok_or(CompatibilityError::ServiceNotFound)?;
    merge_certificate(&mut service, certificates, service_id);
    let key_reference = profile
        .get("signing_key_reference")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .or_else(|| service.get("key_reference").and_then(Value::as_str))
        .map(str::to_owned);
    if let Some(key_reference) = &key_reference {
        service.insert("key_reference".into(), Value::String(key_reference.clone()));
    }
    let requested_purpose = clean(request.key_purpose.as_deref())
        .or_else(|| clean(profile.get("key_purpose").and_then(Value::as_str)))
        .unwrap_or_else(|| "vc_jwt_issuer".into());
    let mut effective_profile = profile.clone();
    if let Some(key_reference) = &key_reference {
        effective_profile["signing_key_reference"] = Value::String(key_reference.clone());
    }
    effective_profile["key_purpose"] = Value::String(requested_purpose.clone());
    profiles::validate_binding(&ValidateBindingRequest {
        profile: effective_profile,
        service: Value::Object(service.clone()),
        registry: registry.clone(),
    })
    .map_err(map_profile_error)?;

    let issuer_did = profile.get("issuer_did").cloned().unwrap_or(Value::Null);
    let issuer_did_text = issuer_did.as_str().unwrap_or_default();
    let verification_method_id = profile
        .get("verification_method_id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| {
            key_reference.as_deref().map(|reference| {
                format!(
                    "{issuer_did_text}#{}",
                    documents::did_fragment(service_id, Some(reference))
                )
            })
        })
        .unwrap_or_else(|| {
            format!(
                "{issuer_did_text}#{}",
                documents::did_fragment(service_id, None)
            )
        });
    let issuer_x5c = service
        .get("x5c")
        .filter(|value| value.is_array())
        .cloned()
        .unwrap_or_else(|| json!([]));
    Ok(json!({
        "ok": true,
        "organization_id": request.organization_id,
        "issuer_profile_id": profile.get("id").cloned().unwrap_or(Value::Null),
        "issuer_mode": profile.get("issuer_mode").cloned().unwrap_or_else(|| json!("org_managed")),
        "issuer_did": issuer_did,
        "signing_service_id": service_id,
        "signing_key_reference": key_reference,
        "verification_method_id": verification_method_id,
        "key_purpose": profile.get("key_purpose").cloned().unwrap_or_else(|| Value::String(requested_purpose)),
        "issuer_x5c": issuer_x5c,
        "issuer_profile": profile,
        "service": service
    }))
}

pub async fn resolve_issuer_identity(
    profile_document: &Value,
    registry: &Value,
    certificates: &Value,
    did_document: &Value,
    request: &ResolveIssuerDidRequest,
) -> Result<Value, CompatibilityError> {
    validate_resolve_request(request)?;
    let profiles = profile_document
        .get("profiles")
        .and_then(Value::as_array)
        .ok_or(CompatibilityError::Unavailable)?;
    let key_purpose = clean(request.key_purpose.as_deref());
    let wire_credential_format = clean(request.credential_format.as_deref())
        .map(|credential_format| {
            profiles::custody_format(&CustodyFormatRequest {
                credential_format,
                key_purpose: key_purpose
                    .clone()
                    .unwrap_or_else(|| "vc_jwt_issuer".to_owned()),
            })
            .map(|response| response.wire_format)
            .map_err(map_profile_error)
        })
        .transpose()?;
    let active_profiles = profiles::find_profiles(
        profiles,
        &request.organization_id,
        &FindProfilesRequest {
            active_only: true,
            issuer_did: Some(request.issuer_did.clone()),
            key_purpose,
            wire_credential_format: wire_credential_format.clone(),
            algorithm: clean(request.algorithm.as_deref()),
            allow_missing_algorithm: request.algorithm.is_some(),
            require_signing_service: true,
            ..FindProfilesRequest::default()
        },
    );
    if active_profiles.is_empty() {
        return Err(CompatibilityError::NotFound(
            "Issuer DID is not an active issuer identity for this organization.".into(),
        ));
    }
    let mut resolved = Vec::new();
    let mut mismatch =
        "No matching DID verification method was found for the issuer profile.".to_owned();
    for profile in active_profiles {
        let service_id = required(&profile, "signing_service_id")?;
        let Some(mut service) = service_for(registry, service_id) else {
            continue;
        };
        merge_certificate(&mut service, certificates, service_id);
        let key_reference = clean(profile.get("signing_key_reference").and_then(Value::as_str))
            .or_else(|| clean(service.get("key_reference").and_then(Value::as_str)));
        if let Some(reference) = &key_reference {
            service.insert("key_reference".into(), Value::String(reference.clone()));
        }
        let mut effective_profile = profile.clone();
        if let Some(reference) = &key_reference {
            effective_profile["signing_key_reference"] = Value::String(reference.clone());
        }
        effective_profile["key_purpose"] = Value::String(
            clean(request.key_purpose.as_deref())
                .or_else(|| clean(profile.get("key_purpose").and_then(Value::as_str)))
                .unwrap_or_else(|| "vc_jwt_issuer".into()),
        );
        profiles::validate_binding(&ValidateBindingRequest {
            profile: effective_profile.clone(),
            service: Value::Object(service.clone()),
            registry: registry.clone(),
        })
        .map_err(map_profile_error)?;

        if let Some(format) = wire_credential_format.as_deref() {
            if !supports(&service, "credential_formats", format) {
                mismatch = format!(
                    "Signing service '{service_id}' is not configured for credential_format '{format}'."
                );
                continue;
            }
        }
        if let Some(purpose) = clean(request.key_purpose.as_deref()) {
            if !supports(&service, "key_purposes", &purpose) {
                mismatch = format!(
                    "Signing service '{service_id}' is not configured for key_purpose '{purpose}'."
                );
                continue;
            }
        }
        if let Some(algorithm) = clean(request.algorithm.as_deref()) {
            if !supports(&service, "algorithms", &algorithm) {
                mismatch = format!(
                    "Signing service '{service_id}' does not support algorithm '{algorithm}'."
                );
                continue;
            }
        }
        let candidates = verification_method_candidates(
            &request.issuer_did,
            request.verification_method_id.as_deref(),
            &profile,
            service_id,
            key_reference.as_deref(),
        );
        let Some(method) = find_verification_method(did_document, &request.issuer_did, &candidates)
        else {
            continue;
        };
        let method_id = required(&method, "id")?.to_owned();
        let mut public_jwk = public_jwk_from_method(&method);
        if public_jwk.is_none() {
            let response = kms::public_key(ProviderRequest {
                service_config: Value::Object(service.clone()),
            })
            .await
            .map_err(|_| CompatibilityError::Unavailable)?;
            public_jwk = extract_provider_jwk(&response);
        }
        let Some(mut public_jwk) = public_jwk else {
            return Err(CompatibilityError::Unavailable);
        };
        public_jwk.insert("kid".into(), Value::String(method_id.clone()));
        if effective_profile
            .get("verification_method_id")
            .and_then(Value::as_str)
            .is_none()
        {
            effective_profile["verification_method_id"] = Value::String(method_id.clone());
        }
        if effective_profile
            .get("algorithm")
            .and_then(Value::as_str)
            .is_none()
        {
            if let Some(algorithm) = clean(request.algorithm.as_deref())
                .or_else(|| single_string(&service, "algorithms"))
            {
                effective_profile["algorithm"] = Value::String(algorithm);
            }
        }
        let issuer_x5c = service
            .get("x5c")
            .filter(|value| value.is_array())
            .cloned()
            .unwrap_or_else(|| json!([]));
        resolved.push(json!({
            "ok": true,
            "organization_id": request.organization_id,
            "issuer_did": request.issuer_did,
            "verification_method_id": method_id,
            "public_jwk": public_jwk,
            "verification_method": method,
            "did_document": did_document,
            "key_purpose": effective_profile.get("key_purpose").cloned().unwrap_or(Value::Null),
            "algorithm": effective_profile.get("algorithm").cloned().unwrap_or(Value::Null),
            "issuer_profile": effective_profile,
            "issuer_x5c": issuer_x5c,
            "signing_service": safe_service(&service),
            "resolver": {
                "type": "organization_issuer_profile",
                "source": "gateway_signing_key_registry",
                "public_fallback_used": false,
                "resolved_at": chrono::Utc::now().to_rfc3339()
            }
        }));
    }
    match resolved.len() {
        0 => Err(CompatibilityError::NotFound(mismatch)),
        1 => Ok(resolved.pop().expect("one resolved identity")),
        _ => Err(CompatibilityError::Conflict(
            "Issuer DID resolves to multiple active issuer profiles for the requested organization, purpose, format, and algorithm. Repair the issuer registry before signing."
                .into(),
        )),
    }
}

fn validate_resolve_request(request: &ResolveIssuerDidRequest) -> Result<(), CompatibilityError> {
    if request.organization_id.trim().is_empty() {
        return Err(CompatibilityError::Invalid(
            "organization_id is required.".into(),
        ));
    }
    if !request.issuer_did.starts_with("did:") {
        return Err(CompatibilityError::Invalid(
            "issuer_did must be a DID string.".into(),
        ));
    }
    Ok(())
}

fn signing_payload(
    payload_b64: Option<&str>,
    payload_hex: Option<&str>,
) -> Result<Vec<u8>, CompatibilityError> {
    let payload = if let Some(encoded) = clean(payload_b64) {
        decode_base64(&encoded, "payload_b64")?
    } else if let Some(encoded) = clean(payload_hex) {
        decode_hex(&encoded).map_err(|detail| {
            CompatibilityError::BadRequest(format!("Invalid payload_hex: {detail}"))
        })?
    } else {
        return Err(CompatibilityError::BadRequest(
            "Either payload_b64 or payload_hex is required".into(),
        ));
    };
    if payload.is_empty() {
        return Err(CompatibilityError::BadRequest(
            "Either payload_b64 or payload_hex is required".into(),
        ));
    }
    Ok(payload)
}

fn decode_base64(value: &str, field: &str) -> Result<Vec<u8>, CompatibilityError> {
    let unpadded = value.trim_end_matches('=');
    URL_SAFE_NO_PAD
        .decode(unpadded)
        .or_else(|_| STANDARD_NO_PAD.decode(unpadded))
        .or_else(|_| URL_SAFE.decode(value))
        .or_else(|_| STANDARD.decode(value))
        .map_err(|error| CompatibilityError::BadRequest(format!("Invalid {field}: {error}")))
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) {
        return Err("hex input must contain an even number of characters".into());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .map_err(|_| "hex input is not UTF-8".to_owned())
                .and_then(|pair| {
                    u8::from_str_radix(pair, 16)
                        .map_err(|_| "hex input contains a non-hex character".to_owned())
                })
        })
        .collect()
}

fn encode_hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn selected_algorithm(
    service: &Map<String, Value>,
    requested: Option<&str>,
) -> Result<String, CompatibilityError> {
    let algorithms = service
        .get("algorithms")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    if let Some(requested) = clean(requested) {
        if !algorithms.is_empty() && !algorithms.contains(&requested.as_str()) {
            return Err(CompatibilityError::BadRequest(format!(
                "Algorithm '{requested}' not supported by this service. Supported: {algorithms:?}"
            )));
        }
        return Ok(requested);
    }
    Ok(algorithms.first().copied().unwrap_or("ES256").to_owned())
}

fn authorize_signing_binding(
    registry: &Value,
    service: &Map<String, Value>,
    service_id: &str,
    key_reference: Option<&str>,
    key_purpose: Option<&str>,
    algorithm: Option<&str>,
) -> Result<(), CompatibilityError> {
    let reference_purposes = key_reference
        .and_then(|reference| {
            registry
                .pointer(&format!(
                    "/key_reference_purposes/{}/{}",
                    escape_pointer(service_id),
                    escape_pointer(reference)
                ))
                .and_then(Value::as_array)
        })
        .map(|values| values.iter().filter_map(Value::as_str).collect::<Vec<_>>())
        .unwrap_or_default();
    if reference_purposes.contains(&"lti_tool_signing") && key_purpose != Some("lti_tool_signing") {
        return Err(CompatibilityError::Conflict(format!(
            "Key reference '{}' is reserved exclusively for lti_tool_signing.",
            key_reference.unwrap_or_default()
        )));
    }
    if let Some(purpose) = clean(key_purpose) {
        if !crate::domain::key_purposes()
            .iter()
            .any(|definition| definition.id == purpose)
        {
            return Err(CompatibilityError::Invalid(format!(
                "Unsupported key_purpose '{purpose}'."
            )));
        }
        let configured = service
            .get("key_purposes")
            .and_then(Value::as_array)
            .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(&purpose)));
        if !configured {
            return Err(CompatibilityError::Conflict(format!(
                "Signing service '{service_id}' is not configured for key_purpose '{purpose}'."
            )));
        }
    }
    if key_purpose == Some("lti_tool_signing") {
        if key_reference.is_none_or(str::is_empty) {
            return Err(CompatibilityError::Conflict(
                "LTI tool signing requires an explicit key_reference; the signing service default may be a credential issuer key.".into(),
            ));
        }
        if algorithm != Some("RS256") {
            return Err(CompatibilityError::Conflict(
                "LTI tool signing requires the dedicated RSA/RS256 key.".into(),
            ));
        }
        if reference_purposes != ["lti_tool_signing"] {
            return Err(CompatibilityError::Conflict(format!(
                "Key reference '{}' is not registered exclusively for lti_tool_signing.",
                key_reference.unwrap_or_default()
            )));
        }
    }
    Ok(())
}

fn reject_credential_profile_key_reuse(
    profile_document: &Value,
    service_id: &str,
    key_reference: &str,
) -> Result<(), CompatibilityError> {
    let reused = profile_document
        .get("profiles")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .filter(|profile| profile.get("status").and_then(Value::as_str) != Some("archived"))
        .filter(|profile| {
            profile.get("key_purpose").and_then(Value::as_str) != Some("lti_tool_signing")
        })
        .any(|profile| {
            profile
                .get("signing_key_reference")
                .and_then(Value::as_str)
                .map_or_else(
                    || {
                        profile.get("signing_service_id").and_then(Value::as_str)
                            == Some(service_id)
                    },
                    |reference| reference.trim() == key_reference,
                )
        });
    if reused {
        return Err(CompatibilityError::Conflict(format!(
            "Key reference '{key_reference}' is assigned to a credential issuer profile and cannot sign LTI assertions."
        )));
    }
    Ok(())
}

fn map_kms_error(error: kms::KmsError) -> CompatibilityError {
    match error {
        kms::KmsError::InvalidConfig(detail) | kms::KmsError::UnsupportedProvider(detail) => {
            CompatibilityError::BadRequest(detail)
        }
        _ => CompatibilityError::Unavailable,
    }
}

async fn complete_profile_binding(
    profile: &mut Value,
    service: &mut Map<String, Value>,
) -> Result<(), CompatibilityError> {
    let key_reference = clean(profile.get("signing_key_reference").and_then(Value::as_str))
        .or_else(|| clean(service.get("key_reference").and_then(Value::as_str)));
    if let Some(reference) = &key_reference {
        profile["signing_key_reference"] = Value::String(reference.clone());
        service.insert("key_reference".into(), Value::String(reference.clone()));
    }
    let requested = clean(profile.get("algorithm").and_then(Value::as_str));
    let managed = service.get("id").and_then(Value::as_str) == Some("managed-openbao-transit");
    if managed {
        let reference = key_reference.as_deref().ok_or_else(|| {
            CompatibilityError::Invalid(
                "Issuer profiles require an explicit signing key reference.".into(),
            )
        })?;
        let purpose = required(profile, "key_purpose")?;
        if !managed_key_purposes(reference).contains(&purpose) {
            return Err(CompatibilityError::Invalid(format!(
                "Managed KMS key '{reference}' is not provisioned for key_purpose '{purpose}'."
            )));
        }
        let provider_key = kms::public_key(ProviderRequest {
            service_config: Value::Object(service.clone()),
        })
        .await
        .map_err(map_kms_error)?;
        let jwk = extract_provider_jwk(&provider_key).ok_or(CompatibilityError::Unavailable)?;
        let discovered = algorithm_for_jwk(&jwk).ok_or_else(|| {
            CompatibilityError::Invalid(format!(
                "Managed KMS key '{reference}' uses an unsupported public key type."
            ))
        })?;
        if requested
            .as_deref()
            .is_some_and(|value| value != discovered)
        {
            return Err(CompatibilityError::Invalid(format!(
                "Managed KMS key '{reference}' uses algorithm '{discovered}', not '{}'.",
                requested.as_deref().unwrap_or_default()
            )));
        }
        profile["algorithm"] = Value::String(discovered.into());
        return Ok(());
    }
    if requested.is_some() {
        return Ok(());
    }
    let algorithms = service
        .get("algorithms")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    if algorithms.len() == 1 {
        profile["algorithm"] = Value::String(algorithms[0].into());
        Ok(())
    } else {
        Err(CompatibilityError::Invalid(
            "Issuer profile algorithm could not be determined from the selected KMS key. Specify an algorithm that matches the key binding.".into(),
        ))
    }
}

fn managed_key_purposes(reference: &str) -> &'static [&'static str] {
    if reference.starts_with("oid4vp-verifier-") {
        &["oid4vp_request_signing"]
    } else if reference.starts_with("lti-tool-") {
        &["lti_tool_signing"]
    } else if reference.starts_with("cred-dsc-") {
        &["mdoc_dsc", "x509_doc_signer", "vdsnc_signing", "csca"]
    } else if reference.starts_with("cred-issuer-") {
        &["vc_jwt_issuer", "jwks_signing"]
    } else {
        &[]
    }
}

fn algorithm_for_jwk(jwk: &Map<String, Value>) -> Option<&'static str> {
    match (
        jwk.get("kty").and_then(Value::as_str),
        jwk.get("crv").and_then(Value::as_str),
    ) {
        (Some("EC"), Some("P-256")) => Some("ES256"),
        (Some("EC"), Some("P-384")) => Some("ES384"),
        (Some("RSA"), _) => Some("RS256"),
        (Some("OKP"), Some("Ed25519")) => Some("EdDSA"),
        _ => None,
    }
}

fn map_document_error(error: documents::DocumentError) -> CompatibilityError {
    match error {
        documents::DocumentError::Invalid(detail) => CompatibilityError::BadRequest(detail),
        documents::DocumentError::Conflict(detail) => CompatibilityError::Conflict(detail),
        documents::DocumentError::NotFound(detail) => CompatibilityError::NotFound(detail),
        documents::DocumentError::Storage(_) | documents::DocumentError::Corrupt(_) => {
            CompatibilityError::Unavailable
        }
    }
}

fn service_for(registry: &Value, service_id: &str) -> Option<Map<String, Value>> {
    registry
        .get("services")
        .and_then(Value::as_array)?
        .iter()
        .find(|service| service.get("id").and_then(Value::as_str) == Some(service_id))?
        .as_object()
        .cloned()
}

fn supports(service: &Map<String, Value>, field: &str, requested: &str) -> bool {
    service
        .get(field)
        .and_then(Value::as_array)
        .is_none_or(|values| {
            values.is_empty()
                || values.iter().any(|value| {
                    value.as_str().is_some_and(|configured| {
                        configured == requested
                            || (field == "algorithms" && configured.eq_ignore_ascii_case(requested))
                    })
                })
        })
}

fn single_string(service: &Map<String, Value>, field: &str) -> Option<String> {
    let values = service.get(field)?.as_array()?;
    (values.len() == 1)
        .then(|| values[0].as_str().map(str::to_owned))
        .flatten()
}

fn verification_method_candidates(
    issuer_did: &str,
    requested: Option<&str>,
    profile: &Value,
    service_id: &str,
    key_reference: Option<&str>,
) -> Vec<String> {
    let raw = [
        requested,
        profile
            .get("verification_method_id")
            .and_then(Value::as_str),
        profile.get("kid").and_then(Value::as_str),
        profile.get("signing_key_reference").and_then(Value::as_str),
        key_reference,
    ];
    let generated_fragment = documents::did_fragment(service_id, key_reference);
    let mut candidates = Vec::new();
    for value in raw
        .into_iter()
        .flatten()
        .chain(std::iter::once(generated_fragment.as_str()))
    {
        if let Some(normalized) = normalize_method_id(issuer_did, value) {
            if !candidates.contains(&normalized) {
                candidates.push(normalized);
            }
        }
    }
    candidates
}

fn normalize_method_id(issuer_did: &str, value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else if value.starts_with('#') {
        Some(format!("{issuer_did}{value}"))
    } else if value.starts_with("did:") || value.contains('#') {
        Some(value.into())
    } else {
        Some(format!("{issuer_did}#{value}"))
    }
}

fn find_verification_method(
    document: &Value,
    issuer_did: &str,
    candidates: &[String],
) -> Option<Value> {
    let assertion_ids = document
        .get("assertionMethod")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            entry
                .as_str()
                .or_else(|| entry.get("id").and_then(Value::as_str))
        })
        .filter_map(|value| normalize_method_id(issuer_did, value))
        .collect::<Vec<_>>();
    document
        .get("verificationMethod")
        .and_then(Value::as_array)?
        .iter()
        .filter_map(Value::as_object)
        .find_map(|method| {
            let method_id = normalize_method_id(issuer_did, method.get("id")?.as_str()?)?;
            if !candidates.is_empty() && !candidates.contains(&method_id) {
                return None;
            }
            if !assertion_ids.is_empty() && !assertion_ids.contains(&method_id) {
                return None;
            }
            let mut method = method.clone();
            method.insert("id".into(), Value::String(method_id));
            Some(Value::Object(method))
        })
}

fn public_jwk_from_method(method: &Value) -> Option<Map<String, Value>> {
    let mut jwk = method.get("publicKeyJwk")?.as_object()?.clone();
    jwk.get("kty").and_then(Value::as_str)?;
    for private in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
        jwk.remove(private);
    }
    if !jwk.contains_key("kid") {
        if let Some(id) = method.get("id") {
            jwk.insert("kid".into(), id.clone());
        }
    }
    Some(jwk)
}

fn extract_provider_jwk(response: &Value) -> Option<Map<String, Value>> {
    response
        .get("public_jwk")
        .unwrap_or(response)
        .as_object()
        .filter(|jwk| jwk.get("kty").and_then(Value::as_str).is_some())
        .cloned()
}

fn safe_service(service: &Map<String, Value>) -> Value {
    const ALLOWED: &[&str] = &[
        "id",
        "name",
        "service_type",
        "provider",
        "provider_label",
        "protocol",
        "category",
        "region",
        "key_reference",
        "key_aliases",
        "algorithms",
        "status",
        "managed",
        "read_only",
        "key_purposes",
        "credential_formats",
        "signature_encoding",
        "created_at",
        "updated_at",
    ];
    Value::Object(
        service
            .iter()
            .filter(|(name, _)| ALLOWED.contains(&name.as_str()))
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect(),
    )
}

fn empty_did_document(issuer_did: &str) -> Value {
    json!({
        "id": issuer_did,
        "controller": issuer_did,
        "verificationMethod": [],
        "assertionMethod": []
    })
}

fn retarget_document(document: &Value, issuer_did: &str) -> Value {
    let Some(source) = document.as_object() else {
        return empty_did_document(issuer_did);
    };
    let source_did = source
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or(issuer_did);
    if source_did == issuer_did {
        return document.clone();
    }
    let rewrite = |value: &str| {
        value
            .strip_prefix(source_did)
            .filter(|suffix| suffix.starts_with('#'))
            .map_or_else(|| value.into(), |suffix| format!("{issuer_did}{suffix}"))
    };
    let mut output = source.clone();
    output.insert("id".into(), Value::String(issuer_did.into()));
    output.insert("controller".into(), Value::String(issuer_did.into()));
    let methods = source
        .get("verificationMethod")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .map(|method| {
            let mut method = method.clone();
            if let Some(id) = method.get("id").and_then(Value::as_str) {
                method.insert("id".into(), Value::String(rewrite(id)));
            }
            if method.get("controller").and_then(Value::as_str) == Some(source_did) {
                method.insert("controller".into(), Value::String(issuer_did.into()));
            }
            Value::Object(method)
        })
        .collect();
    output.insert("verificationMethod".into(), Value::Array(methods));
    for relationship in [
        "authentication",
        "assertionMethod",
        "keyAgreement",
        "capabilityInvocation",
        "capabilityDelegation",
    ] {
        let Some(entries) = source.get(relationship).and_then(Value::as_array) else {
            continue;
        };
        output.insert(
            relationship.into(),
            Value::Array(
                entries
                    .iter()
                    .map(|entry| {
                        if let Some(value) = entry.as_str() {
                            Value::String(rewrite(value))
                        } else if let Some(method) = entry.as_object() {
                            let mut method = method.clone();
                            if let Some(id) = method.get("id").and_then(Value::as_str) {
                                method.insert("id".into(), Value::String(rewrite(id)));
                            }
                            if method.get("controller").and_then(Value::as_str) == Some(source_did)
                            {
                                method
                                    .insert("controller".into(), Value::String(issuer_did.into()));
                            }
                            Value::Object(method)
                        } else {
                            entry.clone()
                        }
                    })
                    .collect(),
            ),
        );
    }
    Value::Object(output)
}

fn merge_certificate(service: &mut Map<String, Value>, certificates: &Value, service_id: &str) {
    let Some(attachment) = certificates
        .pointer(&format!("/services/{}", escape_pointer(service_id)))
        .and_then(Value::as_object)
    else {
        return;
    };
    for (name, value) in attachment {
        service.insert(name.clone(), value.clone());
    }
}

fn escape_pointer(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

fn required<'a>(value: &'a Value, name: &str) -> Result<&'a str, CompatibilityError> {
    value
        .get(name)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| CompatibilityError::Invalid(format!("Issuer profile is missing {name}.")))
}

fn clean(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn normalized_or(value: &str, fallback: &str) -> String {
    clean(Some(value)).unwrap_or_else(|| fallback.into())
}

fn map_profile_error(error: profiles::ProfileError) -> CompatibilityError {
    match error {
        profiles::ProfileError::Invalid(detail) => CompatibilityError::Invalid(detail),
        profiles::ProfileError::Conflict(detail) => CompatibilityError::Conflict(detail),
        profiles::ProfileError::NotFound(detail) => CompatibilityError::NotFound(detail),
        profiles::ProfileError::Storage(_) | profiles::ProfileError::Corrupt(_) => {
            CompatibilityError::Unavailable
        }
    }
}

fn default_issuer_mode() -> String {
    "org_managed".into()
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Deserialize)]
    struct Contract {
        schema_version: u8,
        request: IssuerContextRequest,
        profile_document: Value,
        registry: Value,
        certificates: Value,
        expected: Value,
    }

    #[derive(Deserialize)]
    struct IdentityContract {
        schema_version: u8,
        request: ResolveIssuerDidRequest,
        profile_document: Value,
        registry: Value,
        certificates: Value,
        did_document: Value,
        expected_without_resolved_at: Value,
    }

    #[derive(Deserialize)]
    struct SigningContract {
        schema_version: u8,
        service: Map<String, Value>,
        cases: Vec<SigningCase>,
    }

    #[derive(Deserialize)]
    struct SigningCase {
        name: String,
        registry: Value,
        request: Value,
        expected: Option<Value>,
        expected_error: Option<Value>,
    }

    #[test]
    fn issuer_context_selects_one_did_and_includes_profile_certificate_chain() {
        let contract: Contract = serde_json::from_str(include_str!(
            "../../../../contracts/gateway-issuer-context-behavior.json"
        ))
        .expect("issuer context contract");
        assert_eq!(contract.schema_version, 1);
        let result = resolve_issuer_context(
            &contract.profile_document,
            &contract.registry,
            &contract.certificates,
            &contract.request,
        )
        .expect("issuer context");
        assert_eq!(result, contract.expected);
    }

    #[tokio::test]
    async fn issuer_identity_matches_language_neutral_behavior() {
        let contract: IdentityContract = serde_json::from_str(include_str!(
            "../../../../contracts/gateway-issuer-identity-behavior.json"
        ))
        .expect("issuer identity contract");
        assert_eq!(contract.schema_version, 1);
        let mut result = resolve_issuer_identity(
            &contract.profile_document,
            &contract.registry,
            &contract.certificates,
            &contract.did_document,
            &contract.request,
        )
        .await
        .expect("issuer identity");
        result
            .pointer_mut("/resolver")
            .and_then(Value::as_object_mut)
            .expect("resolver")
            .remove("resolved_at");
        assert_eq!(result, contract.expected_without_resolved_at);
    }

    #[test]
    fn did_public_jwk_strips_private_parameters() {
        let method = json!({
            "id": "did:web:issuer.example#key-1",
            "publicKeyJwk": {"kty": "EC", "crv": "P-256", "x": "x", "y": "y", "d": "secret"}
        });
        let jwk = public_jwk_from_method(&method).expect("public JWK");
        assert!(!jwk.contains_key("d"));
        assert_eq!(jwk.get("kid"), method.get("id"));
    }

    #[test]
    fn service_signing_authorization_matches_language_neutral_behavior() {
        let contract: SigningContract = serde_json::from_str(include_str!(
            "../../../../contracts/gateway-signing-authorization-behavior.json"
        ))
        .expect("signing authorization contract");
        assert_eq!(contract.schema_version, 1);
        for case in contract.cases {
            let payload = signing_payload(
                case.request.get("payload_b64").and_then(Value::as_str),
                case.request.get("payload_hex").and_then(Value::as_str),
            )
            .expect("contract payload");
            let mut service = contract.service.clone();
            if let Some(reference) = case.request.get("key_reference").cloned() {
                service.insert("key_reference".into(), reference);
            }
            let authorization = authorize_signing_binding(
                &case.registry,
                &service,
                "service-1",
                case.request.get("key_reference").and_then(Value::as_str),
                case.request.get("key_purpose").and_then(Value::as_str),
                case.request.get("algorithm").and_then(Value::as_str),
            )
            .and_then(|()| {
                selected_algorithm(
                    &service,
                    case.request.get("algorithm").and_then(Value::as_str),
                )
            });
            if let Some(expected) = case.expected {
                assert_eq!(
                    encode_hex(&payload),
                    expected["payload_hex"],
                    "{}",
                    case.name
                );
                assert_eq!(authorization.expect(&case.name), expected["algorithm"]);
            } else {
                let error = authorization.expect_err(&case.name);
                let expected = case.expected_error.expect("expected error");
                assert!(
                    error
                        .to_string()
                        .contains(expected["contains"].as_str().unwrap()),
                    "{}: {error}",
                    case.name
                );
                let status = match error {
                    CompatibilityError::BadRequest(_) => 400,
                    CompatibilityError::Conflict(_) => 409,
                    CompatibilityError::Invalid(_) => 422,
                    _ => 500,
                };
                assert_eq!(status, expected["status"], "{}", case.name);
            }
        }
    }
}
