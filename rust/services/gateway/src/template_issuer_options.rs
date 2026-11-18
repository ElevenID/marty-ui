//! Public template selection constraints, shared with actual template writes.
use marty_credential_template::{CredentialFormat, IssuanceProtocol};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OptionsRequest {
    pub organization_id: String,
    pub compliance_profile_id: String,
    pub credential_payload_format: Option<String>,
    pub supported_formats: Option<Vec<String>>,
}

#[derive(Debug)]
pub struct OptionsError(pub u16, pub &'static str);

#[derive(Debug, Clone)]
pub struct TemplateIssuerContext {
    pub organization_id: String,
    pub compliance_profile_id: String,
    pub primary: CredentialFormat,
    pub formats: Vec<CredentialFormat>,
    pub protocol: IssuanceProtocol,
    pub requires_x509: bool,
}

impl OptionsRequest {
    pub fn validate(&self) -> Result<(), OptionsError> {
        for value in [&self.organization_id, &self.compliance_profile_id] {
            if value.trim().is_empty() || value.len() > 255 {
                return Err(OptionsError(
                    422,
                    "Organization and compliance profile are required.",
                ));
            }
        }
        Ok(())
    }
}

impl TemplateIssuerContext {
    pub fn from_profile(request: &OptionsRequest, profile: &Value) -> Result<Self, OptionsError> {
        request.validate()?;
        if profile["id"].as_str() != Some(request.compliance_profile_id.as_str()) {
            return Err(OptionsError(
                502,
                "Compliance profile returned an invalid identity.",
            ));
        }
        match profile.get("organization_id") {
            Some(Value::String(org)) if org == &request.organization_id => {}
            None | Some(Value::Null) if profile["is_system"] == true => {}
            _ => {
                return Err(OptionsError(
                    403,
                    "Compliance profile is not authorized for this organization.",
                ))
            }
        }
        if !profile["status"]
            .as_str()
            .is_some_and(|value| value.eq_ignore_ascii_case("active"))
            || profile.get("discoverable") == Some(&Value::Bool(false))
        {
            return Err(OptionsError(
                422,
                "An active discoverable compliance profile is required.",
            ));
        }
        let format = profile["credential_format"]
            .as_str()
            .and_then(|value| CredentialFormat::parse(value).ok())
            .ok_or(OptionsError(
                502,
                "Compliance profile returned an invalid credential format.",
            ))?;
        let primary = request
            .credential_payload_format
            .as_deref()
            .map(|value| marty_credential_template::normalize_payload_format(Some(value), &[]))
            .transpose()
            .map_err(|_| OptionsError(422, "Credential payload format is invalid."))?
            .unwrap_or(format);
        if primary != format {
            return Err(OptionsError(
                422,
                "Credential payload format does not match the compliance profile.",
            ));
        }
        let mut formats = Vec::new();
        if let Some(values) = &request.supported_formats {
            if values.is_empty() {
                return Err(OptionsError(
                    422,
                    "At least one supported format is required.",
                ));
            }
            for value in values {
                let format = CredentialFormat::parse(value)
                    .map_err(|_| OptionsError(422, "Supported credential format is invalid."))?;
                if !formats.contains(&format) {
                    formats.push(format);
                }
            }
        } else {
            formats.push(primary);
        }
        if !formats.contains(&primary) {
            return Err(OptionsError(
                422,
                "Supported formats must include the payload format.",
            ));
        }
        let protocol = IssuanceProtocol::parse(profile["issuance_protocol"].as_str())
            .map_err(|_| OptionsError(422, "The compliance profile issuance protocol is not supported by credential templates."))?;
        // Reuse the owner's format/protocol rules; placeholder identifiers here
        // only avoid requiring claim-document fields during option discovery.
        marty_credential_template::validate_protocol_requirements(
            Some(&request.compliance_profile_id),
            primary,
            protocol,
            &formats,
            Some("urn:marty:issuer-options"),
            Some("pending"),
        )
        .map_err(|_| {
            OptionsError(
                422,
                "Credential format and issuance protocol are incompatible.",
            )
        })?;
        Ok(Self {
            organization_id: request.organization_id.clone(),
            compliance_profile_id: request.compliance_profile_id.clone(),
            primary,
            formats,
            protocol,
            requires_x509: profile["issuer_artifact_requirements"]["requires_x509_cert"] == true,
        })
    }

    pub fn describe(&self) -> Value {
        json!({"organization_id":self.organization_id, "compliance_profile_id":self.compliance_profile_id,
        "credential_payload_format":self.primary.canonical(), "supported_formats":self.formats.iter().map(|format| format.canonical()).collect::<Vec<_>>(),
        "issuance_protocol":self.protocol.wire(), "requirements":{
            "vct":self.formats.contains(&CredentialFormat::SdJwtVc),
            "doctype":self.formats.iter().any(|format| matches!(format, CredentialFormat::Mdoc|CredentialFormat::ZkMdoc)),
            "revocation_profile":self.protocol != IssuanceProtocol::PhysicalDocument,
            "x509_certificate":self.requires_x509
        }})
    }

    pub fn validate_template(&self, body: &Value) -> Result<(), OptionsError> {
        if !body["issuance_protocol"].is_null() {
            let protocol = body["issuance_protocol"]
                .as_str()
                .ok_or(OptionsError(422, "Issuance protocol must be a string."))?;
            if IssuanceProtocol::parse(Some(protocol)).ok() != Some(self.protocol) {
                return Err(OptionsError(
                    422,
                    "Issuance protocol does not match the compliance profile.",
                ));
            }
        }
        marty_credential_template::validate_protocol_requirements(
            Some(&self.compliance_profile_id),
            self.primary,
            self.protocol,
            &self.formats,
            body["vct"].as_str(),
            body["doctype"].as_str(),
        )
        .map_err(|_| {
            OptionsError(
                422,
                "Template fields do not satisfy its format and issuance protocol.",
            )
        })
    }

    pub fn binding(
        &self,
        did: &str,
        format: CredentialFormat,
        resolved: &Value,
    ) -> Result<Value, OptionsError> {
        let profile = &resolved["issuer_profile"];
        let algorithm = resolved["algorithm"]
            .as_str()
            .filter(|value| !value.trim().is_empty());
        if resolved["ok"] != true
            || resolved["organization_id"].as_str() != Some(&self.organization_id)
            || resolved["issuer_did"].as_str() != Some(did)
            || resolved["key_purpose"] != format.issuer_key_purpose()
            || profile["organization_id"].as_str() != Some(&self.organization_id)
            || profile["issuer_did"].as_str() != Some(did)
            || profile["status"] != "active"
            || profile["credential_format"]
                .as_str()
                .and_then(|value| CredentialFormat::parse(value).ok())
                != Some(format)
            || profile["key_purpose"] != format.issuer_key_purpose()
            || algorithm.is_none()
            || profile["algorithm"].as_str() != algorithm
            || resolved["public_jwk"]["alg"]
                .as_str()
                .is_some_and(|value| Some(value) != algorithm)
            || !resolved["public_jwk"].as_object().is_some_and(|jwk| {
                jwk.get("kty").is_some_and(Value::is_string)
                    && !["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
                        .iter()
                        .any(|field| jwk.contains_key(*field))
            })
        {
            return Err(OptionsError(
                502,
                "Issuer registry returned an invalid binding.",
            ));
        }
        if self.requires_x509
            && !resolved["issuer_x5c"].as_array().is_some_and(|values| {
                !values.is_empty()
                    && values
                        .iter()
                        .all(|value| value.as_str().is_some_and(|value| !value.trim().is_empty()))
            })
        {
            return Err(OptionsError(
                422,
                "The compliance profile requires an issuer certificate.",
            ));
        }
        Ok(
            json!({"credential_format":format.canonical(), "key_purpose":format.issuer_key_purpose(), "algorithm":algorithm}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> OptionsRequest {
        serde_json::from_value(
            json!({"organization_id":"org-a", "compliance_profile_id":"compliance-a"}),
        )
        .unwrap()
    }
    fn profile() -> Value {
        json!({"id":"compliance-a", "organization_id":"org-a", "status":"ACTIVE", "credential_format":"SD_JWT_VC", "issuance_protocol":"OID4VCI_PRE_AUTH", "discoverable":true})
    }
    fn binding() -> Value {
        json!({"ok":true,"organization_id":"org-a", "issuer_did":"did:example:a", "key_purpose":"vc_jwt_issuer", "algorithm":"ES256",
            "public_jwk":{"kty":"EC"}, "issuer_profile":{"organization_id":"org-a", "issuer_did":"did:example:a", "key_purpose":"vc_jwt_issuer", "algorithm":"ES256", "status":"active", "credential_format":"SD_JWT_VC"}})
    }
    #[test]
    fn contexts_are_derived_from_authorized_active_profiles_and_keep_multiple_formats() {
        let mut request = request();
        request.supported_formats = Some(vec!["sd_jwt_vc".into(), "mso_mdoc".into()]);
        let context = TemplateIssuerContext::from_profile(&request, &profile()).unwrap();
        assert_eq!(
            context.describe()["supported_formats"],
            json!(["SD_JWT_VC", "MDOC"])
        );
        assert_eq!(context.describe()["requirements"]["doctype"], true);
        for (field, value, status) in [
            ("organization_id", json!("org-b"), 403),
            ("status", json!("SUSPENDED"), 422),
            ("discoverable", json!(false), 422),
            ("credential_format", json!("invalid"), 502),
            ("id", json!("another"), 502),
        ] {
            let mut invalid = profile();
            invalid[field] = value;
            assert_eq!(
                TemplateIssuerContext::from_profile(&request, &invalid)
                    .unwrap_err()
                    .0,
                status
            );
        }
        let mut system = profile();
        system["organization_id"] = Value::Null;
        system["is_system"] = json!(true);
        assert!(TemplateIssuerContext::from_profile(&request, &system).is_ok());
        system["is_system"] = json!(false);
        assert_eq!(
            TemplateIssuerContext::from_profile(&request, &system)
                .unwrap_err()
                .0,
            403
        );
        system["is_system"] = json!(true);
        system["organization_id"] = json!(17);
        assert_eq!(
            TemplateIssuerContext::from_profile(&request, &system)
                .unwrap_err()
                .0,
            403
        );
    }
    #[test]
    fn private_selectors_and_unsupported_or_mismatched_contracts_fail_closed() {
        assert!(serde_json::from_value::<OptionsRequest>(json!({"organization_id":"org-a", "compliance_profile_id":"compliance-a", "issuer_profile_id":"private"})).is_err());
        let mut request = request();
        request.credential_payload_format = Some("MDOC".into());
        assert_eq!(
            TemplateIssuerContext::from_profile(&request, &profile())
                .unwrap_err()
                .0,
            422
        );
        let mut profile = profile();
        profile["issuance_protocol"] = json!("DIRECT");
        assert_eq!(
            TemplateIssuerContext::from_profile(&super::tests::request(), &profile)
                .unwrap_err()
                .0,
            422
        );
    }
    #[test]
    fn writes_enforce_the_same_contract_and_public_binding_constraints() {
        let context = TemplateIssuerContext::from_profile(&request(), &profile()).unwrap();
        assert!(context
            .validate_template(&json!({"vct":"https://issuer.example/credentials/a"}))
            .is_ok());
        assert!(context.validate_template(&json!({"vct":""})).is_err());
        assert!(context
            .validate_template(
                &json!({"vct":"urn:example:a", "issuance_protocol":"PHYSICAL_DOCUMENT"})
            )
            .is_err());
        let valid = binding();
        assert_eq!(
            context
                .binding("did:example:a", CredentialFormat::SdJwtVc, &valid)
                .unwrap()["algorithm"],
            "ES256"
        );
        for pointer in [
            "/organization_id",
            "/issuer_did",
            "/key_purpose",
            "/algorithm",
            "/issuer_profile/organization_id",
            "/issuer_profile/credential_format",
            "/issuer_profile/status",
        ] {
            let mut invalid = valid.clone();
            *invalid.pointer_mut(pointer).unwrap() = json!("wrong");
            assert!(
                context
                    .binding("did:example:a", CredentialFormat::SdJwtVc, &invalid)
                    .is_err(),
                "{pointer}"
            );
        }
        let mut invalid = valid;
        invalid["public_jwk"]["d"] = json!("private");
        assert!(context
            .binding("did:example:a", CredentialFormat::SdJwtVc, &invalid)
            .is_err());
    }
}
