use mmf_security::constant_time_secret_eq;

use crate::transaction_reads::TransactionReadError;

#[derive(Clone)]
pub struct ManagementSecurity {
    api_key: Option<Box<str>>,
}

impl std::fmt::Debug for ManagementSecurity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ManagementSecurity")
            .field("api_key_configured", &self.api_key.is_some())
            .finish()
    }
}

impl ManagementSecurity {
    #[must_use]
    pub fn new(api_key: Option<&str>) -> Self {
        Self {
            api_key: api_key.map(Box::<str>::from),
        }
    }

    pub fn authorize(&self, presented: Option<&str>) -> Result<(), TransactionReadError> {
        let expected = self
            .api_key
            .as_deref()
            .ok_or(TransactionReadError::ApiKeyNotConfigured)?;
        let presented = presented
            .filter(|value| !value.is_empty())
            .ok_or(TransactionReadError::ApiKeyMissing)?;
        if !constant_time_secret_eq(expected.as_bytes(), presented.as_bytes()) {
            return Err(TransactionReadError::InvalidApiKey);
        }
        Ok(())
    }

    pub fn require_organization(
        &self,
        trusted: Option<&str>,
        expected: &str,
        hide_resource: bool,
    ) -> Result<(), TransactionReadError> {
        let trusted = trusted
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or(TransactionReadError::TrustedOrganizationRequired)?;
        if !constant_time_secret_eq(trusted.as_bytes(), expected.as_bytes()) {
            return Err(if hide_resource {
                TransactionReadError::ResourceNotFound
            } else {
                TransactionReadError::OrganizationMismatch
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::transaction_reads::TransactionReadError;

    use super::ManagementSecurity;

    #[test]
    fn management_auth_and_tenant_hiding_match_the_legacy_boundary() {
        let missing = ManagementSecurity::new(None);
        assert_eq!(
            missing.authorize(Some("candidate")),
            Err(TransactionReadError::ApiKeyNotConfigured)
        );

        let security = ManagementSecurity::new(Some("expected"));
        assert_eq!(
            security.authorize(None),
            Err(TransactionReadError::ApiKeyMissing)
        );
        assert_eq!(
            security.authorize(Some("")),
            Err(TransactionReadError::ApiKeyMissing)
        );
        assert_eq!(
            security.authorize(Some("wrong")),
            Err(TransactionReadError::InvalidApiKey)
        );
        assert_eq!(security.authorize(Some("expected")), Ok(()));
        assert_eq!(
            security.require_organization(None, "org-a", false),
            Err(TransactionReadError::TrustedOrganizationRequired)
        );
        assert_eq!(
            security.require_organization(Some("org-b"), "org-a", false),
            Err(TransactionReadError::OrganizationMismatch)
        );
        assert_eq!(
            security.require_organization(Some("org-b"), "org-a", true),
            Err(TransactionReadError::ResourceNotFound)
        );
        assert_eq!(
            security.require_organization(Some(" org-a "), "org-a", true),
            Ok(())
        );
    }
}
