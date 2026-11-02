//! Read-only ordering decision for a retained public generation after cold
//! recovery. This is neither activation authority nor a maintenance result.
use super::*;
use crate::installer_public_ingress::PublicIngressMetadata;

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StartupDependency {
    NonPublicSource,
    PendingActivation,
    CredentialRefreshDue,
    CertificateExpired,
    CertificateNotYetValid,
}

#[derive(Debug, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub(crate) enum CurrentGenerationUsability {
    UsablePublic {
        selected_sequence: u64,
        generation_sha256: String,
        configuration_sha256: String,
        observed_at: u64,
        credential_fresh_until: u64,
        certificate_not_after: u64,
    },
    MaintenanceRequired {
        reason: StartupDependency,
        observed_at: u64,
    },
}

impl CurrentGenerationUsability {
    pub(crate) fn can_start_before_maintenance(&self) -> bool {
        matches!(self, Self::UsablePublic { .. })
    }
}

enum PublicMaterial {
    Usable {
        credential_fresh_until: u64,
        certificate_not_after: u64,
    },
    Unavailable(StartupDependency),
}

fn public_material_at(
    metadata: &PublicIngressMetadata,
    fullchain: &[u8],
    at: u64,
) -> Result<PublicMaterial> {
    // Verify the immutable chain and admission first. An expired or not-yet-
    // valid leaf is ordinary maintenance only after its retained evidence is
    // authenticated; malformed chains, changed keys and signatures remain
    // integrity errors, independently of the clock.
    let historical_at = metadata.certificate_admission["observed_at"]
        .as_u64()
        .filter(|value| *value > 0)
        .ok_or(REFUSED)?;
    let historical = metadata.validate_selected_at(fullchain, historical_at)?;
    let not_before = historical.metadata()["not_before"]
        .as_u64()
        .ok_or(REFUSED)?;
    let not_after = historical.metadata()["not_after"].as_u64().ok_or(REFUSED)?;
    let (credential_fresh_until, due) =
        schedule::credential_due(metadata.token_observed_at, metadata.token_ttl_seconds, at)?;
    if at < not_before {
        return Ok(PublicMaterial::Unavailable(
            StartupDependency::CertificateNotYetValid,
        ));
    }
    if at >= not_after {
        return Ok(PublicMaterial::Unavailable(
            StartupDependency::CertificateExpired,
        ));
    }
    // The selected-chain validator uses zero remaining-lifetime margin and
    // still verifies the complete production chain, exact SANs and retained
    // SPKI. New-candidate admission keeps its independent one-hour margin.
    metadata.validate_selected_at(fullchain, at)?;
    if due {
        return Ok(PublicMaterial::Unavailable(
            StartupDependency::CredentialRefreshDue,
        ));
    }
    Ok(PublicMaterial::Usable {
        credential_fresh_until,
        certificate_not_after: not_after,
    })
}

/// Authenticate the current immutable selection without Docker, CA access,
/// credential refresh or repair. The caller must first reconcile any pending
/// activation and local OpenBao recovery under the same installation lock.
/// An ACME order or provider outage does not make fresh selected material
/// unusable, so this reader intentionally does not inspect the ACME schedule.
pub(crate) fn current_startup_usability(
    view: &LockedInspection,
    installation: &Path,
) -> Result<CurrentGenerationUsability> {
    view.require_path_binding(installation)?;
    let initial = installer_doctor::load_initial_session(view, installation)?;
    require_lineage(view, installation, &initial.configuration_sha256)?;
    let binding = generation::load_verified(
        installation,
        &view.journal().installation_id().to_string(),
        &view.journal().runtime().ok_or(REFUSED)?.engine_id,
    )?
    .ok_or(REFUSED)?;
    let saved = installer_doctor::load_session(view, installation)?;
    generation::verify_model(
        installation,
        &binding,
        &saved.model,
        binding.network_id.as_deref(),
    )?;
    let pending = tx::has_pending_activation(view, installation, &binding)?;
    let material = if pending {
        None
    } else {
        binding
            .public_ingress_metadata(installation)?
            .map(|metadata| {
                binding
                    .read(installation, "installer_ingress_tls_cert")
                    .map(|chain| (metadata, chain))
            })
            .transpose()?
    };
    // Obtain the one validity observation after potentially long lineage
    // reads, so their duration cannot make an old clock authorize startup.
    let at = now()?;
    let result = if pending {
        CurrentGenerationUsability::MaintenanceRequired {
            reason: StartupDependency::PendingActivation,
            observed_at: at,
        }
    } else if let Some((metadata, fullchain)) = material {
        match public_material_at(&metadata, &fullchain, at)? {
            PublicMaterial::Usable {
                credential_fresh_until,
                certificate_not_after,
            } => CurrentGenerationUsability::UsablePublic {
                selected_sequence: binding.sequence(),
                generation_sha256: binding.sha256()?,
                configuration_sha256: saved.configuration_sha256,
                observed_at: at,
                credential_fresh_until,
                certificate_not_after,
            },
            PublicMaterial::Unavailable(reason) => {
                CurrentGenerationUsability::MaintenanceRequired {
                    reason,
                    observed_at: at,
                }
            }
        }
    } else {
        CurrentGenerationUsability::MaintenanceRequired {
            reason: StartupDependency::NonPublicSource,
            observed_at: at,
        }
    };
    view.require_path_binding(installation)?;
    view.require_unchanged()?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::installer_public_ingress::tests as fixture;
    use spki::der::{asn1::BitString, DecodePem, EncodePem};
    use x509_cert::Certificate;

    fn material() -> (PublicIngressMetadata, Vec<u8>) {
        let plan = fixture::plan();
        (
            fixture::metadata(&plan, true),
            plan.fullchain_pem().as_bytes().to_vec(),
        )
    }

    #[test]
    fn selected_startup_uses_the_exact_conservative_credential_deadline() {
        let (metadata, chain) = material();
        let deadline = metadata.token_observed_at + 1800;
        assert!(matches!(
            public_material_at(&metadata, &chain, deadline - 1).unwrap(),
            PublicMaterial::Usable { credential_fresh_until, .. } if credential_fresh_until == deadline
        ));
        for at in [deadline, deadline + 1] {
            assert!(matches!(
                public_material_at(&metadata, &chain, at).unwrap(),
                PublicMaterial::Unavailable(StartupDependency::CredentialRefreshDue)
            ));
        }
    }

    #[test]
    fn selected_chain_has_zero_admission_margin_but_stops_at_its_actual_expiry() {
        let (mut metadata, chain) = material();
        let expiry = metadata.certificate_admission["not_after"]
            .as_u64()
            .unwrap();
        metadata.token_observed_at = expiry - 1;
        assert!(matches!(
            public_material_at(&metadata, &chain, expiry - 1).unwrap(),
            PublicMaterial::Usable { certificate_not_after, .. } if certificate_not_after == expiry
        ));
        assert!(matches!(
            public_material_at(&metadata, &chain, expiry).unwrap(),
            PublicMaterial::Unavailable(StartupDependency::CertificateExpired)
        ));
        let before = metadata.certificate_admission["not_before"]
            .as_u64()
            .unwrap();
        metadata.token_observed_at = before - 1;
        assert!(matches!(
            public_material_at(&metadata, &chain, before - 1).unwrap(),
            PublicMaterial::Unavailable(StartupDependency::CertificateNotYetValid)
        ));
    }

    #[test]
    fn unusable_clock_or_chain_is_not_reclassified_as_ordinary_maintenance() {
        let (metadata, chain) = material();
        let at = metadata.token_observed_at;
        for change in [0, 3599] {
            let mut altered = metadata.clone();
            altered.token_ttl_seconds = change;
            assert!(public_material_at(&altered, &chain, at).is_err());
        }
        let mut altered = metadata.clone();
        altered.token_observed_at = at + 121;
        assert!(public_material_at(&altered, &chain, at).is_err());
        let mut altered = metadata.clone();
        altered.dns_names = vec!["another.example".into()];
        assert!(public_material_at(&altered, &chain, at).is_err());
        let mut altered = metadata.clone();
        altered.certificate_admission["trust_class"] = json!("staging_test");
        assert!(public_material_at(&altered, &chain, at).is_err());
        let expiry = metadata.certificate_admission["not_after"]
            .as_u64()
            .unwrap();
        assert!(public_material_at(&metadata, b"invalid expired chain", expiry).is_err());
        let text = std::str::from_utf8(&chain).unwrap();
        let end =
            text.find("-----END CERTIFICATE-----").unwrap() + "-----END CERTIFICATE-----".len();
        let mut leaf = Certificate::from_pem(&chain[..end]).unwrap();
        let mut signature = leaf.signature.as_bytes().unwrap().to_vec();
        signature[0] ^= 1;
        leaf.signature = BitString::from_bytes(&signature).unwrap();
        let altered_chain = format!(
            "{}{}",
            leaf.to_pem(spki::der::pem::LineEnding::LF).unwrap(),
            text[end..].trim_start()
        );
        assert!(public_material_at(&metadata, altered_chain.as_bytes(), expiry).is_err());
    }

    #[test]
    fn only_the_typed_usable_variant_reorders_startup() {
        for reason in [
            StartupDependency::NonPublicSource,
            StartupDependency::PendingActivation,
            StartupDependency::CredentialRefreshDue,
            StartupDependency::CertificateExpired,
            StartupDependency::CertificateNotYetValid,
        ] {
            assert!(!CurrentGenerationUsability::MaintenanceRequired {
                reason,
                observed_at: 1,
            }
            .can_start_before_maintenance());
        }
        assert!(CurrentGenerationUsability::UsablePublic {
            selected_sequence: 0,
            generation_sha256: "a".repeat(64),
            configuration_sha256: "b".repeat(64),
            observed_at: 1,
            credential_fresh_until: 1801,
            certificate_not_after: 3601,
        }
        .can_start_before_maintenance());
    }
}
