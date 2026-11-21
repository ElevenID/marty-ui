use chrono::DateTime;

use crate::{
    model, thumbprint, BindingError, BindingRecord, ErrorKind, HashBasis, PrincipalType,
    RuntimeKind, ThumbprintEncoding, TrustedBindingInputs, TypedThumbprint,
    ValidatedPrincipalBinding, CONFIGURATION_PROFILE, PROFILE,
};

fn shape(condition: bool, field: &'static str) -> Result<(), BindingError> {
    if condition {
        Ok(())
    } else {
        Err(BindingError::new(ErrorKind::SchemaInvalid, field))
    }
}

fn length(value: &str, minimum: usize, maximum: usize) -> bool {
    (minimum..=maximum).contains(&value.chars().count())
}

pub(crate) fn uuid(value: &str, field: &'static str) -> Result<(), BindingError> {
    shape(
        value.len() == 36
            && [8, 13, 18, 23]
                .iter()
                .all(|index| value.as_bytes()[*index] == b'-')
            && uuid::Uuid::parse_str(value).is_ok(),
        field,
    )
}

pub(crate) fn uri(
    value: &str,
    maximum: usize,
    no_wildcard: bool,
    field: &'static str,
) -> Result<(), BindingError> {
    // URL parsing is only a shape check. Never compare its normalized output,
    // dereference a URI, or infer permission from a path or trust-domain prefix.
    let bytes = value.as_bytes();
    let mut index = 0;
    let mut lexical = !bytes.is_empty();
    while lexical && index < bytes.len() {
        let byte = bytes[index];
        lexical = byte.is_ascii_alphanumeric() || b"-._~:/?#[]@!$&'()*+,;=%".contains(&byte);
        if byte == b'%' {
            lexical &= index + 2 < bytes.len()
                && bytes[index + 1].is_ascii_hexdigit()
                && bytes[index + 2].is_ascii_hexdigit();
            index += 2;
        }
        index += 1;
    }
    shape(
        lexical
            && length(value, 1, maximum)
            && (!no_wildcard || !value.contains('*'))
            && url::Url::parse(value).is_ok(),
        field,
    )
}

fn profile_uri(value: &str, field: &'static str) -> Result<(), BindingError> {
    uri(value, 1024, true, field)
}

fn principal(principal: &model::Principal, field: &'static str) -> Result<(), BindingError> {
    profile_uri(&principal.id, field)
}

pub(crate) fn session_shape(
    session: &model::Session,
    field: &'static str,
) -> Result<(), BindingError> {
    profile_uri(&session.represented_subject.id, field)?;
    principal(&session.principal, field)?;
    profile_uri(&session.runtime_instance_ref, field)?;
    profile_uri(&session.session_ref, field)?;
    profile_uri(&session.establishment_evidence_ref, field)?;
    TypedThumbprint::from_document(&session.key_thumbprint)?;
    Ok(())
}

pub(crate) fn record_shape(record: &model::Record) -> Result<(), BindingError> {
    shape(record.profile == PROFILE, "record.profile")?;
    uuid(&record.organization_id, "record.organization_id")?;
    principal(&record.principal, "record.principal")?;
    profile_uri(
        &record.authentication.issuer,
        "record.authentication.issuer",
    )?;
    shape(
        length(&record.authentication.subject, 1, 512),
        "record.authentication.subject",
    )?;
    profile_uri(
        &record.authentication.audience,
        "record.authentication.audience",
    )?;
    TypedThumbprint::from_document(&record.authentication.key_thumbprint)?;
    profile_uri(&record.runtime.instance_ref, "record.runtime.instance_ref")?;
    match (record.runtime.kind, &record.runtime.machine_identity_id) {
        (RuntimeKind::Managed, Some(id)) => uuid(id, "record.runtime.machine_identity_id")?,
        (RuntimeKind::External, None) => {}
        _ => {
            return Err(BindingError::new(
                ErrorKind::SchemaInvalid,
                "record.runtime",
            ))
        }
    }
    shape(
        record.principal.kind != PrincipalType::MachineIdentity
            || record.runtime.kind == RuntimeKind::Managed,
        "record.runtime",
    )?;
    if let Some(session) = &record.session_binding {
        session_shape(session, "record.session_binding")?;
    }
    for value in [&record.agent_definition_ref, &record.run_ref]
        .into_iter()
        .flatten()
    {
        profile_uri(value, "record.correlation")?;
    }
    Ok(())
}

pub(crate) fn configuration_shape(
    configuration: &model::Configuration,
) -> Result<(), BindingError> {
    shape(
        configuration.profile == CONFIGURATION_PROFILE,
        "configuration.profile",
    )?;
    uuid(
        &configuration.organization_id,
        "configuration.organization_id",
    )?;
    uuid(
        &configuration.deployment_profile_id,
        "configuration.deployment_profile_id",
    )?;
    principal(&configuration.principal, "configuration.principal")?;
    profile_uri(
        &configuration.authentication_source.issuer,
        "configuration.authentication_source",
    )?;
    shape(
        length(&configuration.authentication_source.subject, 1, 512),
        "configuration.authentication_source",
    )?;
    shape(
        (1..=16).contains(&configuration.allowed_audiences.len())
            && unique(&configuration.allowed_audiences),
        "configuration.allowed_audiences",
    )?;
    for audience in &configuration.allowed_audiences {
        profile_uri(audience, "configuration.allowed_audiences")?;
    }
    TypedThumbprint::from_document(&configuration.expected_key_thumbprint)?;
    let runtime = &configuration.runtime;
    profile_uri(&runtime.instance_ref, "configuration.runtime.instance_ref")?;
    match runtime.kind {
        RuntimeKind::Managed => {
            let Some(id) = &runtime.machine_identity_id else {
                return Err(BindingError::new(
                    ErrorKind::SchemaInvalid,
                    "configuration.runtime",
                ));
            };
            uuid(id, "configuration.runtime.machine_identity_id")?;
            shape(
                runtime
                    .active_key_id
                    .as_deref()
                    .is_some_and(|value| length(value, 1, 512)),
                "configuration.runtime.active_key_id",
            )?;
            shape(
                matches!(
                    runtime.stored_thumbprint_encoding,
                    Some(ThumbprintEncoding::MipSha256Hex | ThumbprintEncoding::MipSha256Base64url)
                ),
                "configuration.runtime.stored_thumbprint_encoding",
            )?;
        }
        RuntimeKind::External => shape(
            runtime.machine_identity_id.is_none()
                && runtime.active_key_id.is_none()
                && runtime.stored_thumbprint_encoding.is_none(),
            "configuration.runtime",
        )?,
    }
    shape(
        configuration.principal.kind != PrincipalType::MachineIdentity
            || runtime.kind == RuntimeKind::Managed,
        "configuration.runtime",
    )?;
    Ok(())
}

fn unique<T: PartialEq>(values: &[T]) -> bool {
    values
        .iter()
        .enumerate()
        .all(|(index, value)| !values[..index].contains(value))
}

fn datetime(value: &str) -> bool {
    DateTime::parse_from_rfc3339(value).is_ok()
}

pub(crate) fn machine_shape(machine: &model::Machine) -> Result<(), BindingError> {
    const FIELD: &str = "machine_identity";
    uuid(&machine.id, FIELD)?;
    uuid(&machine.organization_id, FIELD)?;
    shape(
        length(&machine.machine_id, 1, 512) && length(&machine.display_name, 1, 256),
        FIELD,
    )?;
    shape(
        machine
            .description
            .as_ref()
            .is_none_or(|value| length(value, 0, 1024)),
        FIELD,
    )?;
    shape(
        matches!(
            machine.machine_type.as_str(),
            "SECURE_DOCUMENT_PRINTER"
                | "DOCUMENT_PERSONALIZATION_SYSTEM"
                | "VERIFICATION_APPLIANCE"
                | "WALLET_SECURE_ELEMENT"
                | "HSM_WORKLOAD"
                | "SECURE_PROCESSING_RUNTIME"
                | "OTHER"
        ),
        FIELD,
    )?;
    shape(
        matches!(
            machine.status.as_str(),
            "PROVISIONED" | "ACTIVE" | "SUSPENDED" | "REVOKED" | "RETIRED"
        ),
        FIELD,
    )?;
    shape(
        !machine.identity_keys.is_empty() && unique(&machine.identity_keys),
        FIELD,
    )?;
    for key in &machine.identity_keys {
        shape(length(&key.key_id, 1, 512), FIELD)?;
        let encoded = key.thumbprint.strip_prefix("sha256:");
        shape(
            encoded.is_some_and(|value| {
                value.len() >= 32
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            }),
            FIELD,
        )?;
        shape(
            matches!(
                key.algorithm.as_str(),
                "RS256"
                    | "RS384"
                    | "RS512"
                    | "ES256"
                    | "ES384"
                    | "ES512"
                    | "PS256"
                    | "PS384"
                    | "PS512"
                    | "EdDSA"
                    | "Ed25519"
                    | "Ed448"
            ),
            FIELD,
        )?;
        shape(
            matches!(
                key.status.as_str(),
                "ACTIVE" | "ROTATING" | "REVOKED" | "EXPIRED"
            ),
            FIELD,
        )?;
        shape(
            key.public_key_jwk.is_some() || key.certificate_chain_ref.is_some(),
            FIELD,
        )?;
        if let Some(jwk) = &key.public_key_jwk {
            shape(!jwk.is_empty(), FIELD)?;
        }
        if let Some(reference) = &key.certificate_chain_ref {
            uri(reference, usize::MAX, false, FIELD)?;
        }
        for value in [&key.valid_from, &key.valid_until].into_iter().flatten() {
            shape(datetime(value), FIELD)?;
        }
    }
    // The pinned core schema requires exactly one ACTIVE key on ACTIVE machines.
    if machine.status == "ACTIVE" {
        shape(
            machine
                .identity_keys
                .iter()
                .filter(|key| key.status == "ACTIVE")
                .count()
                == 1,
            FIELD,
        )?;
    }
    if let Some(assignments) = &machine.assignments {
        for id in [
            &assignments.deployment_profile_id,
            &assignments.operator_organization_id,
        ]
        .into_iter()
        .flatten()
        {
            uuid(id, FIELD)?;
        }
        shape(
            assignments
                .site_id
                .as_ref()
                .is_none_or(|value| length(value, 0, 256)),
            FIELD,
        )?;
    }
    if let Some(ids) = &machine.credential_ids {
        shape(
            unique(ids) && ids.iter().all(|value| length(value, 1, 512)),
            FIELD,
        )?;
    }
    if let Some(identity) = &machine.attestation_identity {
        if let Some(ids) = &identity.attestation_key_ids {
            shape(
                unique(ids) && ids.iter().all(|value| length(value, 1, 512)),
                FIELD,
            )?;
        }
        if let Some(formats) = &identity.evidence_formats {
            shape(
                unique(formats)
                    && formats.iter().all(|value| {
                        matches!(
                            value.as_str(),
                            "EAT" | "TPM_QUOTE" | "PLATFORM_ATTESTATION" | "CUSTOM"
                        )
                    }),
                FIELD,
            )?;
        }
        if let Some(references) = &identity.endorsement_refs {
            shape(unique(references), FIELD)?;
            for reference in references {
                uri(reference, usize::MAX, false, FIELD)?;
            }
        }
    }
    shape(datetime(&machine.created_at), FIELD)?;
    for value in [
        &machine.updated_at,
        &machine.suspended_at,
        &machine.revoked_at,
        &machine.retired_at,
    ]
    .into_iter()
    .flatten()
    {
        shape(datetime(value), FIELD)?;
    }
    shape(
        machine
            .status_reason
            .as_ref()
            .is_none_or(|value| length(value, 0, 512)),
        FIELD,
    )
}

/// Check the pinned profile against independent authoritative inputs.
///
/// The inputs' names are not proof of their trust. Callers must authenticate
/// source evidence, obtain current state under the already authorized tenant,
/// enforce freshness, and separately authorize the intended operation.
pub fn validate_binding(
    record: &BindingRecord,
    inputs: TrustedBindingInputs<'_>,
) -> Result<ValidatedPrincipalBinding, BindingError> {
    let record = &record.0;
    let configuration = &inputs.configuration.0;
    let fail = BindingError::new;
    if inputs.organization_id != configuration.organization_id
        || record.organization_id != configuration.organization_id
    {
        return Err(fail(ErrorKind::TenantMismatch, "record.organization_id"));
    }
    if record.principal != configuration.principal {
        return Err(fail(ErrorKind::PrincipalMismatch, "record.principal"));
    }
    let authentication = &record.authentication;
    if authentication.issuer != configuration.authentication_source.issuer
        || authentication.subject != configuration.authentication_source.subject
    {
        return Err(fail(
            ErrorKind::SourceIdentityMismatch,
            "record.authentication",
        ));
    }
    if !configuration
        .allowed_audiences
        .contains(&authentication.audience)
    {
        return Err(fail(
            ErrorKind::AudienceMismatch,
            "record.authentication.audience",
        ));
    }
    if authentication.key_algorithm != configuration.expected_key_algorithm {
        return Err(fail(
            ErrorKind::SelectedAlgorithmMismatch,
            "record.authentication.key_algorithm",
        ));
    }
    let runtime = &record.runtime;
    let expected_runtime = &configuration.runtime;
    if runtime.kind != expected_runtime.kind
        || runtime.instance_ref != expected_runtime.instance_ref
        || runtime.machine_identity_id != expected_runtime.machine_identity_id
    {
        return Err(fail(ErrorKind::RuntimeMismatch, "record.runtime"));
    }
    let key = TypedThumbprint::from_document(&authentication.key_thumbprint)?;
    let expected_key = TypedThumbprint::from_document(&configuration.expected_key_thumbprint)?;
    if !key.same_binding(&expected_key) {
        return Err(fail(
            ErrorKind::KeyBindingMismatch,
            "record.authentication.key_thumbprint",
        ));
    }
    match (runtime.kind, inputs.machine) {
        (RuntimeKind::Managed, None) => {
            return Err(fail(ErrorKind::MissingMachineState, "machine_identity"))
        }
        (RuntimeKind::External, Some(_)) => {
            return Err(fail(
                ErrorKind::ExternalMachineEnrollment,
                "machine_identity",
            ))
        }
        (RuntimeKind::External, None) => {}
        (RuntimeKind::Managed, Some(snapshot)) => {
            let machine = &snapshot.0;
            if machine.organization_id != configuration.organization_id
                || Some(&machine.id) != runtime.machine_identity_id.as_ref()
            {
                return Err(fail(ErrorKind::MachineIdentityMismatch, "machine_identity"));
            }
            if machine
                .assignments
                .as_ref()
                .and_then(|assignments| assignments.deployment_profile_id.as_ref())
                .is_some_and(|id| id != &configuration.deployment_profile_id)
            {
                return Err(fail(
                    ErrorKind::DeploymentAssignmentMismatch,
                    "machine_identity.assignments.deployment_profile_id",
                ));
            }
            if record.principal.kind == PrincipalType::MachineIdentity
                && record.principal.id != machine.machine_id
            {
                return Err(fail(
                    ErrorKind::MachinePrincipalMismatch,
                    "record.principal",
                ));
            }
            let active: Vec<_> = machine
                .identity_keys
                .iter()
                .filter(|key| key.status == "ACTIVE")
                .collect();
            if machine.status != "ACTIVE" || active.len() != 1 {
                return Err(fail(ErrorKind::InactiveMachine, "machine_identity"));
            }
            let active = active[0];
            if Some(&active.key_id) != expected_runtime.active_key_id.as_ref() {
                return Err(fail(
                    ErrorKind::ActiveKeyMismatch,
                    "machine_identity.identity_keys",
                ));
            }
            if !authentication
                .key_algorithm
                .compatible_with(&active.algorithm)
            {
                return Err(fail(
                    ErrorKind::ActiveKeyAlgorithmMismatch,
                    "machine_identity.identity_keys",
                ));
            }
            let registered = TypedThumbprint::from_document(&model::Thumbprint {
                basis: configuration.expected_key_thumbprint.basis,
                encoding: expected_runtime
                    .stored_thumbprint_encoding
                    .expect("validated managed configuration"),
                value: active.thumbprint.clone(),
            })?;
            if !registered.same_binding(&expected_key) {
                return Err(fail(
                    ErrorKind::RegisteredKeyMismatch,
                    "machine_identity.identity_keys",
                ));
            }
            if let Some(jwk) = &active.public_key_jwk {
                // Always check public-only key material, including certificate basis.
                let (material_algorithm, public_key) = thumbprint::public_jwk(jwk)?;
                if !material_algorithm.compatible_with(&active.algorithm) {
                    return Err(fail(
                        ErrorKind::ActiveKeyAlgorithmMismatch,
                        "machine_identity.identity_keys",
                    ));
                }
                if registered.basis() == HashBasis::JwkRfc7638Sha256
                    && !public_key.same_binding(&registered)
                {
                    return Err(fail(
                        ErrorKind::RegisteredKeyMismatch,
                        "machine_identity.identity_keys",
                    ));
                }
            }
        }
    }
    let session = record.session_binding.as_ref();
    let expected_session = inputs.session.map(|evidence| &evidence.0);
    if configuration.shared_runtime && (session.is_none() || expected_session.is_none()) {
        return Err(fail(
            ErrorKind::MissingSubjectSession,
            "record.session_binding",
        ));
    }
    match (session, expected_session) {
        (None, None) => {}
        (Some(actual), Some(expected)) if actual == expected => {
            let session_key = TypedThumbprint::from_document(&actual.key_thumbprint)?;
            if actual.principal != record.principal
                || actual.runtime_instance_ref != runtime.instance_ref
                || !session_key.same_binding(&key)
            {
                return Err(fail(
                    ErrorKind::SessionRuntimeMismatch,
                    "record.session_binding",
                ));
            }
        }
        _ => {
            return Err(fail(
                ErrorKind::SessionBindingMismatch,
                "record.session_binding",
            ))
        }
    }
    Ok(ValidatedPrincipalBinding {
        record: record.clone(),
        key,
        deployment_profile_id: configuration.deployment_profile_id.clone(),
    })
}
