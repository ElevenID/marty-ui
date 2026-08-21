use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};

use crate::{AuthenticatedUser, PortError, UserType};

pub fn build_canvas_lti_user(session: &Value) -> Result<AuthenticatedUser, PortError> {
    let session = session.as_object().ok_or_else(|| {
        PortError::new(
            "canvas_lti_session_invalid",
            "Canvas LTI session must be an object",
        )
    })?;
    let verified = object(session.get("verified_launch"));
    let learner = object(verified.and_then(|value| value.get("learner_identity")));
    let raw_claims = object(verified.and_then(|value| value.get("raw_claims")));
    let lis_claims = raw_claims
        .and_then(|claims| {
            claims
                .get("https://purl.imsglobal.org/spec/lti/claim/lis")
                .or_else(|| claims.get("lis"))
        })
        .and_then(Value::as_object);

    let issuer = first_nonempty([
        value(verified, "issuer"),
        value(raw_claims, "iss"),
        session.get("canvas_account_id"),
        Some(&Value::String("canvas".into())),
    ])
    .unwrap_or_else(|| "canvas".into());
    let subject = first_nonempty([
        value(verified, "subject"),
        value(learner, "subject"),
        value(raw_claims, "sub"),
        value(learner, "id"),
        session.get("learner_key"),
    ])
    .ok_or_else(|| {
        PortError::new(
            "canvas_lti_subject_required",
            "Canvas LTI session is missing a learner subject",
        )
    })?;
    let digest = hex_digest(format!("{issuer}|{subject}").as_bytes());
    let email = first_nonempty([
        value(learner, "email"),
        value(raw_claims, "email"),
        value(raw_claims, "lis_person_contact_email_primary"),
        value(lis_claims, "person_contact_email_primary"),
    ])
    .unwrap_or_else(|| format!("canvas-{}@canvas.lti.local", &digest[..16]));
    let display_name = first_nonempty([
        value(learner, "name"),
        value(raw_claims, "name"),
        value(raw_claims, "lis_person_name_full"),
        value(lis_claims, "person_name_full"),
        session.get("learner_display_name"),
    ]);
    let (inferred_given, inferred_family) = split_name(display_name.as_deref());
    let given_name = first_nonempty([
        value(learner, "given_name"),
        value(raw_claims, "given_name"),
        value(raw_claims, "lis_person_name_given"),
        value(lis_claims, "person_name_given"),
    ])
    .or(inferred_given);
    let family_name = first_nonempty([
        value(learner, "family_name"),
        value(raw_claims, "family_name"),
        value(raw_claims, "lis_person_name_family"),
        value(lis_claims, "person_name_family"),
    ])
    .or(inferred_family);
    let username = first_nonempty([
        value(learner, "preferred_username"),
        value(raw_claims, "preferred_username"),
        value(learner, "login_id"),
        value(raw_claims, "login_id"),
        value(raw_claims, "lis_person_sourcedid"),
        value(lis_claims, "person_sourcedid"),
    ])
    .or_else(|| email.split_once('@').map(|(local, _)| local.to_owned()))
    .or(display_name)
    .or_else(|| Some(subject.clone()));

    Ok(AuthenticatedUser {
        user_id: format!("canvas-lti-{}", &digest[..32]),
        email,
        username,
        given_name,
        family_name,
        user_type: UserType::Applicant,
        applicant_id: None,
        roles: vec!["applicant".into(), "canvas_lti_learner".into()],
        organization_id: first_nonempty([session.get("organization_id")]),
        organization_name: Some("Canvas learner organization".into()),
        organization: None,
        default_organization_id: None,
        default_organization_name: None,
        organizations: Vec::new(),
        organization_context_unavailable: false,
        organization_context_error: None,
        onboarding_completed: None,
        picture: None,
        impersonation: None,
        did_subject: None,
    })
}

fn object(value: Option<&Value>) -> Option<&Map<String, Value>> {
    value.and_then(Value::as_object)
}

fn value<'a>(object: Option<&'a Map<String, Value>>, key: &str) -> Option<&'a Value> {
    object.and_then(|object| object.get(key))
}

fn first_nonempty<'a>(values: impl IntoIterator<Item = Option<&'a Value>>) -> Option<String> {
    values
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::trim)
        .find(|value| !value.is_empty())
        .map(str::to_owned)
}

fn split_name(name: Option<&str>) -> (Option<String>, Option<String>) {
    let Some(name) = name.map(str::trim).filter(|name| !name.is_empty()) else {
        return (None, None);
    };
    let mut parts = name.split_whitespace();
    let given = parts.next().map(str::to_owned);
    let family = {
        let remainder = parts.collect::<Vec<_>>().join(" ");
        (!remainder.is_empty()).then_some(remainder)
    };
    (given, family)
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
