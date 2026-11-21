//! Public response shape for the selected organization/KEY approval profile.
//!
//! The producer remains responsible for immutable digest and authority checks.
//! This projection prevents malformed or retargeted terms reaching a human's
//! consent screen even when the returned grant reference itself is unchanged.

use chrono::{DateTime, Datelike, Duration, Utc};
use serde_json::{json, Value};
use std::collections::BTreeSet;

use super::{canonical_uuid, digest, fields, AdminRoute};

pub(super) fn timestamp(value: &Value) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value.as_str()?)
        .ok()
        .filter(|time| {
            (1..=9999).contains(&time.year()) && time.timestamp_subsec_nanos() < 1_000_000_000
        })
        .map(|time| time.with_timezone(&Utc))
}

pub(super) fn ordered_instants(start: &Value, end: &Value, maximum_seconds: i64) -> bool {
    let (Some(start), Some(end)) = (timestamp(start), timestamp(end)) else {
        return false;
    };
    end > start && end - start <= Duration::seconds(maximum_seconds)
}

fn uri(value: &Value) -> bool {
    value.as_str().is_some_and(|text| {
        !text.is_empty()
            && text.len() <= 1024
            && text.is_ascii()
            && !text
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
            && url::Url::parse(text).is_ok()
    })
}

fn principal(value: &Value) -> bool {
    value.as_object().is_some_and(|object| {
        fields(object, &["type", "id"], &[])
            && matches!(
                value["type"].as_str(),
                Some("USER" | "ORGANIZATION" | "SERVICE_ACCOUNT" | "MACHINE_IDENTITY" | "EXTERNAL")
            )
            && uri(&value["id"])
    })
}

fn scope(value: &Value) -> bool {
    value.as_array().is_some_and(|items| {
        let mut seen = BTreeSet::new();
        (1..=64).contains(&items.len())
            && items.iter().all(|item| {
                uri(item)
                    && item
                        .as_str()
                        .is_some_and(|item| !item.contains('*') && seen.insert(item))
            })
    })
}

fn constraints(value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    match value["mode"].as_str() {
        Some("EXACT_OPERATION") => {
            fields(object, &["mode", "request_profile", "request_digest"], &[])
                && uri(&value["request_profile"])
                && digest(&value["request_digest"])
        }
        Some("EXTERNAL_PROFILE") => {
            fields(
                object,
                &[
                    "mode",
                    "profile",
                    "document_ref",
                    "document_digest",
                    "evaluator",
                ],
                &[],
            ) && uri(&value["profile"])
                && uri(&value["document_ref"])
                && digest(&value["document_digest"])
                && principal(&value["evaluator"])
        }
        _ => false,
    }
}

pub(super) fn valid_review(route: &AdminRoute, user: Option<&str>, value: &Value) -> bool {
    let Some(user) = user.filter(|user| canonical_uuid(user).is_some()) else {
        return false;
    };
    let terms = &value["terms"];
    let Some(object) = terms.as_object() else {
        return false;
    };
    let organization = json!({"type":"ORGANIZATION", "id":format!("urn:marty:organization:{}", route.organization_id)});
    let (Some(valid_from), Some(valid_until), Some(created_at), Some(expires_at)) = (
        timestamp(&terms["valid_from"]),
        timestamp(&terms["valid_until"]),
        timestamp(&value["created_at"]),
        timestamp(&value["expires_at"]),
    ) else {
        return false;
    };
    fields(
        object,
        &[
            "grantor",
            "subject",
            "delegate",
            "binding",
            "actions",
            "audiences",
            "resources",
            "valid_from",
            "valid_until",
            "subdelegation_allowed",
            "constraints",
        ],
        &[],
    ) && terms["grantor"] == json!({"type":"USER", "id":format!("urn:marty:user:{user}")})
        && terms["subject"] == organization
        && value["issuer"] == organization
        && principal(&terms["delegate"])
        && terms["binding"].as_object().is_some_and(|binding| {
            fields(binding, &["method", "key_thumbprint"], &[])
                && terms["binding"]["method"] == "KEY"
                && digest(&terms["binding"]["key_thumbprint"])
        })
        && [&terms["actions"], &terms["audiences"], &terms["resources"]]
            .into_iter()
            .all(scope)
        && terms["subdelegation_allowed"] == false
        && constraints(&terms["constraints"])
        && valid_until > valid_from
        && expires_at > created_at
        && expires_at <= valid_until
        && expires_at - created_at <= Duration::seconds(300)
        && value["confirmation_max_age_seconds"]
            .as_u64()
            .is_some_and(|age| (1..=300).contains(&age))
}
