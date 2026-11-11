//! Binds the complete frozen OID4VP query to native authenticated evidence.
//! Presentation Exchange field evaluation stays in the Core verifier.

use std::collections::BTreeSet;

use marty_oid4vci::verifier::{
    DescriptorMapEntry, InputDescriptor, PresentationDefinition, PresentationSubmission,
    VerificationEngine,
};
use marty_oid4vp_contract::{AssociatedResponseToken, Oid4vpEvaluationTransportV1, QueryKind};
use marty_verification::credential_format::DetectedCredentialFormat;
use serde_json::{json, Value};

use crate::CredentialVerificationEvidence;

pub(crate) fn matches_query(
    transport: &Oid4vpEvaluationTransportV1,
    selected: &AssociatedResponseToken,
    format: DetectedCredentialFormat,
    evidence: &CredentialVerificationEvidence,
) -> bool {
    if !evidence.verified || !matches_format(&selected.format, format) {
        return false;
    }
    match transport.query_kind {
        QueryKind::Dcql => matches_dcql(transport, selected, format, evidence),
        QueryKind::PresentationExchange => matches_pe(transport, selected, evidence),
    }
}

fn matches_format(requested: &str, actual: DetectedCredentialFormat) -> bool {
    match requested {
        "dc+sd-jwt" | "vc+sd-jwt" => actual == DetectedCredentialFormat::SdJwt,
        "mso_mdoc" => actual == DetectedCredentialFormat::Mdoc,
        "jwt_vc_json" | "jwt_vc" => matches!(
            actual,
            DetectedCredentialFormat::W3cVc | DetectedCredentialFormat::OpenbadgeV3
        ),
        "ldp_vc" => matches!(
            actual,
            DetectedCredentialFormat::W3cVcdmDi | DetectedCredentialFormat::OpenbadgeV3
        ),
        _ => false,
    }
}

fn known_fields(value: &Value, fields: &[&str]) -> bool {
    value
        .as_object()
        .is_some_and(|object| object.keys().all(|key| fields.contains(&key.as_str())))
}

fn matches_dcql(
    transport: &Oid4vpEvaluationTransportV1,
    selected: &AssociatedResponseToken,
    format: DetectedCredentialFormat,
    evidence: &CredentialVerificationEvidence,
) -> bool {
    // Unsupported credential_sets, claim_sets, values and extension semantics
    // cannot silently disappear while adapting this deliberately bounded profile.
    if !known_fields(&transport.query_document, &["credentials"])
        || !known_fields(&selected.query, &["id", "format", "meta", "claims"])
        || !matches_types(&selected.query["meta"], format, &evidence.credential_types)
    {
        return false;
    }
    let claims = match selected.query.get("claims") {
        None => &[][..],
        Some(Value::Array(values)) => values.as_slice(),
        _ => return false,
    };
    let mut ids = BTreeSet::new();
    for claim in claims {
        if !known_fields(claim, &["id", "path", "intent_to_retain"])
            || claim
                .get("intent_to_retain")
                .is_some_and(|value| !value.is_boolean())
        {
            return false;
        }
        if let Some(id) = claim.get("id") {
            let Some(id) = id.as_str().filter(|id| !id.is_empty()) else {
                return false;
            };
            if !ids.insert(id) {
                return false;
            }
        }
        let Some(path) = claim["path"]
            .as_array()
            .filter(|path| !path.is_empty() && path.len() <= 16)
        else {
            return false;
        };
        let Some(path) = path.iter().map(Value::as_str).collect::<Option<Vec<_>>>() else {
            return false;
        };
        if path.iter().any(|part| part.is_empty()) {
            return false;
        }
        let document = if format == DetectedCredentialFormat::Mdoc {
            evidence
                .claims
                .get("_mdoc")
                .and_then(|value| value.get("documents"))
                .and_then(Value::as_array)
                .filter(|documents| documents.len() == 1)
                .and_then(|documents| documents[0].get("namespaces"))
        } else {
            evidence.authenticated_document.as_ref()
        };
        let Some(mut value) = document else {
            return false;
        };
        for component in path {
            let Some(next) = value.as_object().and_then(|object| object.get(component)) else {
                return false;
            };
            value = next;
        }
        if value.is_null() {
            return false;
        }
    }
    true
}

fn matches_types(meta: &Value, format: DetectedCredentialFormat, authenticated: &[String]) -> bool {
    if meta.as_object().is_none_or(|object| object.len() != 1) {
        return false;
    }
    match format {
        DetectedCredentialFormat::SdJwt => meta["vct_values"]
            .as_array()
            .filter(|values| !values.is_empty())
            .is_some_and(|values| {
                values
                    .iter()
                    .all(|value| value.as_str().is_some_and(|value| !value.is_empty()))
                    && values.iter().any(|value| {
                        authenticated
                            .iter()
                            .any(|actual| Some(actual.as_str()) == value.as_str())
                    })
            }),
        DetectedCredentialFormat::Mdoc => meta["doctype_value"].as_str().is_some_and(|value| {
            !value.is_empty() && authenticated.iter().any(|actual| actual == value)
        }),
        DetectedCredentialFormat::W3cVc
        | DetectedCredentialFormat::W3cVcdmDi
        | DetectedCredentialFormat::OpenbadgeV3 => {
            let Some(sets) = meta["type_values"]
                .as_array()
                .filter(|sets| !sets.is_empty())
            else {
                return false;
            };
            if sets.iter().any(|set| {
                set.as_array().is_none_or(|types| {
                    types.is_empty()
                        || types
                            .iter()
                            .any(|value| value.as_str().is_none_or(str::is_empty))
                })
            }) {
                return false;
            }
            sets.iter().any(|set| {
                set.as_array()
                    .expect("validated type set")
                    .iter()
                    .all(|value| {
                        authenticated
                            .iter()
                            .any(|actual| Some(actual.as_str()) == value.as_str())
                    })
            })
        }
        DetectedCredentialFormat::Unknown => false,
    }
}

fn matches_pe(
    transport: &Oid4vpEvaluationTransportV1,
    selected: &AssociatedResponseToken,
    evidence: &CredentialVerificationEvidence,
) -> bool {
    if !known_fields(
        &transport.query_document,
        &["id", "name", "purpose", "format", "input_descriptors"],
    ) || !known_fields(
        &selected.query,
        &["id", "name", "purpose", "format", "constraints"],
    ) || !known_fields(
        &selected.query["constraints"],
        &["fields", "limit_disclosure"],
    ) {
        return false;
    }
    let Some(document) = evidence.authenticated_document.as_ref() else {
        return false;
    };
    let Some(options) = selected.query["format"].get(&selected.format) else {
        return false;
    };
    if !matches_algorithm_options(options, evidence)
        || transport
            .query_document
            .get("format")
            .is_some_and(|formats| {
                formats
                    .get(&selected.format)
                    .is_none_or(|options| !matches_algorithm_options(options, evidence))
            })
    {
        return false;
    }
    if selected.query["constraints"]
        .get("fields")
        .is_some_and(|fields| {
            fields.as_array().is_none_or(|fields| {
                fields.iter().any(|field| {
                    !known_fields(
                        field,
                        &[
                            "id",
                            "name",
                            "purpose",
                            "path",
                            "filter",
                            "optional",
                            "intent_to_retain",
                            "zk_predicate",
                        ],
                    )
                })
            })
        })
    {
        return false;
    }
    let Ok(mut descriptor) = serde_json::from_value::<InputDescriptor>(selected.query.clone())
    else {
        return false;
    };
    // Core's generic PE evaluator has no algorithm evidence parameter. Check
    // the authenticated algorithms above, then delegate all field constraints.
    if let Some(formats) = descriptor.format.as_mut() {
        if let Some(format) = formats.get_mut(&selected.format) {
            format.alg = None;
        }
    }
    let definition = PresentationDefinition {
        id: "bound-response-item".into(),
        name: None,
        purpose: None,
        input_descriptors: vec![descriptor],
    };
    let submission = PresentationSubmission {
        id: "bound-response-item".into(),
        definition_id: definition.id.clone(),
        descriptor_map: vec![DescriptorMapEntry {
            id: selected.query_id.clone(),
            format: selected.format.clone(),
            path: "$".into(),
            path_nested: None,
        }],
    };
    VerificationEngine::new(&transport.verifier_client_id, "")
        .verify_presentation(&definition, &submission, Some(document))
        .check_valid
}

fn matches_algorithm_options(options: &Value, evidence: &CredentialVerificationEvidence) -> bool {
    let Some(options) = options.as_object() else {
        return false;
    };
    options.iter().all(|(key, value)| {
        let algorithm = match key.as_str() {
            "alg" | "sd-jwt_alg_values" | "proof_type" => evidence.algorithm.as_deref(),
            "kb-jwt_alg_values" => evidence.holder_algorithm.as_deref(),
            _ => return false,
        };
        value
            .as_array()
            .filter(|values| !values.is_empty())
            .is_some_and(|values| {
                values.iter().all(Value::is_string)
                    && algorithm.is_some_and(|algorithm| {
                        values.iter().any(|value| value == &json!(algorithm))
                    })
            })
    })
}
