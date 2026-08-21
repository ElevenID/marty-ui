use std::collections::BTreeSet;

use serde_json::{Map, Value};

#[derive(Debug)]
pub struct PresentationPolicyContractError;

const POLICY_FIELDS: &[&str] = &[
    "organization_id",
    "name",
    "description",
    "purpose",
    "display_metadata",
    "required_claims",
    "accepted_credential_types",
    "trust_profile_id",
    "credential_requirements",
    "alternative_requirements",
    "compliance_profile_id",
    "prefer_predicates",
    "fallback_policy",
    "supported_circuits",
    "credential_ranking_strategy",
    "credential_ranking_weights",
    "holder_binding",
    "issuer_constraints",
    "freshness",
];
const RESPONSE_FIELDS: &[&str] = &[
    "id",
    "organization_id",
    "name",
    "status",
    "description",
    "purpose",
    "required_claims",
    "accepted_credential_types",
    "trust_profile_id",
    "display_metadata",
    "credential_requirements",
    "alternative_requirements",
    "compliance_profile_id",
    "holder_binding",
    "issuer_constraints",
    "freshness",
    "prefer_predicates",
    "fallback_policy",
    "supported_circuits",
    "credential_ranking_strategy",
    "credential_ranking_weights",
    "version",
    "created_at",
    "updated_at",
];

pub fn canonicalize_request(
    body: &[u8],
    update: bool,
    include_organization_id: bool,
) -> Result<Value, PresentationPolicyContractError> {
    let mut value = parse_object(body, POLICY_FIELDS)?;
    required_string(&value, "organization_id", 1, 255)?;
    if update {
        if value.contains_key("name") && !value["name"].is_null() {
            required_string(&value, "name", 1, 255)?;
        }
    } else {
        required_string(&value, "name", 1, 255)?;
    }
    validate_optional_string(&value, "description", 2000)?;
    validate_optional_string(&value, "purpose", 2000)?;
    validate_optional_string(&value, "trust_profile_id", 255)?;
    validate_optional_string(&value, "compliance_profile_id", 255)?;
    if let Some(display) = value.get_mut("display_metadata") {
        if !display.is_null() {
            *display = canonical_display(display.take(), false)?;
        }
    }
    if let Some(claims) = value.get_mut("required_claims") {
        if !claims.is_null() {
            canonical_required_claims(claims)?;
        }
    }
    validate_string_array(value.get("accepted_credential_types"), true)?;
    if let Some(requirements) = value.get_mut("credential_requirements") {
        if !requirements.is_null() {
            canonical_requirements(requirements)?;
        }
    }
    if let Some(alternatives) = value.get_mut("alternative_requirements") {
        if !alternatives.is_null() {
            canonical_alternatives(alternatives)?;
        }
    }
    let holder_required = if let Some(holder) = value.get_mut("holder_binding") {
        if holder.is_null() {
            false
        } else {
            let (canonical, required) = canonical_holder(holder.take(), false)?;
            *holder = canonical;
            required
        }
    } else {
        false
    };
    if let Some(constraints) = value.get_mut("issuer_constraints") {
        if !constraints.is_null() {
            *constraints = canonical_issuer_constraints(constraints.take(), false)?;
        }
    }
    if let Some(freshness) = value.get_mut("freshness") {
        if !freshness.is_null() {
            *freshness = canonical_freshness(freshness.take(), false)?;
        }
    }
    validate_optional_bool(&value, "prefer_predicates")?;
    validate_optional_enum(
        &value,
        "fallback_policy",
        &["REQUIRE_PREDICATE", "ACCEPT_RAW", "DENY"],
    )?;
    validate_string_array(value.get("supported_circuits"), true)?;
    validate_optional_enum(
        &value,
        "credential_ranking_strategy",
        &["FRESHEST_FIRST", "HIGHEST_TRUST_FIRST", "CUSTOM"],
    )?;
    if let Some(weights) = value.get("credential_ranking_weights") {
        if !weights.is_null() {
            let weights = weights.as_object().ok_or(PresentationPolicyContractError)?;
            if weights.values().any(|weight| !weight.is_number()) {
                return Err(PresentationPolicyContractError);
            }
        }
    }
    if value
        .get("credential_ranking_strategy")
        .and_then(Value::as_str)
        == Some("CUSTOM")
        && value
            .get("credential_ranking_weights")
            .and_then(Value::as_object)
            .is_none_or(Map::is_empty)
    {
        return Err(PresentationPolicyContractError);
    }
    if !update {
        let has_obligation = nonempty_array(&value, "required_claims")
            || nonempty_array(&value, "credential_requirements")
            || nonempty_array(&value, "alternative_requirements")
            || holder_required;
        if !has_obligation {
            return Err(PresentationPolicyContractError);
        }
    }
    remove_known_nulls(&mut value);
    if !include_organization_id {
        value.remove("organization_id");
    }
    Ok(Value::Object(value))
}

pub fn credential_template_ids(value: &Value) -> Vec<String> {
    let mut ids = Vec::new();
    visit_requirements(value, &mut |requirement| {
        if let Some(id) = requirement
            .get("credential_template_id")
            .and_then(Value::as_str)
        {
            ids.push(id.to_owned());
        }
    });
    ids
}

pub fn apply_authoritative_format(value: &mut Value, template_id: &str, format: &str) {
    visit_requirements_mut(value, &mut |requirement| {
        if requirement
            .get("credential_template_id")
            .and_then(Value::as_str)
            == Some(template_id)
        {
            requirement.insert(
                "credential_payload_format".into(),
                Value::String(format.into()),
            );
        }
    });
}

pub fn project_response(value: Value) -> Result<Value, PresentationPolicyContractError> {
    if let Value::Array(items) = value {
        return items
            .into_iter()
            .map(project_one)
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array);
    }
    project_one(value)
}

pub fn response_route(method: &str, path: &str) -> bool {
    if path == "/v1/presentation-policies" {
        return matches!(method, "GET" | "POST");
    }
    let Some(tail) = path.strip_prefix("/v1/presentation-policies/") else {
        return false;
    };
    let segments = tail.split('/').collect::<Vec<_>>();
    (segments.len() == 1 && matches!(method, "GET" | "PATCH"))
        || (segments.len() == 2 && segments[1] == "activate" && method == "POST")
}

fn project_one(value: Value) -> Result<Value, PresentationPolicyContractError> {
    let source = value.as_object().ok_or(PresentationPolicyContractError)?;
    let mut value = source
        .iter()
        .filter(|(field, _)| RESPONSE_FIELDS.contains(&field.as_str()))
        .map(|(field, value)| (field.clone(), value.clone()))
        .collect::<Map<_, _>>();
    for field in ["id", "organization_id", "name", "created_at", "updated_at"] {
        required_string(&value, field, 0, usize::MAX)?;
    }
    required_enum(
        &value,
        "status",
        &["draft", "active", "suspended", "archived"],
    )?;
    canonical_required_claims(
        value
            .get_mut("required_claims")
            .ok_or(PresentationPolicyContractError)?,
    )?;
    validate_string_array(value.get("accepted_credential_types"), false)?;
    if let Some(display) = value.get_mut("display_metadata") {
        if !display.is_null() {
            *display = canonical_display(display.take(), true)?;
        }
    }
    if let Some(requirements) = value.get_mut("credential_requirements") {
        if !requirements.is_null() {
            canonical_requirements_response(requirements)?;
        }
    }
    if let Some(alternatives) = value.get_mut("alternative_requirements") {
        if !alternatives.is_null() {
            canonical_alternatives_response(alternatives)?;
        }
    }
    let holder = value
        .get_mut("holder_binding")
        .ok_or(PresentationPolicyContractError)?;
    let (canonical_holder, _) = canonical_holder(holder.take(), true)?;
    *holder = canonical_holder;
    if let Some(constraints) = value.get_mut("issuer_constraints") {
        if !constraints.is_null() {
            *constraints = canonical_issuer_constraints(constraints.take(), true)?;
        }
    }
    if let Some(freshness) = value.get_mut("freshness") {
        if !freshness.is_null() {
            *freshness = canonical_freshness(freshness.take(), true)?;
        }
    }
    required_bool(&value, "prefer_predicates")?;
    validate_optional_enum(
        &value,
        "fallback_policy",
        &["REQUIRE_PREDICATE", "ACCEPT_RAW", "DENY"],
    )?;
    validate_string_array(value.get("supported_circuits"), false)?;
    required_enum(
        &value,
        "credential_ranking_strategy",
        &["FRESHEST_FIRST", "HIGHEST_TRUST_FIRST", "CUSTOM"],
    )?;
    let version = value
        .get("version")
        .and_then(Value::as_u64)
        .ok_or(PresentationPolicyContractError)?;
    if version == 0 {
        return Err(PresentationPolicyContractError);
    }
    remove_known_nulls(&mut value);
    Ok(Value::Object(value))
}

fn canonical_requirements(value: &mut Value) -> Result<(), PresentationPolicyContractError> {
    let requirements = value
        .as_array_mut()
        .ok_or(PresentationPolicyContractError)?;
    for requirement in requirements {
        *requirement = canonical_requirement(requirement.take(), false)?;
    }
    Ok(())
}

fn canonical_requirements_response(
    value: &mut Value,
) -> Result<(), PresentationPolicyContractError> {
    let requirements = value
        .as_array_mut()
        .ok_or(PresentationPolicyContractError)?;
    for requirement in requirements {
        *requirement = canonical_requirement(requirement.take(), true)?;
    }
    Ok(())
}

fn canonical_requirement(
    value: Value,
    response: bool,
) -> Result<Value, PresentationPolicyContractError> {
    const FIELDS: &[&str] = &[
        "credential_template_id",
        "display_name",
        "description",
        "required",
        "credential_payload_format",
        "requested_claims",
        "trust_profile_id",
        "max_age_seconds",
        "require_fresh_issuance",
    ];
    let mut value = object(value, FIELDS)?;
    required_string(&value, "credential_template_id", 1, 255)?;
    if response {
        value
            .entry("display_name")
            .or_insert(Value::String(String::new()));
        value.entry("required").or_insert(Value::Bool(true));
        value
            .entry("credential_payload_format")
            .or_insert(Value::String("w3c_vcdm_v2_sd_jwt".into()));
        value
            .entry("require_fresh_issuance")
            .or_insert(Value::Bool(false));
    }
    validate_optional_string(&value, "display_name", 255)?;
    validate_optional_string(&value, "description", 2000)?;
    validate_optional_string(&value, "credential_payload_format", 100)?;
    validate_optional_string(&value, "trust_profile_id", 255)?;
    validate_optional_bool(&value, "required")?;
    validate_optional_bool(&value, "require_fresh_issuance")?;
    if let Some(age) = value.get("max_age_seconds").filter(|age| !age.is_null()) {
        if age.as_u64().is_none_or(|age| age == 0) {
            return Err(PresentationPolicyContractError);
        }
    }
    let claims = value
        .get_mut("requested_claims")
        .and_then(Value::as_array_mut)
        .filter(|claims| !claims.is_empty())
        .ok_or(PresentationPolicyContractError)?;
    for claim in claims {
        *claim = canonical_requested_claim(claim.take(), response)?;
    }
    remove_known_nulls(&mut value);
    Ok(Value::Object(value))
}

fn canonical_requested_claim(
    value: Value,
    response: bool,
) -> Result<Value, PresentationPolicyContractError> {
    const FIELDS: &[&str] = &[
        "claim_name",
        "display_name",
        "description",
        "required",
        "selective_disclosure",
        "accept_derived",
        "predicate_spec",
        "constraints",
    ];
    let mut value = object(value, FIELDS)?;
    required_string(&value, "claim_name", 1, 255)?;
    if response {
        value
            .entry("display_name")
            .or_insert(Value::String(String::new()));
        value.entry("required").or_insert(Value::Bool(true));
        value
            .entry("selective_disclosure")
            .or_insert(Value::Bool(true));
        value.entry("accept_derived").or_insert(Value::Bool(true));
        value
            .entry("constraints")
            .or_insert(Value::Array(Vec::new()));
    }
    validate_optional_string(&value, "display_name", 255)?;
    validate_optional_string(&value, "description", 2000)?;
    for field in ["required", "selective_disclosure", "accept_derived"] {
        validate_optional_bool(&value, field)?;
    }
    if let Some(predicate) = value.get_mut("predicate_spec") {
        if !predicate.is_null() {
            *predicate = canonical_predicate(predicate.take(), response)?;
        }
    }
    if let Some(constraints) = value.get_mut("constraints") {
        if !constraints.is_null() {
            canonical_claim_constraints(constraints, response)?;
        }
    }
    remove_known_nulls(&mut value);
    Ok(Value::Object(value))
}

fn canonical_claim_constraints(
    value: &mut Value,
    response: bool,
) -> Result<(), PresentationPolicyContractError> {
    let constraints = value
        .as_array_mut()
        .ok_or(PresentationPolicyContractError)?;
    for constraint in constraints {
        let mut item = object(
            constraint.take(),
            &["claim_name", "constraint_type", "value", "description"],
        )?;
        required_string(&item, "claim_name", 1, 255)?;
        if response {
            item.entry("constraint_type")
                .or_insert(Value::String("presence".into()));
        }
        validate_optional_enum(
            &item,
            "constraint_type",
            &[
                "equals",
                "not_equals",
                "greater_than",
                "less_than",
                "greater_or_equal",
                "less_or_equal",
                "in_set",
                "not_in_set",
                "presence",
                "regex",
                "age_over",
            ],
        )?;
        validate_optional_string(&item, "description", 2000)?;
        remove_known_nulls(&mut item);
        *constraint = Value::Object(item);
    }
    Ok(())
}

fn canonical_predicate(
    value: Value,
    response: bool,
) -> Result<Value, PresentationPolicyContractError> {
    let mut value = object(
        value,
        &[
            "predicate_type",
            "params",
            "supported_circuits",
            "fallback_policy",
        ],
    )?;
    required_enum(
        &value,
        "predicate_type",
        &[
            "RANGE_PROOF",
            "MEMBERSHIP",
            "EQUALITY",
            "NON_MEMBERSHIP",
            "INEQUALITY",
        ],
    )?;
    if !value.get("params").is_some_and(Value::is_object) {
        return Err(PresentationPolicyContractError);
    }
    if response {
        value
            .entry("supported_circuits")
            .or_insert(Value::Array(Vec::new()));
    }
    validate_string_array(value.get("supported_circuits"), true)?;
    validate_optional_enum(
        &value,
        "fallback_policy",
        &["REQUIRE_PREDICATE", "ACCEPT_RAW", "DENY"],
    )?;
    remove_known_nulls(&mut value);
    Ok(Value::Object(value))
}

fn canonical_required_claims(value: &mut Value) -> Result<(), PresentationPolicyContractError> {
    let claims = value
        .as_array_mut()
        .ok_or(PresentationPolicyContractError)?;
    for claim in claims {
        let mut item = object(
            claim.take(),
            &[
                "claim_name",
                "credential_type",
                "value_constraint",
                "predicate_spec",
            ],
        )?;
        required_string(&item, "claim_name", 1, 255)?;
        validate_optional_string(&item, "credential_type", usize::MAX)?;
        if let Some(predicate) = item.get_mut("predicate_spec") {
            if !predicate.is_null() {
                *predicate = canonical_predicate(predicate.take(), true)?;
            }
        }
        remove_known_nulls(&mut item);
        *claim = Value::Object(item);
    }
    Ok(())
}

fn canonical_alternatives(value: &mut Value) -> Result<(), PresentationPolicyContractError> {
    canonical_alternatives_impl(value, false)
}

fn canonical_alternatives_response(
    value: &mut Value,
) -> Result<(), PresentationPolicyContractError> {
    canonical_alternatives_impl(value, true)
}

fn canonical_alternatives_impl(
    value: &mut Value,
    response: bool,
) -> Result<(), PresentationPolicyContractError> {
    let alternatives = value
        .as_array_mut()
        .ok_or(PresentationPolicyContractError)?;
    for alternative in alternatives {
        let mut item = object(
            alternative.take(),
            &[
                "name",
                "description",
                "credential_requirements",
                "min_satisfied",
            ],
        )?;
        required_string(&item, "name", 1, 255)?;
        validate_optional_string(&item, "description", 2000)?;
        let minimum = item
            .get("min_satisfied")
            .and_then(Value::as_u64)
            .unwrap_or(1);
        let requirements = item
            .get_mut("credential_requirements")
            .and_then(Value::as_array_mut)
            .filter(|requirements| !requirements.is_empty())
            .ok_or(PresentationPolicyContractError)?;
        for requirement in requirements.iter_mut() {
            *requirement = canonical_requirement(requirement.take(), response)?;
        }
        if minimum == 0 || minimum as usize > requirements.len() {
            return Err(PresentationPolicyContractError);
        }
        if response {
            item.entry("min_satisfied").or_insert(Value::from(1));
        }
        remove_known_nulls(&mut item);
        *alternative = Value::Object(item);
    }
    Ok(())
}

fn canonical_display(
    value: Value,
    response: bool,
) -> Result<Value, PresentationPolicyContractError> {
    let mut value = object(
        value,
        &[
            "title",
            "description",
            "purpose",
            "purpose_description",
            "verifier_name",
            "verifier_logo_url",
            "privacy_policy_url",
            "terms_of_service_url",
        ],
    )?;
    if response {
        value.entry("title").or_insert(Value::String(String::new()));
        value
            .entry("description")
            .or_insert(Value::String(String::new()));
        value
            .entry("purpose")
            .or_insert(Value::String("identity_verification".into()));
        value
            .entry("verifier_name")
            .or_insert(Value::String(String::new()));
    }
    for (field, max) in [
        ("title", 255),
        ("description", 2000),
        ("purpose_description", 2000),
        ("verifier_name", 255),
        ("verifier_logo_url", 2000),
        ("privacy_policy_url", 2000),
        ("terms_of_service_url", 2000),
    ] {
        validate_optional_string(&value, field, max)?;
    }
    validate_optional_enum(
        &value,
        "purpose",
        &[
            "identity_verification",
            "age_verification",
            "employment_verification",
            "address_verification",
            "qualification_verification",
            "authorization",
            "compliance",
            "other",
        ],
    )?;
    remove_known_nulls(&mut value);
    Ok(Value::Object(value))
}

fn canonical_holder(
    value: Value,
    response: bool,
) -> Result<(Value, bool), PresentationPolicyContractError> {
    let mut value = object(
        value,
        &[
            "required",
            "binding_methods",
            "proof_profiles",
            "proof_freshness",
        ],
    )?;
    let required = value
        .get("required")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !required {
        let configured = value
            .get("binding_methods")
            .and_then(Value::as_array)
            .is_some_and(|items| !items.is_empty())
            || value
                .get("proof_profiles")
                .and_then(Value::as_array)
                .is_some_and(|items| !items.is_empty())
            || value
                .get("proof_freshness")
                .is_some_and(|entry| !entry.is_null());
        if configured {
            return Err(PresentationPolicyContractError);
        }
        return Ok((serde_json::json!({"required": false}), false));
    }
    validate_enum_array(
        value.get("binding_methods"),
        &["CREDENTIAL_KEY", "DEVICE_KEY", "SESSION_BINDING"],
        true,
    )?;
    validate_enum_array(
        value.get("proof_profiles"),
        &[
            "OID4VP_VERIFIABLE_PRESENTATION",
            "SD_JWT_KEY_BINDING",
            "MDOC_DEVICE_AUTHENTICATION",
            "CUSTOM",
        ],
        true,
    )?;
    let freshness = value
        .get_mut("proof_freshness")
        .filter(|entry| !entry.is_null())
        .ok_or(PresentationPolicyContractError)?;
    *freshness = canonical_proof_freshness(freshness.take(), response)?;
    value.insert("required".into(), Value::Bool(true));
    Ok((Value::Object(value), true))
}

fn canonical_proof_freshness(
    value: Value,
    response: bool,
) -> Result<Value, PresentationPolicyContractError> {
    let mut value = object(
        value,
        &[
            "challenge_required",
            "audience_binding_required",
            "replay_detection_required",
            "max_proof_age_seconds",
        ],
    )?;
    if response {
        for field in [
            "challenge_required",
            "audience_binding_required",
            "replay_detection_required",
        ] {
            value.entry(field).or_insert(Value::Bool(true));
        }
    }
    for field in [
        "challenge_required",
        "audience_binding_required",
        "replay_detection_required",
    ] {
        validate_optional_bool(&value, field)?;
    }
    if let Some(age) = value
        .get("max_proof_age_seconds")
        .filter(|age| !age.is_null())
    {
        if age.as_u64().is_none_or(|age| age == 0) {
            return Err(PresentationPolicyContractError);
        }
    }
    remove_known_nulls(&mut value);
    Ok(Value::Object(value))
}

fn canonical_issuer_constraints(
    value: Value,
    response: bool,
) -> Result<Value, PresentationPolicyContractError> {
    let mut value = object(
        value,
        &[
            "min_trust_level",
            "required_compliance_statuses",
            "required_accreditations",
        ],
    )?;
    if let Some(level) = value
        .get("min_trust_level")
        .filter(|entry| !entry.is_null())
    {
        if level.as_u64().is_none_or(|level| level > 100) {
            return Err(PresentationPolicyContractError);
        }
    }
    if response {
        value
            .entry("required_compliance_statuses")
            .or_insert(Value::Array(Vec::new()));
        value
            .entry("required_accreditations")
            .or_insert(Value::Array(Vec::new()));
    }
    validate_enum_array(
        value.get("required_compliance_statuses"),
        &["ACCREDITED", "COMPLIANT"],
        false,
    )?;
    validate_string_array(value.get("required_accreditations"), true)?;
    remove_known_nulls(&mut value);
    Ok(Value::Object(value))
}

fn canonical_freshness(
    value: Value,
    response: bool,
) -> Result<Value, PresentationPolicyContractError> {
    let mut value = object(
        value,
        &[
            "max_age_seconds",
            "require_not_revoked",
            "revocation_grace_seconds",
        ],
    )?;
    if response {
        value
            .entry("require_not_revoked")
            .or_insert(Value::Bool(false));
    }
    if let Some(age) = value
        .get("max_age_seconds")
        .filter(|entry| !entry.is_null())
    {
        if age.as_u64().is_none_or(|age| age == 0) {
            return Err(PresentationPolicyContractError);
        }
    }
    if let Some(grace) = value
        .get("revocation_grace_seconds")
        .filter(|entry| !entry.is_null())
    {
        if grace.as_u64().is_none() {
            return Err(PresentationPolicyContractError);
        }
    }
    validate_optional_bool(&value, "require_not_revoked")?;
    remove_known_nulls(&mut value);
    Ok(Value::Object(value))
}

fn visit_requirements(value: &Value, visitor: &mut impl FnMut(&Map<String, Value>)) {
    let Some(policy) = value.as_object() else {
        return;
    };
    if let Some(requirements) = policy
        .get("credential_requirements")
        .and_then(Value::as_array)
    {
        for requirement in requirements.iter().filter_map(Value::as_object) {
            visitor(requirement);
        }
    }
    if let Some(alternatives) = policy
        .get("alternative_requirements")
        .and_then(Value::as_array)
    {
        for alternative in alternatives.iter().filter_map(Value::as_object) {
            if let Some(requirements) = alternative
                .get("credential_requirements")
                .and_then(Value::as_array)
            {
                for requirement in requirements.iter().filter_map(Value::as_object) {
                    visitor(requirement);
                }
            }
        }
    }
}

fn visit_requirements_mut(value: &mut Value, visitor: &mut impl FnMut(&mut Map<String, Value>)) {
    let Some(policy) = value.as_object_mut() else {
        return;
    };
    if let Some(requirements) = policy
        .get_mut("credential_requirements")
        .and_then(Value::as_array_mut)
    {
        for requirement in requirements.iter_mut().filter_map(Value::as_object_mut) {
            visitor(requirement);
        }
    }
    if let Some(alternatives) = policy
        .get_mut("alternative_requirements")
        .and_then(Value::as_array_mut)
    {
        for alternative in alternatives.iter_mut().filter_map(Value::as_object_mut) {
            if let Some(requirements) = alternative
                .get_mut("credential_requirements")
                .and_then(Value::as_array_mut)
            {
                for requirement in requirements.iter_mut().filter_map(Value::as_object_mut) {
                    visitor(requirement);
                }
            }
        }
    }
}

fn parse_object(
    body: &[u8],
    allowed: &[&str],
) -> Result<Map<String, Value>, PresentationPolicyContractError> {
    let value =
        serde_json::from_slice::<Value>(body).map_err(|_| PresentationPolicyContractError)?;
    object(value, allowed)
}

fn object(
    value: Value,
    allowed: &[&str],
) -> Result<Map<String, Value>, PresentationPolicyContractError> {
    let value = value
        .as_object()
        .cloned()
        .ok_or(PresentationPolicyContractError)?;
    if value.keys().any(|field| !allowed.contains(&field.as_str())) {
        return Err(PresentationPolicyContractError);
    }
    Ok(value)
}

fn required_string<'a>(
    value: &'a Map<String, Value>,
    field: &str,
    min: usize,
    max: usize,
) -> Result<&'a str, PresentationPolicyContractError> {
    let value = value
        .get(field)
        .and_then(Value::as_str)
        .ok_or(PresentationPolicyContractError)?;
    let len = value.chars().count();
    if len < min || len > max {
        return Err(PresentationPolicyContractError);
    }
    Ok(value)
}

fn validate_optional_string(
    value: &Map<String, Value>,
    field: &str,
    max: usize,
) -> Result<(), PresentationPolicyContractError> {
    if let Some(entry) = value.get(field).filter(|entry| !entry.is_null()) {
        if entry
            .as_str()
            .is_none_or(|entry| entry.chars().count() > max)
        {
            return Err(PresentationPolicyContractError);
        }
    }
    Ok(())
}

fn required_enum(
    value: &Map<String, Value>,
    field: &str,
    allowed: &[&str],
) -> Result<(), PresentationPolicyContractError> {
    if value
        .get(field)
        .and_then(Value::as_str)
        .is_none_or(|entry| !allowed.contains(&entry))
    {
        return Err(PresentationPolicyContractError);
    }
    Ok(())
}

fn validate_optional_enum(
    value: &Map<String, Value>,
    field: &str,
    allowed: &[&str],
) -> Result<(), PresentationPolicyContractError> {
    if let Some(entry) = value.get(field).filter(|entry| !entry.is_null()) {
        if entry.as_str().is_none_or(|entry| !allowed.contains(&entry)) {
            return Err(PresentationPolicyContractError);
        }
    }
    Ok(())
}

fn required_bool(
    value: &Map<String, Value>,
    field: &str,
) -> Result<(), PresentationPolicyContractError> {
    value
        .get(field)
        .and_then(Value::as_bool)
        .map(|_| ())
        .ok_or(PresentationPolicyContractError)
}

fn validate_optional_bool(
    value: &Map<String, Value>,
    field: &str,
) -> Result<(), PresentationPolicyContractError> {
    if value
        .get(field)
        .is_some_and(|entry| !entry.is_null() && !entry.is_boolean())
    {
        return Err(PresentationPolicyContractError);
    }
    Ok(())
}

fn validate_string_array(
    value: Option<&Value>,
    allow_missing: bool,
) -> Result<(), PresentationPolicyContractError> {
    let Some(value) = value else {
        return if allow_missing {
            Ok(())
        } else {
            Err(PresentationPolicyContractError)
        };
    };
    if value.is_null() && allow_missing {
        return Ok(());
    }
    if value
        .as_array()
        .is_none_or(|items| items.iter().any(|item| !item.is_string()))
    {
        return Err(PresentationPolicyContractError);
    }
    Ok(())
}

fn validate_enum_array(
    value: Option<&Value>,
    allowed: &[&str],
    require_nonempty: bool,
) -> Result<(), PresentationPolicyContractError> {
    let items = value
        .and_then(Value::as_array)
        .ok_or(PresentationPolicyContractError)?;
    if require_nonempty && items.is_empty() {
        return Err(PresentationPolicyContractError);
    }
    if items
        .iter()
        .any(|item| item.as_str().is_none_or(|item| !allowed.contains(&item)))
    {
        return Err(PresentationPolicyContractError);
    }
    Ok(())
}

fn nonempty_array(value: &Map<String, Value>, field: &str) -> bool {
    value
        .get(field)
        .and_then(Value::as_array)
        .is_some_and(|items| !items.is_empty())
}

fn remove_known_nulls(value: &mut Map<String, Value>) {
    let nulls = value
        .iter()
        .filter(|(_, entry)| entry.is_null())
        .map(|(field, _)| field.clone())
        .collect::<BTreeSet<_>>();
    for field in nulls {
        value.remove(&field);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Contract {
        schema_version: u32,
        create_input: Value,
        authoritative_formats: Map<String, Value>,
        expected_create_internal: Value,
        proof_only_input: Value,
        expected_proof_only_internal: Value,
        invalid_requests: Vec<Value>,
        internal_response: Value,
        expected_public_response: Value,
    }

    #[test]
    fn language_neutral_presentation_policy_contract() {
        let contract: Contract = serde_json::from_str(include_str!(
            "../../../../contracts/gateway-presentation-policy-behavior.json"
        ))
        .expect("presentation policy contract");
        assert_eq!(contract.schema_version, 1);
        let mut create = canonicalize_request(
            &serde_json::to_vec(&contract.create_input).expect("fixture"),
            false,
            true,
        )
        .expect("create");
        for (id, format) in contract.authoritative_formats {
            apply_authoritative_format(&mut create, &id, format.as_str().expect("format"));
        }
        assert_eq!(create, contract.expected_create_internal);
        assert_eq!(
            canonicalize_request(
                &serde_json::to_vec(&contract.proof_only_input).expect("fixture"),
                false,
                true
            )
            .expect("proof only"),
            contract.expected_proof_only_internal
        );
        for invalid in contract.invalid_requests {
            assert!(canonicalize_request(
                &serde_json::to_vec(&invalid).expect("fixture"),
                false,
                true
            )
            .is_err());
        }
        assert_eq!(
            project_response(contract.internal_response).expect("response"),
            contract.expected_public_response
        );
    }
}
