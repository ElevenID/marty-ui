use crate::{GatewaySeedConfig, BADGE_DESCRIPTION, BADGE_NAME, BADGE_VCT, ISSUER_DID};
use hmac::{Hmac, Mac};
use serde_json::{json, Map, Value};
use sha2::Sha256;
use std::time::Duration;

pub struct DemoEvidenceConfig {
    pub learner_name: String,
    pub learner_email: String,
    pub course_name: String,
    pub quiz_title: String,
    pub quiz_passing_score_percent: i64,
    pub quiz_points_possible: i64,
}

fn nonempty(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(text)) if !text.is_empty() => Some(text.clone()),
        Some(Value::Number(number)) if number.to_string() != "0" => Some(number.to_string()),
        _ => None,
    }
}

fn seed_field(seed: &Value, group: &str, field: &str) -> Option<String> {
    nonempty(seed.get(group).and_then(|item| item.get(field)))
}

fn score(cfg: &GatewaySeedConfig, demo: &DemoEvidenceConfig) -> i64 {
    cfg.program_binding_score_threshold
        .max(demo.quiz_passing_score_percent)
}

fn achievement(threshold: i64) -> Value {
    let criteria = format!(
        "Complete the Canvas learning activity and earn at least {threshold}% on the interoperability quiz. ElevenID issues the credential from the Marty organization using the canonical DID issuer and remote signing service."
    );
    json!({
        "id": format!("{BADGE_VCT}#achievement"),
        "type": ["Achievement"],
        "name": BADGE_NAME,
        "description": BADGE_DESCRIPTION,
        "criteria": {"id": format!("{BADGE_VCT}/criteria"), "narrative": criteria},
        "image": {"id": format!("{BADGE_VCT}/image.svg"), "type": "Image", "caption": BADGE_NAME},
        "alignment": [
            {"targetName": "Open Badges 3.0", "targetDescription": "Portable achievement credential carried as a verifiable credential."},
            {"targetName": "Marty Identity Protocol", "targetDescription": "MIP-governed issuance, status-list allocation, and destination projection."}
        ]
    })
}

pub fn application_payload(
    cfg: &GatewaySeedConfig,
    demo: &DemoEvidenceConfig,
    canvas_seed: &Value,
    today: &str,
) -> Value {
    let score = score(cfg, demo);
    let course_name =
        seed_field(canvas_seed, "course", "name").unwrap_or_else(|| demo.course_name.clone());
    let quiz_name =
        seed_field(canvas_seed, "quiz", "title").unwrap_or_else(|| demo.quiz_title.clone());
    let course_id = seed_field(canvas_seed, "course", "id").unwrap_or_default();
    let quiz_id = seed_field(canvas_seed, "quiz", "id").unwrap_or_default();
    let given_name = if demo.learner_name.is_empty() {
        "ElevenID".to_owned()
    } else {
        demo.learner_name
            .split_once(' ')
            .map_or(demo.learner_name.as_str(), |(first, _)| first)
            .to_owned()
    };
    let family_name = demo
        .learner_name
        .split_once(' ')
        .map_or("Learner", |(_, family)| family)
        .to_owned();
    let achievement = achievement(cfg.program_binding_score_threshold);
    json!({
        "application_template_id": cfg.application_template_id,
        "applicant_data": {
            "_credential_type": "OpenBadgeCredential",
            "_vct": BADGE_VCT,
            "email": demo.learner_email,
            "given_name": given_name,
            "family_name": family_name,
            "achievement_id": achievement["id"],
            "achievement_name": BADGE_NAME,
            "achievement_description": BADGE_DESCRIPTION,
            "achievement_criteria": achievement["criteria"]["narrative"],
            "badge_image_url": format!("{BADGE_VCT}/image.svg"),
            "course_name": course_name,
            "quiz_name": quiz_name,
            "score_percent": score,
            "completion_date": today,
            "institution_name": "Marty Organization",
            "certificate_id": format!("interoperable-credentials-foundations-{today}"),
            "organization_id": cfg.organization_id,
            "achievement": achievement,
            "result": {
                "type": ["Result"],
                "source": "Canvas AGS score",
                "score": score,
                "maximumScore": demo.quiz_points_possible,
                "passingScore": cfg.program_binding_score_threshold,
                "resultDescription": format!("Completed {quiz_name} with a score of {score}%.")
            },
            "learning_context": {
                "provider": "canvas",
                "course": {"id": course_id, "name": course_name},
                "activity": {"id": quiz_id, "type": "quiz", "name": quiz_name},
                "canvas_account_id": cfg.canvas_account_id
            }
        },
        "integration_context": {
            "scenario": "canvas_mip_quiz_open_badge",
            "credential_type": "OpenBadgeCredential",
            "credential_vct": BADGE_VCT,
            "delivery_mode": cfg.program_binding_delivery_mode,
            "delivery": {"mode": cfg.program_binding_delivery_mode},
            "open_badge": {"vct": BADGE_VCT, "name": BADGE_NAME, "image": format!("{BADGE_VCT}/image.svg"), "criteria": format!("{BADGE_VCT}/criteria")},
            "canvas": {"canvas_account_id": cfg.canvas_account_id, "canvas_course_id": course_id, "canvas_quiz_id": quiz_id, "learner_email": demo.learner_email},
            "issuer": {"mode": "org_managed", "issuer_did": ISSUER_DID, "signing_service_id": "managed-openbao-transit", "signing_key_reference": "cred-issuer-marty-es256"}
        }
    })
}

pub fn ags_score_payload(
    cfg: &GatewaySeedConfig,
    demo: &DemoEvidenceConfig,
    canvas_seed: &Value,
    application_id: &str,
    today: &str,
    event_suffix: &str,
) -> Value {
    let score = score(cfg, demo);
    json!({
        "canvas_event_id": format!("canvas-demo-ags-{application_id}-{event_suffix}"),
        "application_id": application_id,
        "organization_id": cfg.organization_id,
        "credential_template_id": cfg.credential_template_id,
        "canvas_account_id": cfg.canvas_account_id,
        "canvas_course_id": seed_field(canvas_seed, "course", "id").unwrap_or_default(),
        "canvas_course_name": seed_field(canvas_seed, "course", "name").unwrap_or_else(|| demo.course_name.clone()),
        "canvas_user_id": seed_field(canvas_seed, "learner", "id").unwrap_or_default(),
        "canvas_enrollment_id": seed_field(canvas_seed, "enrollment", "id").unwrap_or_default(),
        "learner_email": demo.learner_email,
        "learner_name": demo.learner_name,
        "evidence_type": cfg.program_binding_evidence_type,
        "canvas_quiz_id": seed_field(canvas_seed, "quiz", "id").unwrap_or_default(),
        "line_item_label": seed_field(canvas_seed, "quiz", "title").unwrap_or_else(|| demo.quiz_title.clone()),
        "activity_progress": "Completed",
        "grading_progress": "FullyGraded",
        "submitted": true,
        "completed": true,
        "passed": true,
        "score_given": score,
        "score_maximum": 100,
        "score_percent": score,
        "graded_at": today
    })
}

fn sorted(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut keys = object.keys().collect::<Vec<_>>();
            keys.sort();
            let mut sorted_object = Map::new();
            for key in keys {
                sorted_object.insert(key.clone(), sorted(&object[key]));
            }
            Value::Object(sorted_object)
        }
        Value::Array(values) => Value::Array(values.iter().map(sorted).collect()),
        other => other.clone(),
    }
}

pub struct SignedAgsWire {
    pub body: String,
    pub timestamp: String,
    pub signature: String,
}

pub fn signed_ags_wire(
    payload: &Value,
    secret: &str,
    timestamp: i64,
) -> Result<SignedAgsWire, String> {
    if secret.is_empty() {
        return Err("Canvas AGS signing secret is empty".into());
    }
    let body = serde_json::to_string(&sorted(payload)).map_err(|e| e.to_string())?;
    let timestamp = timestamp.to_string();
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).map_err(|e| e.to_string())?;
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(body.as_bytes());
    let signature = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
    Ok(SignedAgsWire {
        body,
        timestamp,
        signature,
    })
}

pub async fn send_signed_ags(
    url: &str,
    payload: &Value,
    secret: &str,
    timestamp: i64,
) -> Result<Value, String> {
    let wire = signed_ags_wire(payload, secret, timestamp)?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| e.to_string())?;
    let response = client
        .post(url)
        .header("Accept", "application/json")
        .header("Content-Type", "application/json")
        .header("X-Canvas-Timestamp", &wire.timestamp)
        .header("X-Canvas-Signature-256", &wire.signature)
        .body(wire.body)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = response.status();
    let body = response.text().await.map_err(|e| e.to_string())?;
    if !status.is_success() {
        return Err(format!("Canvas AGS score event failed ({status}): {body}"));
    }
    if body.is_empty() {
        Ok(Value::Null)
    } else {
        serde_json::from_str(&body).map_err(|e| e.to_string())
    }
}
