//! Canvas LMS course, learner, and enrollment seed operations.

use async_trait::async_trait;
use serde_json::{json, Value};
use std::time::Duration;
use url::form_urlencoded;

#[derive(Clone, Debug)]
pub struct CanvasRestConfig {
    pub api_base_url: String,
    pub account_id: String,
    pub course_name: String,
    pub course_code: String,
    pub course_sis_id: String,
    pub learner_name: String,
    pub learner_email: String,
    pub learner_password: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CanvasOperation {
    pub method: &'static str,
    pub url: String,
    pub form: Option<Value>,
}

impl CanvasOperation {
    fn get(url: String) -> Self {
        Self {
            method: "GET",
            url,
            form: None,
        }
    }

    fn form(method: &'static str, url: String, form: Value) -> Self {
        Self {
            method,
            url,
            form: Some(form),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum CanvasRestError {
    Http(u16, String),
    Other(String),
}

#[async_trait]
pub trait CanvasRestTransport {
    async fn request(&self, operation: CanvasOperation) -> Result<Value, CanvasRestError>;
}

pub struct CanvasRestHttp {
    client: reqwest::Client,
    admin_token: String,
}

impl CanvasRestHttp {
    pub fn new(admin_token: String) -> Result<Self, CanvasRestError> {
        if admin_token.trim().is_empty() {
            return Err(CanvasRestError::Other(
                "Canvas admin token is required".into(),
            ));
        }
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|e| CanvasRestError::Other(e.to_string()))?;
        Ok(Self {
            client,
            admin_token,
        })
    }
}

#[async_trait]
impl CanvasRestTransport for CanvasRestHttp {
    async fn request(&self, operation: CanvasOperation) -> Result<Value, CanvasRestError> {
        let method = reqwest::Method::from_bytes(operation.method.as_bytes())
            .map_err(|e| CanvasRestError::Other(e.to_string()))?;
        let mut request = self
            .client
            .request(method, operation.url)
            .header("Authorization", format!("Bearer {}", self.admin_token))
            .header("Accept", "application/json");
        if let Some(form) = operation.form {
            let fields = form
                .as_object()
                .ok_or_else(|| CanvasRestError::Other("Canvas form must be an object".into()))?;
            let pairs: Vec<(String, String)> = fields
                .iter()
                .map(|(key, value)| {
                    let value = value.as_str().ok_or_else(|| {
                        CanvasRestError::Other(format!("Canvas form field {key} must be a string"))
                    })?;
                    Ok((key.clone(), value.to_owned()))
                })
                .collect::<Result<_, CanvasRestError>>()?;
            request = request.form(&pairs);
        }
        let response = request
            .send()
            .await
            .map_err(|e| CanvasRestError::Other(e.to_string()))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| CanvasRestError::Other(e.to_string()))?;
        if !status.is_success() {
            return Err(CanvasRestError::Http(status.as_u16(), body));
        }
        serde_json::from_str(&body).map_err(|e| CanvasRestError::Other(e.to_string()))
    }
}

fn base(cfg: &CanvasRestConfig) -> &str {
    cfg.api_base_url.trim_end_matches('/')
}

fn id(value: &Value) -> bool {
    match value.get("id") {
        Some(Value::String(value)) => !value.is_empty(),
        Some(Value::Number(value)) => value.as_i64().is_none_or(|number| number != 0),
        _ => false,
    }
}

fn field_matches(value: &Value, name: &str, expected: &str) -> bool {
    value.get(name).and_then(Value::as_str) == Some(expected)
}

pub async fn ensure_course<T: CanvasRestTransport + Sync>(
    transport: &T,
    cfg: &CanvasRestConfig,
) -> Result<Value, CanvasRestError> {
    let url = format!("{}/api/v1/accounts/{}/courses", base(cfg), cfg.account_id);
    let query = form_urlencoded::Serializer::new(String::new())
        .append_pair("search_term", &cfg.course_name)
        .finish();
    let existing = match transport
        .request(CanvasOperation::get(format!("{url}?{query}")))
        .await
    {
        Ok(value) => value,
        Err(CanvasRestError::Http(_, _)) => json!([]),
        Err(error) => return Err(error),
    };
    if let Some(course) = existing.as_array().and_then(|items| {
        items.iter().find(|item| {
            item.is_object()
                && (field_matches(item, "sis_course_id", &cfg.course_sis_id)
                    || field_matches(item, "course_code", &cfg.course_code)
                    || field_matches(item, "name", &cfg.course_name))
        })
    }) {
        return Ok(course.clone());
    }
    let created = transport
        .request(CanvasOperation::form(
            "POST",
            url,
            json!({
                "course[name]": cfg.course_name,
                "course[course_code]": cfg.course_code,
                "course[sis_course_id]": cfg.course_sis_id,
                "offer": "true"
            }),
        ))
        .await?;
    if !created.is_object() || !id(&created) {
        return Err(CanvasRestError::Other(
            "Failed to create Canvas course".into(),
        ));
    }
    Ok(created)
}

pub async fn ensure_user<T: CanvasRestTransport + Sync>(
    transport: &T,
    cfg: &CanvasRestConfig,
) -> Result<Value, CanvasRestError> {
    let url = format!("{}/api/v1/accounts/{}/users", base(cfg), cfg.account_id);
    let query = form_urlencoded::Serializer::new(String::new())
        .append_pair("search_term", &cfg.learner_email)
        .finish();
    let existing = match transport
        .request(CanvasOperation::get(format!("{url}?{query}")))
        .await
    {
        Ok(value) => value,
        Err(CanvasRestError::Http(_, _)) => json!([]),
        Err(error) => return Err(error),
    };
    if let Some(user) = existing.as_array().and_then(|items| {
        items.iter().find(|item| {
            item.is_object()
                && (field_matches(item, "login_id", &cfg.learner_email)
                    || field_matches(item, "sis_user_id", &cfg.learner_email))
        })
    }) {
        return Ok(user.clone());
    }
    let created = transport
        .request(CanvasOperation::form(
            "POST",
            url,
            json!({
                "user[name]": cfg.learner_name,
                "pseudonym[unique_id]": cfg.learner_email,
                "pseudonym[password]": cfg.learner_password,
                "communication_channel[type]": "email",
                "communication_channel[address]": cfg.learner_email,
                "skip_confirmation": "true"
            }),
        ))
        .await?;
    let user = if let Some(items) = created.as_array() {
        items.first()
    } else {
        Some(&created)
    };
    user.filter(|value| value.is_object())
        .cloned()
        .ok_or_else(|| {
            CanvasRestError::Other("Canvas user create did not return a user payload".into())
        })
}

pub async fn ensure_enrollment<T: CanvasRestTransport + Sync>(
    transport: &T,
    cfg: &CanvasRestConfig,
    course_id: &str,
    user_id: &str,
) -> Result<Value, CanvasRestError> {
    let url = format!("{}/api/v1/courses/{course_id}/enrollments", base(cfg));
    let query = form_urlencoded::Serializer::new(String::new())
        .append_pair("user_id[]", user_id)
        .append_pair("type[]", "StudentEnrollment")
        .finish();
    let existing = match transport
        .request(CanvasOperation::get(format!("{url}?{query}")))
        .await
    {
        Ok(value) => value,
        Err(CanvasRestError::Http(_, _)) => json!([]),
        Err(error) => return Err(error),
    };
    if let Some(enrollment) = existing.as_array().and_then(|items| {
        items.iter().find(|item| {
            item.get("user_id").is_some_and(|value| {
                value.as_str() == Some(user_id) || value.to_string() == user_id
            })
        })
    }) {
        return Ok(enrollment.clone());
    }
    transport
        .request(CanvasOperation::form(
            "POST",
            url,
            json!({
                "enrollment[user_id]": user_id,
                "enrollment[type]": "StudentEnrollment",
                "enrollment[enrollment_state]": "active",
                "notify": "false"
            }),
        ))
        .await
}
