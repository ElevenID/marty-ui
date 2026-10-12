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
    pub launch_module_name: String,
    pub launch_item_title: String,
    pub launch_assignment_name: String,
    pub quiz_title: String,
    pub quiz_description: String,
    pub quiz_points_possible: i64,
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
            let mut pairs = Vec::new();
            for (key, value) in fields {
                if let Some(value) = value.as_str() {
                    pairs.push((key.clone(), value.to_owned()));
                } else if let Some(values) = value.as_array() {
                    for value in values {
                        let value = value.as_str().ok_or_else(|| {
                            CanvasRestError::Other(format!(
                                "Canvas form field {key} must be a string"
                            ))
                        })?;
                        pairs.push((key.clone(), value.to_owned()));
                    }
                } else {
                    return Err(CanvasRestError::Other(format!(
                        "Canvas form field {key} must be a string"
                    )));
                }
            }
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
        if body.is_empty() {
            return Ok(Value::Null);
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

fn id_text(value: &Value) -> String {
    value
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| value.to_string())
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
                value.as_str() == Some(user_id) || value.to_string().as_str() == user_id
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

fn result(action: &str, field: &str, value: Value) -> Value {
    json!({"action": action, field: value})
}

fn required_created(value: Value, error: &str) -> Result<Value, CanvasRestError> {
    if value.is_object() && id(&value) {
        Ok(value)
    } else {
        Err(CanvasRestError::Other(error.into()))
    }
}

fn items_url(cfg: &CanvasRestConfig, course_id: &str, module_id: &str) -> String {
    format!(
        "{}/api/v1/courses/{course_id}/modules/{module_id}/items",
        base(cfg)
    )
}

async fn create_module_item_with_retries<T: CanvasRestTransport + Sync>(
    transport: &T,
    url: &str,
    form: Value,
) -> Result<Value, CanvasRestError> {
    let original = form.as_object().expect("module form object");
    let mut without_completion = original.clone();
    without_completion.retain(|key, _| !key.starts_with("module_item[completion_requirement]"));
    let mut without_content = original.clone();
    without_content.remove("module_item[content_id]");
    let mut compact = without_completion.clone();
    compact.remove("module_item[content_id]");
    let mut attempts = vec![original.clone()];
    for candidate in [without_completion, without_content, compact] {
        if !attempts.contains(&candidate) {
            attempts.push(candidate);
        }
    }
    let mut last_error = None;
    for attempt in attempts {
        match transport
            .request(CanvasOperation::form(
                "POST",
                url.to_owned(),
                Value::Object(attempt),
            ))
            .await
        {
            Ok(value) => {
                return required_created(
                    value,
                    "Canvas module item create did not return an item payload",
                )
            }
            Err(error @ CanvasRestError::Http(400 | 422, _)) => last_error = Some(error),
            Err(error) => return Err(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        CanvasRestError::Other(
            "Canvas module item create failed before any request was attempted".into(),
        )
    }))
}

pub async fn ensure_module<T: CanvasRestTransport + Sync>(
    transport: &T,
    cfg: &CanvasRestConfig,
    course_id: &str,
) -> Result<Value, CanvasRestError> {
    let url = format!("{}/api/v1/courses/{course_id}/modules", base(cfg));
    let modules = transport.request(CanvasOperation::get(url.clone())).await?;
    if let Some(module) = modules.as_array().and_then(|items| {
        items
            .iter()
            .find(|item| field_matches(item, "name", &cfg.launch_module_name))
    }) {
        return Ok(result("existing", "module", module.clone()));
    }
    let created = transport
        .request(CanvasOperation::form(
            "POST",
            url,
            json!({
                "module[name]": cfg.launch_module_name,
                "module[published]": "true"
            }),
        ))
        .await?;
    Ok(result(
        "created",
        "module",
        required_created(
            created,
            "Canvas module create did not return a module payload",
        )?,
    ))
}

pub async fn ensure_module_external_tool_item<T: CanvasRestTransport + Sync>(
    transport: &T,
    cfg: &CanvasRestConfig,
    course_id: &str,
    module_id: &str,
    external_url: &str,
    external_tool_id: Option<&str>,
) -> Result<Value, CanvasRestError> {
    let url = items_url(cfg, course_id, module_id);
    let items = transport.request(CanvasOperation::get(url.clone())).await?;
    if let Some(item) = items.as_array().and_then(|items| {
        items
            .iter()
            .find(|item| field_matches(item, "title", &cfg.launch_item_title))
    }) {
        if item.get("url").and_then(Value::as_str) != Some(external_url)
            || item.get("published") == Some(&Value::Bool(false))
        {
            let Some(item_id) = item.get("id").filter(|value| !value.is_null()) else {
                return Ok(result("existing", "item", item.clone()));
            };
            let mut form = json!({
                "module_item[title]": cfg.launch_item_title,
                "module_item[external_url]": external_url,
                "module_item[new_tab]": "false",
                "module_item[published]": "true"
            });
            if let Some(external_tool_id) = external_tool_id {
                form["module_item[content_id]"] = json!(external_tool_id);
            }
            let updated = transport
                .request(CanvasOperation::form(
                    "PUT",
                    format!("{url}/{}", id_text(item_id)),
                    form,
                ))
                .await?;
            return Ok(result("updated", "item", updated));
        }
        return Ok(result("existing", "item", item.clone()));
    }
    let mut form = json!({
        "module_item[title]": cfg.launch_item_title,
        "module_item[type]": "ExternalTool",
        "module_item[external_url]": external_url,
        "module_item[new_tab]": "false",
        "module_item[published]": "true",
        "module_item[completion_requirement][type]": "must_view"
    });
    if let Some(external_tool_id) = external_tool_id {
        form["module_item[content_id]"] = json!(external_tool_id);
    }
    let created = create_module_item_with_retries(transport, &url, form).await?;
    Ok(result("created", "item", created))
}

pub async fn ensure_quiz<T: CanvasRestTransport + Sync>(
    transport: &T,
    cfg: &CanvasRestConfig,
    course_id: &str,
) -> Result<Value, CanvasRestError> {
    let url = format!("{}/api/v1/courses/{course_id}/quizzes", base(cfg));
    let query = form_urlencoded::Serializer::new(String::new())
        .append_pair("search_term", &cfg.quiz_title)
        .finish();
    let quizzes = transport
        .request(CanvasOperation::get(format!("{url}?{query}")))
        .await?;
    if let Some(quiz) = quizzes.as_array().and_then(|items| {
        items
            .iter()
            .find(|item| field_matches(item, "title", &cfg.quiz_title))
    }) {
        return Ok(result("existing", "quiz", quiz.clone()));
    }
    let created = transport
        .request(CanvasOperation::form(
            "POST",
            url,
            json!({
                "quiz[title]": cfg.quiz_title,
                "quiz[description]": cfg.quiz_description,
                "quiz[quiz_type]": "assignment",
                "quiz[published]": "true",
                "quiz[points_possible]": cfg.quiz_points_possible.to_string(),
                "quiz[allowed_attempts]": "1",
                "quiz[scoring_policy]": "keep_highest"
            }),
        ))
        .await?;
    Ok(result(
        "created",
        "quiz",
        required_created(created, "Canvas quiz create did not return a quiz payload")?,
    ))
}

pub async fn ensure_module_quiz_item<T: CanvasRestTransport + Sync>(
    transport: &T,
    cfg: &CanvasRestConfig,
    course_id: &str,
    module_id: &str,
    quiz_id: &str,
) -> Result<Value, CanvasRestError> {
    let url = items_url(cfg, course_id, module_id);
    let items = transport.request(CanvasOperation::get(url.clone())).await?;
    if let Some(item) = items.as_array().and_then(|items| {
        items
            .iter()
            .find(|item| field_matches(item, "title", &cfg.quiz_title))
    }) {
        return Ok(result("existing", "item", item.clone()));
    }
    let created = create_module_item_with_retries(
        transport,
        &url,
        json!({
            "module_item[title]": cfg.quiz_title,
            "module_item[type]": "Quiz",
            "module_item[content_id]": quiz_id,
            "module_item[published]": "true",
            "module_item[completion_requirement][type]": "must_submit"
        }),
    )
    .await?;
    Ok(result("created", "item", created))
}

pub async fn ensure_external_tool_assignment<T: CanvasRestTransport + Sync>(
    transport: &T,
    cfg: &CanvasRestConfig,
    course_id: &str,
    external_url: &str,
) -> Result<Value, CanvasRestError> {
    let url = format!("{}/api/v1/courses/{course_id}/assignments", base(cfg));
    let query = form_urlencoded::Serializer::new(String::new())
        .append_pair("search_term", &cfg.launch_assignment_name)
        .finish();
    let assignments = transport
        .request(CanvasOperation::get(format!("{url}?{query}")))
        .await?;
    let existing = assignments.as_array().and_then(|items| {
        items
            .iter()
            .find(|item| field_matches(item, "name", &cfg.launch_assignment_name))
    });
    if let Some(item) = existing {
        if item.get("id").is_none_or(Value::is_null) {
            return Ok(result("existing", "assignment", item.clone()));
        }
    }
    let form = json!({
        "assignment[name]": cfg.launch_assignment_name,
        "assignment[published]": "true",
        "assignment[points_possible]": "100",
        "assignment[grading_type]": "points",
        "assignment[submission_types][]": ["external_tool"],
        "assignment[external_tool_tag_attributes][url]": external_url,
        "assignment[external_tool_tag_attributes][new_tab]": "false"
    });
    let (method, action, target) = if let Some(item) = existing {
        ("PUT", "updated", format!("{url}/{}", id_text(&item["id"])))
    } else {
        ("POST", "created", url)
    };
    let value = transport
        .request(CanvasOperation::form(method, target, form))
        .await?;
    if action == "created" {
        required_created(
            value.clone(),
            "Canvas assignment create did not return an assignment payload",
        )?;
    }
    Ok(result(action, "assignment", value))
}
