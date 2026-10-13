//! Composes the Canvas REST and Rails seed steps into one demo LMS surface.

use crate::{
    ensure_canvas_developer_key, ensure_canvas_external_tool, ensure_canvas_public_domain,
    ensure_course, ensure_enrollment, ensure_external_tool_assignment, ensure_module,
    ensure_module_external_tool_item, ensure_module_quiz_item, ensure_quiz, ensure_user,
    CanvasDockerTransport, CanvasRailsConfig, CanvasRestConfig, CanvasRestError,
    CanvasRestTransport, CanvasRunConfig, ConnectorRunConfig,
};
use serde_json::{json, Value};

pub struct CanvasLmsSeedResult {
    pub summary: Value,
}

fn id(value: &Value) -> Result<String, String> {
    match value.get("id") {
        Some(Value::String(value)) if !value.is_empty() => Ok(value.clone()),
        Some(Value::Number(value)) => Ok(value.to_string()),
        _ => Err("Canvas seed response did not include an ID".into()),
    }
}

fn rest_error(error: CanvasRestError) -> String {
    match error {
        CanvasRestError::Http(code, _) => format!("Canvas REST request failed ({code})"),
        CanvasRestError::Other(message) => message,
    }
}

fn field(value: &Value, name: &str) -> Value {
    value.get(name).cloned().unwrap_or(Value::Null)
}

pub async fn seed_canvas_lms_objects<
    D: CanvasDockerTransport + Sync,
    R: CanvasRestTransport + Sync,
>(
    docker: &D,
    rest: &R,
    canvas: &CanvasRunConfig,
    connector: &ConnectorRunConfig,
    platform_id: &str,
) -> Result<CanvasLmsSeedResult, String> {
    let rails_cfg = CanvasRailsConfig {
        container_name: canvas.container_name.clone(),
        account_id: canvas.account_id.clone(),
        admin_email: canvas.admin_email.clone(),
        admin_password: canvas.admin_password.clone(),
        browser_base_url: canvas.browser_base_url.clone(),
        lti_client_id: connector.lti_client_id.clone(),
        lti_tool_base_url: connector.lti_tool_base_url.clone(),
        display_name: connector.display_name.clone(),
    };
    let rest_cfg = CanvasRestConfig {
        api_base_url: canvas.api_base_url.clone(),
        account_id: canvas.account_id.clone(),
        course_name: canvas.course_name.clone(),
        course_code: canvas.course_code.clone(),
        course_sis_id: canvas.course_sis_id.clone(),
        learner_name: canvas.learner_name.clone(),
        learner_email: canvas.learner_email.clone(),
        learner_password: canvas.learner_password.clone(),
        launch_module_name: canvas.launch_module_name.clone(),
        launch_item_title: canvas.launch_item_title.clone(),
        launch_assignment_name: canvas.launch_assignment_name.clone(),
        quiz_title: canvas.quiz_title.clone(),
        quiz_description: canvas.quiz_description.clone(),
        quiz_points_possible: canvas.quiz_points_possible,
    };
    let public_domain = ensure_canvas_public_domain(docker, &rails_cfg).await?;
    let course = ensure_course(rest, &rest_cfg).await.map_err(rest_error)?;
    let user = ensure_user(rest, &rest_cfg).await.map_err(rest_error)?;
    let enrollment = ensure_enrollment(rest, &rest_cfg, &id(&course)?, &id(&user)?)
        .await
        .map_err(rest_error)?;
    let developer_key = ensure_canvas_developer_key(docker, &rails_cfg, platform_id).await?;
    let external_tool =
        ensure_canvas_external_tool(docker, &rails_cfg, platform_id, &id(&course)?).await?;
    let mut launch_surface = Value::Null;
    let mut quiz_surface = Value::Null;
    if canvas.launch_seed_enabled {
        let launch_url = format!(
            "{}/v1/integrations/canvas/lti/platforms/{platform_id}/experience-login",
            connector.lti_tool_base_url.trim_end_matches('/')
        );
        let module = ensure_module(rest, &rest_cfg, &id(&course)?)
            .await
            .map_err(rest_error)?;
        let item = ensure_module_external_tool_item(
            rest,
            &rest_cfg,
            &id(&course)?,
            &id(&module["module"])?,
            &launch_url,
            Some(&id(&external_tool["tool"])?),
        )
        .await
        .map_err(rest_error)?;
        launch_surface = json!({
            "module": {
                "id": field(&module["module"], "id"),
                "name": field(&module["module"], "name"),
                "action": field(&module, "action"),
            },
            "module_item": {
                "id": field(&item["item"], "id"),
                "title": field(&item["item"], "title"),
                "html_url": field(&item["item"], "html_url"),
                "action": field(&item, "action"),
            }
        });
        match ensure_external_tool_assignment(rest, &rest_cfg, &id(&course)?, &launch_url).await {
            Ok(assignment) => {
                launch_surface["assignment"] = json!({
                    "id": field(&assignment["assignment"], "id"),
                    "name": field(&assignment["assignment"], "name"),
                    "html_url": field(&assignment["assignment"], "html_url"),
                    "action": field(&assignment, "action"),
                })
            }
            Err(CanvasRestError::Http(code, _)) => {
                launch_surface["assignment_error"] =
                    json!(format!("Canvas assignment seed failed ({code})"))
            }
            Err(CanvasRestError::Other(message)) => {
                launch_surface["assignment_error"] =
                    json!(format!("Canvas assignment seed failed: {message}"))
            }
        }
        if canvas.quiz_seed_enabled {
            let result = async {
                let quiz = ensure_quiz(
                    rest,
                    &rest_cfg,
                    &id(&course).map_err(CanvasRestError::Other)?,
                )
                .await?;
                let quiz_item = ensure_module_quiz_item(
                    rest,
                    &rest_cfg,
                    &id(&course).map_err(CanvasRestError::Other)?,
                    &id(&module["module"]).map_err(CanvasRestError::Other)?,
                    &id(&quiz["quiz"]).map_err(CanvasRestError::Other)?,
                )
                .await?;
                Ok::<Value, CanvasRestError>(json!({
                    "id": field(&quiz["quiz"], "id"),
                    "title": field(&quiz["quiz"], "title"),
                    "html_url": field(&quiz["quiz"], "html_url"),
                    "action": field(&quiz, "action"),
                    "module_item": {
                        "id": field(&quiz_item["item"], "id"),
                        "title": field(&quiz_item["item"], "title"),
                        "html_url": field(&quiz_item["item"], "html_url"),
                        "action": field(&quiz_item, "action")
                    }
                }))
            }
            .await;
            quiz_surface = match result {
                Ok(value) => value,
                Err(CanvasRestError::Http(code, _)) => {
                    json!({"error": format!("Canvas quiz seed failed ({code})")})
                }
                Err(CanvasRestError::Other(error)) => {
                    json!({"error": format!("Canvas quiz seed failed: {error}")})
                }
            };
        }
    }
    let mut summary = json!({
        "public_domain": public_domain,
        "developer_key": {
            "id": field(&developer_key["key"], "id"),
            "name": field(&developer_key["key"], "name"),
            "client_id": developer_key["key"].get("global_id").filter(|value| !value.is_null()).or_else(|| developer_key["key"].get("name")).map(|value| value.as_str().map(str::to_owned).unwrap_or_else(|| value.to_string())).unwrap_or_default(),
            "action": field(&developer_key, "action"),
            "owner_binding_account_id": field(&developer_key["key"], "owner_binding_account_id"),
            "owner_binding_workflow_state": field(&developer_key["key"], "owner_binding_workflow_state"),
            "requested_binding_account_id": field(&developer_key["key"], "requested_binding_account_id"),
            "requested_binding_workflow_state": field(&developer_key["key"], "requested_binding_workflow_state"),
        },
        "course": {
            "id": field(&course, "id"),
            "name": field(&course, "name"),
            "course_code": field(&course, "course_code"),
            "sis_course_id": field(&course, "sis_course_id"),
        },
        "learner": {
            "id": field(&user, "id"),
            "name": field(&user, "name"),
            "login_id": field(&user, "login_id"),
        },
        "enrollment": enrollment,
        "external_tool": {
            "id": field(&external_tool["tool"], "id"),
            "name": field(&external_tool["tool"], "name"),
            "deployment_id": field(&external_tool["tool"], "deployment_id"),
            "action": field(&external_tool, "action"),
        }
    });
    if !launch_surface.is_null() {
        summary["launch_surface"] = launch_surface;
    }
    if !quiz_surface.is_null() {
        summary["quiz"] = quiz_surface;
    }
    Ok(CanvasLmsSeedResult { summary })
}

#[cfg(test)]
mod tests {
    use super::rest_error;
    use crate::CanvasRestError;

    #[test]
    fn canvas_http_error_does_not_echo_learner_password() {
        let error = CanvasRestError::Http(422, "pseudonym[password]=private-value".into());
        assert_eq!(rest_error(error), "Canvas REST request failed (422)");
    }
}
