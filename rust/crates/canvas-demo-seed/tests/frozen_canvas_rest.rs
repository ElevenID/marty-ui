use async_trait::async_trait;
use marty_canvas_demo_seed::{
    ensure_course, ensure_enrollment, ensure_external_tool_assignment, ensure_module,
    ensure_module_external_tool_item, ensure_module_quiz_item, ensure_quiz, ensure_user,
    CanvasOperation, CanvasRestConfig, CanvasRestError, CanvasRestTransport,
};
use serde_json::{json, Value};
use std::{collections::VecDeque, sync::Mutex};

struct Stub {
    responses: Mutex<VecDeque<Result<Value, CanvasRestError>>>,
    operations: Mutex<Vec<Value>>,
}

#[async_trait]
impl CanvasRestTransport for Stub {
    async fn request(&self, operation: CanvasOperation) -> Result<Value, CanvasRestError> {
        self.operations.lock().unwrap().push(json!({
            "method": operation.method,
            "url": operation.url,
            "payload": null,
            "form": operation.form
        }));
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected Canvas REST operation")
    }
}

fn cfg() -> CanvasRestConfig {
    CanvasRestConfig {
        api_base_url: "http://canvas:8088".into(),
        account_id: "1".into(),
        course_name: "Marty Course".into(),
        course_code: "MARTY-101".into(),
        course_sis_id: "marty-course".into(),
        learner_name: "Test Learner".into(),
        learner_email: "learner@example.com".into(),
        learner_password: "test-learner-password".into(),
        launch_module_name: "Credential Launch".into(),
        launch_item_title: "Launch Credential".into(),
        launch_assignment_name: "Credential Assignment".into(),
        quiz_title: "Credential Quiz".into(),
        quiz_description: "Quiz description".into(),
        quiz_points_possible: 100,
    }
}

#[tokio::test]
async fn canvas_launch_surface_create_and_repeat_match_frozen_python() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-real-seed-behavior-v1.json"
    ))
    .unwrap();
    let frozen = &contract["canvas_launch_surface_rest"];
    let responses = vec![
        json!([]),
        frozen["created"]["module"]["module"].clone(),
        json!([]),
        frozen["created"]["tool_item"]["item"].clone(),
        json!([]),
        frozen["created"]["quiz"]["quiz"].clone(),
        json!([]),
        frozen["created"]["quiz_item"]["item"].clone(),
        json!([]),
        frozen["created"]["assignment"]["assignment"].clone(),
        json!([frozen["existing"]["module"]["module"]]),
        json!([{"id": 11, "title": "Launch Credential", "url": "https://stale.example/launch", "published": false}]),
        frozen["existing"]["tool_item"]["item"].clone(),
        json!([frozen["existing"]["quiz"]["quiz"]]),
        json!([frozen["existing"]["quiz_item"]["item"]]),
        json!([frozen["existing"]["assignment"]["assignment"]]),
        frozen["existing"]["assignment"]["assignment"].clone(),
    ];
    let stub = Stub {
        responses: Mutex::new(responses.into_iter().map(Ok).collect()),
        operations: Mutex::new(Vec::new()),
    };
    let cfg = cfg();
    let launch_url = "https://marty.example/launch";
    for (mode, expected) in [
        ("created", &frozen["created"]),
        ("existing", &frozen["existing"]),
    ] {
        assert_eq!(
            ensure_module(&stub, &cfg, "42").await.unwrap(),
            expected["module"],
            "{mode}"
        );
        assert_eq!(
            ensure_module_external_tool_item(&stub, &cfg, "42", "10", launch_url, Some("99"))
                .await
                .unwrap(),
            expected["tool_item"],
            "{mode}"
        );
        assert_eq!(
            ensure_quiz(&stub, &cfg, "42").await.unwrap(),
            expected["quiz"],
            "{mode}"
        );
        assert_eq!(
            ensure_module_quiz_item(&stub, &cfg, "42", "10", "12")
                .await
                .unwrap(),
            expected["quiz_item"],
            "{mode}"
        );
        assert_eq!(
            ensure_external_tool_assignment(&stub, &cfg, "42", launch_url)
                .await
                .unwrap(),
            expected["assignment"],
            "{mode}"
        );
    }
    assert_eq!(
        json!(*stub.operations.lock().unwrap()),
        frozen["operations"]
    );
}

#[tokio::test]
async fn canvas_core_create_and_repeat_match_frozen_python() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-real-seed-behavior-v1.json"
    ))
    .unwrap();
    let frozen = &contract["canvas_core_rest"];
    let responses = vec![
        json!([]),
        frozen["created"]["course"].clone(),
        json!([]),
        json!([frozen["created"]["learner"]]),
        json!([]),
        frozen["created"]["enrollment"].clone(),
        json!([frozen["existing"]["course"]]),
        json!([frozen["existing"]["learner"]]),
        json!([frozen["existing"]["enrollment"]]),
    ];
    let stub = Stub {
        responses: Mutex::new(responses.into_iter().map(Ok).collect()),
        operations: Mutex::new(Vec::new()),
    };
    let cfg = cfg();
    assert_eq!(
        ensure_course(&stub, &cfg).await.unwrap(),
        frozen["created"]["course"]
    );
    assert_eq!(
        ensure_user(&stub, &cfg).await.unwrap(),
        frozen["created"]["learner"]
    );
    assert_eq!(
        ensure_enrollment(&stub, &cfg, "42", "77").await.unwrap(),
        frozen["created"]["enrollment"]
    );
    assert_eq!(
        ensure_course(&stub, &cfg).await.unwrap(),
        frozen["existing"]["course"]
    );
    assert_eq!(
        ensure_user(&stub, &cfg).await.unwrap(),
        frozen["existing"]["learner"]
    );
    assert_eq!(
        ensure_enrollment(&stub, &cfg, "42", "77").await.unwrap(),
        frozen["existing"]["enrollment"]
    );
    assert_eq!(
        json!(*stub.operations.lock().unwrap()),
        frozen["operations"]
    );
}

#[tokio::test]
async fn canvas_list_http_failure_creates_but_transport_failure_stops() {
    let stub = Stub {
        responses: Mutex::new(VecDeque::from(vec![
            Err(CanvasRestError::Http(404, "missing".into())),
            Ok(json!({"id": 42})),
        ])),
        operations: Mutex::new(Vec::new()),
    };
    ensure_course(&stub, &cfg()).await.unwrap();
    assert_eq!(stub.operations.lock().unwrap().len(), 2);
    let stub = Stub {
        responses: Mutex::new(VecDeque::from(vec![Err(CanvasRestError::Other(
            "connection failed".into(),
        ))])),
        operations: Mutex::new(Vec::new()),
    };
    assert_eq!(
        ensure_course(&stub, &cfg()).await.unwrap_err(),
        CanvasRestError::Other("connection failed".into())
    );
    assert_eq!(stub.operations.lock().unwrap().len(), 1);
}
