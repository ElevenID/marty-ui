//! Standard AGS line-item metadata, requested only by configured claim rules.
use super::*;

pub(super) const LINE_ITEM_READ_SCOPE: &str =
    "https://purl.imsglobal.org/spec/lti-ags/scope/lineitem.readonly";
pub(super) const LINE_ITEM_ACCEPT: &str = "application/vnd.ims.lis.v2.lineitem+json";
const LINE_ITEM_BYTES: usize = 65_536;

pub(super) fn results_url(line_item: &str) -> Result<String, CanvasProviderReadError> {
    let mut url =
        Url::parse(line_item).map_err(|_| CanvasProviderReadError::InvalidConfiguration)?;
    url.set_path(&format!("{}/results", url.path().trim_end_matches('/')));
    Ok(url.into())
}

pub(super) fn activity_name_requested(
    resources: &CanvasSyncResources,
    requirement: &Value,
) -> bool {
    resources
        .application_template
        .as_ref()
        .and_then(|template| template.get("claim_collection_rules"))
        .and_then(Value::as_array)
        .is_some_and(|rules| {
            marty_claim_collection::evidence_pointer_requested(
                rules,
                requirement,
                "/assertion/activity_name",
            )
        })
}

pub(super) fn validate_result_binding(
    records: &[Value],
    line_item: &str,
    subject: &str,
) -> Result<(), CanvasProviderReadError> {
    if records.len() > 1 {
        return Err(CanvasProviderReadError::Unavailable);
    }
    let Some(record) = records.first() else {
        // An empty authenticated result collection is verified negative evidence.
        return Ok(());
    };
    if record.get("userId").and_then(Value::as_str) != Some(subject)
        || record.get("scoreOf").and_then(Value::as_str) != Some(line_item)
    {
        return Err(CanvasProviderReadError::Unavailable);
    }
    Ok(())
}

impl HttpCanvasAuthoritativeProvider {
    pub(super) async fn read_ags_activity_name(
        &self,
        resources: &CanvasSyncResources,
        line_item: &str,
    ) -> Result<String, CanvasProviderReadError> {
        let validated =
            validate_canvas_lti_service_url(line_item, &self.policy.private_origin_allowlist)
                .await
                .map_err(|_| CanvasProviderReadError::InvalidConfiguration)?;
        self.enforce_lti_service_trust(resources, &validated)?;
        let url =
            Url::parse(&validated).map_err(|_| CanvasProviderReadError::InvalidConfiguration)?;
        reject_embedded_credentials(&url)?;
        let token = self
            .lti_access_token(resources, LtiCollectionKind::AgsLineItem)
            .await?;
        let (client, _) = client_for_canvas_origin(origin_url(&url)?.as_str(), &self.policy)
            .await
            .map_err(|_| CanvasProviderReadError::InvalidConfiguration)?;
        read_line_item_name(&RestReadClient::Total(client), url, &token).await
    }
}

async fn read_line_item_name(
    client: &RestReadClient,
    url: Url,
    token: &str,
) -> Result<String, CanvasProviderReadError> {
    let response = client
        .get_accept(url.clone(), token, LINE_ITEM_ACCEPT)
        .await?;
    let item = read_json_response(response, LINE_ITEM_BYTES).await?;
    if item.get("id").and_then(Value::as_str) != Some(url.as_str()) {
        return Err(CanvasProviderReadError::Unavailable);
    }
    item.get("label")
        .and_then(Value::as_str)
        .filter(|name| !name.trim().is_empty() && name.len() <= 4096)
        .map(str::to_owned)
        .ok_or(CanvasProviderReadError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ags_results_preserve_route_query_and_bind_the_selected_learner() {
        let item = "https://canvas.example/api/lti/courses/1/line_items/2?resource=owned";
        assert_eq!(
            results_url(item).unwrap(),
            "https://canvas.example/api/lti/courses/1/line_items/2/results?resource=owned"
        );
        let result = json!({"userId":"learner-7","scoreOf":item,"resultScore":95});
        assert_eq!(
            validate_result_binding(std::slice::from_ref(&result), item, "learner-7"),
            Ok(())
        );
        assert_eq!(validate_result_binding(&[], item, "learner-7"), Ok(()));
        assert_eq!(
            validate_result_binding(&[json!({})], item, "learner-7"),
            Err(CanvasProviderReadError::Unavailable)
        );
        assert_eq!(
            validate_result_binding(&[result.clone(), result.clone()], item, "learner-7"),
            Err(CanvasProviderReadError::Unavailable)
        );
        for field in ["userId", "scoreOf"] {
            let mut foreign = result.clone();
            foreign[field] = json!("foreign");
            assert_eq!(
                validate_result_binding(std::slice::from_ref(&foreign), item, "learner-7"),
                Err(CanvasProviderReadError::Unavailable)
            );
            foreign.as_object_mut().unwrap().remove(field);
            assert_eq!(
                validate_result_binding(std::slice::from_ref(&foreign), item, "learner-7"),
                Err(CanvasProviderReadError::Unavailable)
            );
        }
    }

    async fn label_fixture(
        change: impl FnOnce(&mut Value),
    ) -> Result<String, CanvasProviderReadError> {
        use axum::{
            extract::{Form, State},
            http::HeaderMap,
            routing::{get, post},
            Json, Router,
        };
        async fn grant(Form(form): Form<BTreeMap<String, String>>) -> Json<Value> {
            assert_eq!(form["scope"], LINE_ITEM_READ_SCOPE);
            assert_eq!(form["grant_type"], "client_credentials");
            Json(json!({"access_token":"synthetic-lineitem-token"}))
        }
        async fn item(State(body): State<Value>, headers: HeaderMap) -> Json<Value> {
            assert_eq!(headers["accept"], LINE_ITEM_ACCEPT);
            assert_eq!(headers["authorization"], "Bearer synthetic-lineitem-token");
            Json(body)
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let url = Url::parse(&format!("{origin}/lineitem")).unwrap();
        let mut body = json!({"id":url.as_str(),"label":"Authentic Canvas activity",
            "scoreMaximum":100,"provider_private":"SYNTHETIC_NOT_RETAINED"});
        change(&mut body);
        let app = Router::new()
            .route("/token", post(grant))
            .route("/lineitem", get(item))
            .with_state(body);
        let server = tokio::spawn(async move { axum::serve(listener, app).await });
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let token = request_lti_token(
            &client,
            Url::parse(&format!("{origin}/token")).unwrap(),
            "synthetic-client",
            "synthetic-assertion",
            LtiCollectionKind::AgsLineItem.scope(),
        )
        .await
        .unwrap();
        let result = read_line_item_name(&RestReadClient::Total(client), url, &token).await;
        server.abort();
        result
    }

    #[tokio::test]
    async fn ags_lineitem_uses_readonly_grant_and_standard_media_type() {
        assert_eq!(
            label_fixture(|_| {}).await.unwrap(),
            "Authentic Canvas activity"
        );
    }

    #[tokio::test]
    async fn ags_lineitem_rejects_foreign_identity_and_unusable_labels() {
        assert_eq!(
            label_fixture(|body| body["id"] = json!("https://foreign.example/lineitem")).await,
            Err(CanvasProviderReadError::Unavailable)
        );
        for label in [
            Value::Null,
            json!("  "),
            json!({"not":"text"}),
            json!("x".repeat(4097)),
        ] {
            assert_eq!(
                label_fixture(|body| body["label"] = label).await,
                Err(CanvasProviderReadError::Unavailable)
            );
        }
    }
}
