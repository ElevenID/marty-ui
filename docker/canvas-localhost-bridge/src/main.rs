use axum::body::{to_bytes, Body};
use axum::extract::State;
use axum::http::{header, HeaderMap, Method, Request, Response, StatusCode};
use axum::routing::any;
use axum::Router;
use serde_json::{json, Value};
use std::env;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone)]
struct Bridge {
    upstream_base: String,
    discovery: Value,
    client: reqwest::Client,
}

const DISCOVERY_PATH: &str = "/.well-known/openid-configuration";
const ERROR_PREFIX: &str = "Canvas localhost bridge upstream failure: ";

fn env_base(name: &str, default: &str) -> String {
    env::var(name)
        .unwrap_or_else(|_| default.to_owned())
        .trim_end_matches('/')
        .to_owned()
}

fn discovery(public_base: &str) -> Value {
    json!({
        "issuer": public_base,
        "authorization_endpoint": format!("{public_base}/api/lti/authorize_redirect"),
        "token_endpoint": format!("{public_base}/login/oauth2/token"),
        "jwks_uri": format!("{public_base}/api/lti/security/jwks"),
        "registration_endpoint": format!("{public_base}/api/lti/registrations"),
        "scopes_supported": ["openid"],
        "response_types_supported": ["id_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "claims_supported": [
            "iss", "sub", "aud", "exp", "iat", "nonce",
            "https://purl.imsglobal.org/spec/lti/claim/deployment_id",
            "https://purl.imsglobal.org/spec/lti/claim/context",
            "https://purl.imsglobal.org/spec/lti/claim/roles",
            "https://purl.imsglobal.org/spec/lti/claim/message_type",
            "https://purl.imsglobal.org/spec/lti/claim/version",
            "https://purl.imsglobal.org/spec/lti/claim/target_link_uri"
        ]
    })
}

fn hop_by_hop(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn json_response(status: StatusCode, payload: &Value, send_body: bool) -> Response<Body> {
    let bytes = serde_json::to_vec(payload).expect("JSON object serializes");
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            header::CONTENT_LENGTH,
            if send_body { bytes.len() } else { 0 }.to_string(),
        )
        .body(if send_body {
            Body::from(bytes)
        } else {
            Body::empty()
        })
        .expect("static response headers are valid")
}

async fn handle(State(state): State<Arc<Bridge>>, request: Request<Body>) -> Response<Body> {
    let method = request.method().clone();
    if !matches!(
        method,
        Method::GET | Method::HEAD | Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    ) {
        return Response::builder()
            .status(StatusCode::NOT_IMPLEMENTED)
            .header(header::CONTENT_LENGTH, "0")
            .body(Body::empty())
            .expect("static response headers are valid");
    }
    let send_body = method != Method::HEAD;
    if (method == Method::GET || method == Method::HEAD) && request.uri().path() == DISCOVERY_PATH {
        return json_response(StatusCode::OK, &state.discovery, send_body);
    }

    let target = format!("{}{}", state.upstream_base, request.uri());
    let (parts, body) = request.into_parts();
    let body = match to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes,
        Err(error) => {
            return json_response(
                StatusCode::BAD_GATEWAY,
                &json!({ "error": format!("{ERROR_PREFIX}{error}") }),
                send_body,
            );
        }
    };
    let mut headers = HeaderMap::new();
    for (name, value) in &parts.headers {
        if name != header::HOST && !hop_by_hop(name.as_str()) {
            headers.append(name, value.clone());
        }
    }
    let response = state
        .client
        .request(method, target)
        .headers(headers)
        .body(body)
        .send()
        .await;
    let response = match response {
        Ok(response) => response,
        Err(error) => {
            return json_response(
                StatusCode::BAD_GATEWAY,
                &json!({ "error": format!("{ERROR_PREFIX}{error}") }),
                send_body,
            );
        }
    };
    let status = response.status();
    let response_headers = response.headers().clone();
    let body = match response.bytes().await {
        Ok(bytes) => bytes,
        Err(error) => {
            return json_response(
                StatusCode::BAD_GATEWAY,
                &json!({ "error": format!("{ERROR_PREFIX}{error}") }),
                send_body,
            );
        }
    };
    let mut builder = Response::builder().status(status);
    for (name, value) in &response_headers {
        if !hop_by_hop(name.as_str()) && name != header::CONTENT_LENGTH {
            builder = builder.header(name, value);
        }
    }
    builder
        .header(
            header::CONTENT_LENGTH,
            if send_body { body.len() } else { 0 }.to_string(),
        )
        .body(if send_body {
            Body::from(body)
        } else {
            Body::empty()
        })
        .expect("upstream headers were parsed by reqwest")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let upstream_base = env_base(
        "CANVAS_LOCALHOST_BRIDGE_UPSTREAM",
        "http://host.docker.internal:8088",
    );
    let public_base = env_base(
        "CANVAS_LOCALHOST_BRIDGE_PUBLIC_BASE",
        "http://localhost:8088",
    );
    let host =
        env::var("CANVAS_LOCALHOST_BRIDGE_LISTEN_HOST").unwrap_or_else(|_| "127.0.0.1".to_owned());
    let port: u16 = env::var("CANVAS_LOCALHOST_BRIDGE_LISTEN_PORT")
        .unwrap_or_else(|_| "8088".to_owned())
        .parse()?;
    let listener = tokio::net::TcpListener::bind((host.as_str(), port)).await?;
    let client = reqwest::Client::builder()
        // Redirects must return to the caller so Canvas credentials and cookies
        // are never replayed to a different host by this local proxy.
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()?;
    let state = Arc::new(Bridge {
        upstream_base,
        discovery: discovery(&public_base),
        client,
    });
    eprintln!(
        "[canvas-localhost-bridge] listening on {host}:{port} -> upstream {}",
        state.upstream_base
    );
    let app = Router::new().fallback(any(handle)).with_state(state);
    axum::serve(listener, app).await?;
    Ok(())
}
