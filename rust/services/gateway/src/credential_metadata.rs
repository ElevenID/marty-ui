//! Public credential type metadata and badge assets.

use serde_json::{json, Value};

pub const MARTY_BADGE_SLUG: &str = "marty-verified-member-badge";
pub const CANVAS_BADGE_SLUG: &str = "canvas-interoperability-foundations-badge";

const MARTY_NAME: &str = "Marty Verified Member Badge";
const MARTY_DESCRIPTION: &str = "Verified membership credential issued by Marty Identity Platform for secure passwordless sign-in.";
const CANVAS_NAME: &str = "Interoperable Credentials Foundations Badge";
const CANVAS_DESCRIPTION: &str = "Open Badge 3.0 credential for completing the Interoperable Credentials Foundations learning check in Canvas.";
const CANVAS_CRITERIA: &str = "Complete the Canvas learning activity and earn the configured passing score on the interoperability quiz. ElevenID issues the credential from the Marty organization using the canonical DID issuer and remote signing service.";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialMetadataResponse {
    pub content_type: &'static str,
    pub cache_control: &'static str,
    pub body: Vec<u8>,
}

pub fn response(path: &str, base_url: &str) -> Option<CredentialMetadataResponse> {
    let base_url = base_url.trim_end_matches('/');
    let json = match path {
        "/credentials/marty-verified-member-badge"
        | "/.well-known/vct/credentials/marty-verified-member-badge" => {
            Some(marty_metadata(base_url))
        }
        "/credentials/canvas-interoperability-foundations-badge"
        | "/.well-known/vct/credentials/canvas-interoperability-foundations-badge" => {
            Some(canvas_metadata(base_url))
        }
        "/credentials/canvas-interoperability-foundations-badge/criteria" => {
            Some(canvas_criteria(base_url))
        }
        _ => None,
    };
    if let Some(json) = json {
        return Some(CredentialMetadataResponse {
            content_type: "application/json",
            cache_control: "public, max-age=300",
            body: serde_json::to_vec(&json).expect("static metadata serializes"),
        });
    }
    let svg = match path {
        "/credentials/marty-verified-member-badge/image.svg" => Some(MARTY_SVG),
        "/credentials/canvas-interoperability-foundations-badge/image.svg" => Some(CANVAS_SVG),
        _ => None,
    }?;
    Some(CredentialMetadataResponse {
        content_type: "image/svg+xml",
        cache_control: "public, max-age=86400",
        body: svg.as_bytes().to_vec(),
    })
}

fn credential_url(base_url: &str, slug: &str, suffix: &str) -> String {
    format!("{base_url}/credentials/{slug}{suffix}")
}

fn display(base_url: &str, slug: &str, name: &str, description: &str, background: &str) -> Value {
    let logo = json!({
        "uri": credential_url(base_url, slug, "/image.svg"),
        "alt_text": name,
    });
    json!({
        "lang": "en-US",
        "locale": "en-US",
        "name": name,
        "description": description,
        "background_color": background,
        "text_color": "#FFFFFF",
        "logo": logo,
        "rendering": {"simple": {
            "logo": logo,
            "background_color": background,
            "text_color": "#FFFFFF"
        }}
    })
}

fn claim(path: &str, name: &str, disclosure: &str) -> Value {
    json!({
        "path": [path],
        "display": [{"lang": "en-US", "name": name}],
        "sd": disclosure,
    })
}

fn marty_metadata(base_url: &str) -> Value {
    json!({
        "vct": credential_url(base_url, MARTY_BADGE_SLUG, ""),
        "name": MARTY_NAME,
        "description": MARTY_DESCRIPTION,
        "display": [display(base_url, MARTY_BADGE_SLUG, MARTY_NAME, MARTY_DESCRIPTION, "#3B1C8F")],
        "claims": [
            claim("email", "Email Address", "always"),
            claim("member_id", "Member ID", "always"),
            claim("organization_name", "Organization", "allowed"),
            claim("role", "Role", "always"),
            claim("achievement_name", "Badge Name", "never")
        ]
    })
}

fn canvas_metadata(base_url: &str) -> Value {
    let base = credential_url(base_url, CANVAS_BADGE_SLUG, "");
    json!({
        "vct": base,
        "name": CANVAS_NAME,
        "description": CANVAS_DESCRIPTION,
        "display": [display(base_url, CANVAS_BADGE_SLUG, CANVAS_NAME, CANVAS_DESCRIPTION, "#0B5F7A")],
        "open_badges": {
            "version": "3.0",
            "achievement": {
                "id": format!("{base}#achievement"),
                "type": ["Achievement"],
                "name": CANVAS_NAME,
                "description": CANVAS_DESCRIPTION,
                "criteria": {"id": format!("{base}/criteria"), "narrative": CANVAS_CRITERIA},
                "image": {"id": format!("{base}/image.svg"), "type": "Image", "caption": CANVAS_NAME},
                "alignment": [
                    {"targetName": "Open Badges 3.0", "targetDescription": "Portable achievement credential carried as a verifiable credential."},
                    {"targetName": "Marty Identity Protocol", "targetDescription": "MIP-governed issuance, status-list allocation, and destination projection."}
                ]
            }
        },
        "claims": [
            claim("email", "Learner Email", "always"),
            claim("given_name", "Given Name", "always"),
            claim("family_name", "Family Name", "always"),
            claim("achievement", "Achievement", "never"),
            claim("result", "Canvas Quiz Result", "allowed"),
            claim("learning_context", "Canvas Learning Context", "allowed"),
            claim("credentialStatus", "Credential Status", "never")
        ]
    })
}

fn canvas_criteria(base_url: &str) -> Value {
    json!({
        "id": credential_url(base_url, CANVAS_BADGE_SLUG, "/criteria"),
        "type": ["Criteria"],
        "name": "Interoperable Credentials Foundations criteria",
        "narrative": CANVAS_CRITERIA
    })
}

const CANVAS_SVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" width="512" height="512" viewBox="0 0 512 512" role="img" aria-label="Interoperable Credentials Foundations Badge">
  <defs>
    <linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#0B5F7A"/>
      <stop offset="100%" stop-color="#16213E"/>
    </linearGradient>
  </defs>
  <rect width="512" height="512" rx="72" fill="url(#g)"/>
  <circle cx="256" cy="186" r="86" fill="#FFFFFF" opacity=".14"/>
  <path d="M256 92l112 64v128l-112 64-112-64V156l112-64z" fill="none" stroke="#FFFFFF" stroke-width="22" stroke-linejoin="round"/>
  <path d="M206 260l-34-34-24 24 58 58 120-120-24-24-96 96z" fill="#FFFFFF"/>
  <text x="256" y="404" text-anchor="middle" font-family="Inter, Segoe UI, Arial, sans-serif" font-size="39" font-weight="800" fill="#FFFFFF">INTEROPERABLE</text>
  <text x="256" y="446" text-anchor="middle" font-family="Inter, Segoe UI, Arial, sans-serif" font-size="30" font-weight="700" fill="#D7F8FF">CREDENTIALS</text>
</svg>"##;

const MARTY_SVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" width="512" height="512" viewBox="0 0 512 512" role="img" aria-label="Marty Verified Member Badge">
  <defs>
    <linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#6A3CFF"/>
      <stop offset="100%" stop-color="#241057"/>
    </linearGradient>
  </defs>
  <rect width="512" height="512" rx="96" fill="url(#g)"/>
  <path d="M256 76l142 54v112c0 87-58 153-142 194-84-41-142-107-142-194V130l142-54z" fill="#fff" opacity=".14"/>
  <path d="M221 282l-47-47-32 32 79 79 158-158-32-32-126 126z" fill="#fff"/>
  <text x="256" y="410" text-anchor="middle" font-family="Inter, Segoe UI, Arial, sans-serif" font-size="44" font-weight="800" fill="#fff">MARTY</text>
  <text x="256" y="452" text-anchor="middle" font-family="Inter, Segoe UI, Arial, sans-serif" font-size="26" font-weight="700" fill="#E9E1FF">VERIFIED MEMBER</text>
</svg>"##;

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use sha2::{Digest, Sha256};

    #[derive(Deserialize)]
    struct Contract {
        schema_version: u32,
        base_url: String,
        json_cases: Vec<JsonCase>,
        svg_cases: Vec<SvgCase>,
    }

    #[derive(Deserialize)]
    struct JsonCase {
        paths: Vec<String>,
        cache_control: String,
        expected: Value,
    }

    #[derive(Deserialize)]
    struct SvgCase {
        path: String,
        cache_control: String,
        length: usize,
        sha256: String,
    }

    #[test]
    fn language_neutral_credential_metadata_contract() {
        let contract: Contract = serde_json::from_str(include_str!(
            "../../../../contracts/credential-metadata-behavior.json"
        ))
        .expect("valid credential metadata contract");
        assert_eq!(contract.schema_version, 1);
        for case in contract.json_cases {
            for path in case.paths {
                let response = response(&path, &contract.base_url).expect("response");
                assert_eq!(response.content_type, "application/json");
                assert_eq!(response.cache_control, case.cache_control);
                assert_eq!(
                    serde_json::from_slice::<Value>(&response.body).expect("JSON"),
                    case.expected
                );
            }
        }
        for case in contract.svg_cases {
            let response = response(&case.path, &contract.base_url).expect("response");
            assert_eq!(response.content_type, "image/svg+xml");
            assert_eq!(response.cache_control, case.cache_control);
            assert_eq!(response.body.len(), case.length);
            assert_eq!(format!("{:x}", Sha256::digest(&response.body)), case.sha256);
        }
    }
}
