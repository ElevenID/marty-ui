//! Public credential type metadata and badge assets.

use serde_json::{json, Value};

pub const MARTY_BADGE_SLUG: &str = "marty-verified-member-badge";

const MARTY_NAME: &str = "Marty Verified Member Badge";
const MARTY_DESCRIPTION: &str = "Verified membership credential issued by Marty Identity Platform for secure passwordless sign-in.";

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
    fn retired_provider_badge_assets_are_not_platform_metadata() {
        for path in [
            "/credentials/canvas-interoperability-foundations-badge",
            "/.well-known/vct/credentials/canvas-interoperability-foundations-badge",
            "/credentials/canvas-interoperability-foundations-badge/criteria",
            "/credentials/canvas-interoperability-foundations-badge/image.svg",
        ] {
            assert!(response(path, "https://issuer.example").is_none(), "{path}");
        }
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
