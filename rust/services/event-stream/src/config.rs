use std::{collections::HashMap, env, fs, net::SocketAddr};
use tonic::metadata::AsciiMetadataValue;

const DEFAULT_HTTP_PORT: u16 = 8015;
const DEFAULT_GRPC_PORT: u16 = 9015;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub http_addr: SocketAddr,
    pub grpc_addr: SocketAddr,
    pub grpc_enabled: bool,
    pub grpc_server_tls: Option<GrpcServerTls>,
    pub service_token: Option<String>,
    pub service_authentication_required: bool,
}

pub use marty_service_runtime::GrpcServerTls;

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let mut values = env::vars().collect::<HashMap<_, _>>();
        if let Some(file) = value(&values, "GRPC_SERVICE_TOKEN_FILE").map(str::to_owned) {
            if value(&values, "GRPC_SERVICE_TOKEN").is_some() {
                return Err("GRPC_SERVICE_TOKEN and GRPC_SERVICE_TOKEN_FILE conflict".into());
            }
            let token = fs::read_to_string(file)
                .map_err(|_| "GRPC_SERVICE_TOKEN_FILE could not be read")?;
            values.insert("GRPC_SERVICE_TOKEN".into(), token.trim().into());
        }
        Self::from_values(&values)
    }

    fn from_values(values: &HashMap<String, String>) -> Result<Self, String> {
        let http_port = parse_port(values, "EVENT_STREAM_SERVICE_PORT", DEFAULT_HTTP_PORT)?;
        let grpc_port = parse_port(values, "EVENT_STREAM_GRPC_PORT", DEFAULT_GRPC_PORT)?;
        let grpc_enabled = parse_bool(values, "EVENT_STREAM_GRPC_ENABLED", true)?;
        let environment = value(values, "ENVIRONMENT")
            .unwrap_or("development")
            .to_ascii_lowercase();
        let deployed = match environment.as_str() {
            "development" | "dev" | "local" | "test" => false,
            "beta" | "production" | "prod" => true,
            _ => return Err("ENVIRONMENT is invalid".into()),
        };
        let service_token = value(values, "GRPC_SERVICE_TOKEN").map(str::to_owned);
        if deployed && grpc_enabled && service_token.is_none() {
            return Err("deployed Event Stream gRPC requires GRPC_SERVICE_TOKEN".into());
        }
        if service_token.as_ref().is_some_and(|token| token.len() < 32) {
            return Err("GRPC_SERVICE_TOKEN must have at least 32 characters".into());
        }
        if service_token
            .as_deref()
            .is_some_and(|token| AsciiMetadataValue::try_from(token).is_err())
        {
            return Err("GRPC_SERVICE_TOKEN is not valid gRPC metadata".into());
        }
        if values.contains_key("GRPC_WORKLOAD_TLS_SERVER_KEY") {
            return Err("GRPC_WORKLOAD_TLS_SERVER_KEY is retired".into());
        }
        let grpc_server_tls = marty_service_runtime::GrpcServerTls::from_values(
            |name| values.get(name).map(String::as_str),
            marty_service_runtime::TlsIdentityNames::new("GRPC_WORKLOAD_TLS_SERVER"),
            std::time::Duration::from_secs(10),
            64,
        )?;
        if deployed && grpc_enabled && grpc_server_tls.is_none() {
            return Err("deployed Event Stream gRPC requires a remote KMS TLS identity".into());
        }
        if http_port == grpc_port {
            return Err("Event Stream HTTP and gRPC ports must differ".into());
        }
        Ok(Self {
            http_addr: SocketAddr::from(([0, 0, 0, 0], http_port)),
            grpc_addr: SocketAddr::from(([0, 0, 0, 0], grpc_port)),
            grpc_enabled,
            grpc_server_tls,
            service_token,
            service_authentication_required: deployed && grpc_enabled,
        })
    }
}

fn value<'a>(values: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    values
        .get(name)
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn parse_bool(values: &HashMap<String, String>, name: &str, default: bool) -> Result<bool, String> {
    match value(values, name) {
        Some(value) if value.eq_ignore_ascii_case("true") => Ok(true),
        Some(value) if value.eq_ignore_ascii_case("false") => Ok(false),
        Some(_) => Err(format!("{name} must be true or false")),
        None => Ok(default),
    }
}

fn parse_port(values: &HashMap<String, String>, name: &str, default: u16) -> Result<u16, String> {
    match value(values, name) {
        Some(value) => value
            .parse::<u16>()
            .ok()
            .filter(|port| *port > 0)
            .ok_or_else(|| format!("{name} must be a valid TCP port")),
        None => Ok(default),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_deployed_contract() {
        assert_eq!(DEFAULT_HTTP_PORT, 8015);
        assert_eq!(DEFAULT_GRPC_PORT, 9015);
    }

    #[test]
    fn deployed_listener_requires_remote_signer_and_rejects_key_files() {
        let mut values = HashMap::from([("ENVIRONMENT".into(), "production".into())]);
        assert!(Config::from_values(&values).is_err());
        values.insert("GRPC_SERVICE_TOKEN".into(), "s".repeat(32));
        values.insert("GRPC_WORKLOAD_TLS_SERVER_KEY".into(), "retired.pem".into());
        assert!(Config::from_values(&values)
            .unwrap_err()
            .contains("retired"));
        values.remove("GRPC_WORKLOAD_TLS_SERVER_KEY");
        for (name, value) in [
            ("GRPC_WORKLOAD_TLS_SERVER_CERT", "public.pem"),
            (
                "GRPC_WORKLOAD_TLS_SERVER_KMS_ADDR",
                "https://bao.internal:8200",
            ),
            ("GRPC_WORKLOAD_TLS_SERVER_KMS_CA_CERT", "ca.pem"),
            ("GRPC_WORKLOAD_TLS_SERVER_KMS_TOKEN_FILE", "token"),
            (
                "GRPC_WORKLOAD_TLS_SERVER_KMS_KEY_NAME",
                "event-stream-server",
            ),
            ("GRPC_WORKLOAD_TLS_SERVER_KMS_KEY_VERSION", "1"),
        ] {
            values.insert(name.into(), value.into());
        }
        assert!(Config::from_values(&values)
            .unwrap()
            .grpc_server_tls
            .is_some());
        values.insert(
            "GRPC_WORKLOAD_TLS_SERVER_KMS_ADDR".into(),
            "http://bao.internal:8200".into(),
        );
        assert!(Config::from_values(&values).is_err());
        values.insert(
            "GRPC_WORKLOAD_TLS_SERVER_KMS_ADDR".into(),
            "https://bao.internal:8200".into(),
        );
        values.insert("ENVIRONMENT".into(), "unrecognized".into());
        assert!(Config::from_values(&values).is_err());
    }
}
