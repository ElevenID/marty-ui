use std::{env, net::SocketAddr};

const DEFAULT_HTTP_PORT: u16 = 8015;
const DEFAULT_GRPC_PORT: u16 = 9015;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub http_addr: SocketAddr,
    pub grpc_addr: SocketAddr,
    pub grpc_enabled: bool,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let http_port = parse_port("EVENT_STREAM_SERVICE_PORT", DEFAULT_HTTP_PORT)?;
        let grpc_port = parse_port("EVENT_STREAM_GRPC_PORT", DEFAULT_GRPC_PORT)?;
        let grpc_enabled = parse_bool("EVENT_STREAM_GRPC_ENABLED", true)?;
        Ok(Self {
            http_addr: SocketAddr::from(([0, 0, 0, 0], http_port)),
            grpc_addr: SocketAddr::from(([0, 0, 0, 0], grpc_port)),
            grpc_enabled,
        })
    }
}

fn parse_bool(name: &str, default: bool) -> Result<bool, String> {
    match env::var(name) {
        Ok(value) if value.eq_ignore_ascii_case("true") => Ok(true),
        Ok(value) if value.eq_ignore_ascii_case("false") => Ok(false),
        Ok(_) => Err(format!("{name} must be true or false")),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(env::VarError::NotUnicode(_)) => Err(format!("{name} must be valid Unicode")),
    }
}

fn parse_port(name: &str, default: u16) -> Result<u16, String> {
    match env::var(name) {
        Ok(value) => value
            .parse::<u16>()
            .map_err(|_| format!("{name} must be a valid TCP port")),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(env::VarError::NotUnicode(_)) => Err(format!("{name} must be valid Unicode")),
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
}
