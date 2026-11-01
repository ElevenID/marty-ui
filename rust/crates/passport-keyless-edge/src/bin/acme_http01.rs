//! Plain HTTP challenge service. Its startup and requests have no dependency on
//! application HTTPS, certificate validity, or an available OpenBao connection.

#[cfg(unix)]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use marty_passport_keyless_edge::{
        acme_http01::{validate_bind, AllowedIdentifiers, Responder},
        required,
    };

    let bind = validate_bind(&required("MARTY_ACME_HTTP01_BIND")?)?;
    let canonical = required("MARTY_ACME_HTTP01_CANONICAL_ORIGIN")?;
    let alias = match std::env::var("MARTY_ACME_HTTP01_PUBLIC_ENTRY_ORIGIN") {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(error) => return Err(error.into()),
    };
    let identifiers = AllowedIdentifiers::from_origins(&canonical, alias.as_deref())?;
    let directory = required("MARTY_ACME_HTTP01_DIRECTORY")?;
    let responder = Responder::open(std::path::Path::new(&directory), identifiers)?;
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, responder.router()).await?;
    Ok(())
}

#[cfg(not(unix))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    Err("marty-acme-http01 requires a Unix filesystem".into())
}
