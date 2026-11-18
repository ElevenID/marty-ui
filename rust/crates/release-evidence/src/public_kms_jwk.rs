//! Convert a KMS public SPKI PEM to a public JWK for release-only fixtures.

use std::io::{self, Read};

fn main() {
    let mut pem = String::new();
    if io::stdin()
        .take(16 * 1024 + 1)
        .read_to_string(&mut pem)
        .is_err()
        || pem.len() > 16 * 1024
    {
        eprintln!("invalid bounded public key input");
        std::process::exit(1);
    }
    let jwk = marty_crypto::jwk::public_key_pem_to_jwk(&pem).and_then(|key| key.to_json());
    match jwk {
        Ok(json) => println!("{json}"),
        Err(_) => {
            eprintln!("public key is not a supported SPKI PEM");
            std::process::exit(1);
        }
    }
}
