//! Join the actual separately compiled Authenticator native test artifact.
use super::holder_issuer_authority::Owner;
use marty_device_registration::pairing_enrollment::PairingRedeemResult;
use marty_trust_profile::TrustProfileRepository;
use serde_json::{json, Value};
use std::{path::PathBuf, process::Stdio, time::Duration};

pub const CASE: &str = "operations::verified_issuance::joined_device_tests::actual_device_authority_and_remote_holder_qualify_receipt";

pub async fn run(
    owner: &mut Owner,
    device_origin: &str,
    gateway_key: &str,
    enrolled: &PairingRedeemResult,
    nonce: &str,
    fixture: &Value,
) {
    let config = PathBuf::from(std::env::var("MARTY_TEST_JOINED_WALLET_CONFIG").unwrap());
    let directory = config.parent().unwrap().to_owned();
    assert!(config.is_absolute() && config.file_name().unwrap() == "joined-fixture.json");
    assert!(fixture["nonce"].as_str() == Some(nonce));
    let executable = PathBuf::from(std::env::var("MARTY_TEST_JOINED_NATIVE_BINARY").unwrap());
    assert!(executable.is_absolute() && executable.is_file());
    assert!(executable
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("marty_authenticator_bridge-"));
    let public = &enrolled.presentation_signing_public_jwk;
    let public_only =
        json!({"kty":public["kty"],"crv":public["crv"],"x":public["x"],"y":public["y"]});
    std::fs::write(
        directory.join("holder.json"),
        json!({"nonce":nonce,"public_jwk":public_only}).to_string(),
    )
    .unwrap();
    let input = directory.join("native-input.json");
    assert!(!input.exists());
    std::fs::write(
        &input,
        json!({"nonce":nonce,"device_origin":device_origin,"device_service_token":gateway_key,
        "device_bearer":enrolled.device_credential,"holder_public_jwk":public})
        .to_string(),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&input, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    std::fs::write(directory.join("device-ca.pem"), &owner.ca).unwrap();
    let mut roots = owner.ca.clone();
    // Bao's public PEM can omit its final newline. Keep certificate delimiters
    // separate when composing the native issuer/Device trust bundle.
    roots.push(b'\n');
    roots.extend(std::fs::read(fixture["issuer_ca_file"].as_str().unwrap()).unwrap());
    std::fs::write(directory.join("native-roots.pem"), roots).unwrap();
    std::fs::create_dir(directory.join("empty-roots")).unwrap();
    let output_path = directory.join("native-private-output.log");
    let output = std::fs::File::create(&output_path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        output
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .unwrap();
    }
    let repo = owner.repository.clone();
    let mut changed = owner.relationship.clone();
    let mutation_directory = directory.clone();
    let owned_nonce = nonce.to_owned();
    let mutation = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(40), async {
            loop {
                if let Ok(signal) =
                    tokio::fs::read_to_string(mutation_directory.join("native-response-ready"))
                        .await
                {
                    assert!(signal == owned_nonce);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            // Commit an actual owner service-grant change after the native
            // credential response. No response/authority fixture is substituted.
            changed.metadata["marty_wallet_issuance_authorizations_v1"][0]
                ["credential_configuration_id"] = json!("revoked-native-configuration");
            repo.save_profile_issuer(&changed).await.unwrap();
            tokio::fs::write(
                mutation_directory.join("native-authority-updated"),
                owned_nonce,
            )
            .await
            .unwrap();
        })
        .await
        .unwrap();
    });
    let mut child = tokio::process::Command::new(executable)
        .args([CASE, "--ignored", "--exact", "--nocapture"])
        .env_clear()
        .envs(std::env::vars().filter(|(name, _)| {
            matches!(
                name.as_str(),
                "PATH" | "HOME" | "LD_LIBRARY_PATH" | "TMPDIR" | "TMP" | "TEMP" | "SystemRoot"
            )
        }))
        .env("MARTY_TEST_JOINED_NATIVE_INPUT", &input)
        .env("SSL_CERT_FILE", directory.join("native-roots.pem"))
        .env("SSL_CERT_DIR", directory.join("empty-roots"))
        .env_remove("MARTY_TEST_OPENBAO_ROOT_TOKEN")
        .env_remove("MARTY_TEST_OPENBAO_TOKEN")
        .env_remove("BAO_TOKEN")
        .stdout(Stdio::from(output.try_clone().unwrap()))
        .stderr(Stdio::from(output))
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let status = match tokio::time::timeout(Duration::from_secs(90), child.wait()).await {
        Ok(status) => status.unwrap(),
        Err(_) => {
            child.kill().await.unwrap();
            child.wait().await.unwrap();
            mutation.abort();
            panic!("owned native consumer timed out; child reaped");
        }
    };
    let output = std::fs::read_to_string(output_path).unwrap();
    // Raw child output may contain private fixture values on an assertion
    // failure. Emit only this closed list of independently useful milestones.
    for phase in [
        "authority-fetched",
        "receipt-prepared",
        "holder-signing-response",
        "prepare-metadata-transport",
        "prepare-metadata-status",
        "prepare-issuer-mismatch",
        "prepare-service-grant",
        "prepare-token-exchange",
        "prepare-nonce",
        "prepare-holder-key",
        "prepare-configuration",
        "prepare-offer",
        "prepare-other",
        "remote-holder-signed",
        "complete-credential-request",
        "complete-other",
        "credential-response-received",
        "verified-receipt-admitted",
        "changed-authority-rejected",
    ] {
        if output
            .lines()
            .any(|line| line == format!("MARTY_JOINED_PHASE {phase}"))
        {
            println!("joined_native_phase={phase}");
        }
    }
    if !status.success() {
        mutation.abort();
        panic!("joined native consumer failed; private output withheld");
    }
    mutation.await.unwrap();
    assert!(output.contains("1 passed; 0 failed; 0 ignored;"));
    for phase in ["verified-receipt-admitted", "changed-authority-rejected"] {
        assert!(output
            .lines()
            .any(|line| line == format!("MARTY_JOINED_PHASE {phase}")));
    }
    owner
        .repository
        .save_profile_issuer(&owner.relationship)
        .await
        .unwrap();
    println!("joined_native_consumer=1_passed_0_ignored");
}
