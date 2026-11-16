fn main() {
    println!("cargo:rerun-if-env-changed=MARTY_DEPLOY_SOURCE_SHA");
    println!("cargo:rerun-if-env-changed=MARTY_DEPLOY_RELEASE_TAG");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_INSTALLER_DEVELOPMENT");
    if std::env::var_os("CARGO_FEATURE_INSTALLER_DEVELOPMENT").is_some() {
        assert!(
            std::env::var_os("MARTY_DEPLOY_SOURCE_SHA").is_none()
                && std::env::var_os("MARTY_DEPLOY_RELEASE_TAG").is_none(),
            "installer-development must not carry a release build identity"
        );
        println!(
            "cargo:rustc-env=MARTY_DEPLOY_BUILD_IDENTITY=unknown:unsigned-installer-development"
        );
        return;
    }
    let source = std::env::var("MARTY_DEPLOY_SOURCE_SHA").unwrap_or_else(|_| "unknown".into());
    let tag = std::env::var("MARTY_DEPLOY_RELEASE_TAG").unwrap_or_else(|_| "unreleased".into());
    println!("cargo:rustc-env=MARTY_DEPLOY_BUILD_IDENTITY={source}:{tag}");
}
