fn main() {
    println!("cargo:rerun-if-env-changed=MARTY_DEPLOY_SOURCE_SHA");
    println!("cargo:rerun-if-env-changed=MARTY_DEPLOY_RELEASE_TAG");
    let source = std::env::var("MARTY_DEPLOY_SOURCE_SHA").unwrap_or_else(|_| "unknown".into());
    let tag = std::env::var("MARTY_DEPLOY_RELEASE_TAG").unwrap_or_else(|_| "unreleased".into());
    println!("cargo:rustc-env=MARTY_DEPLOY_BUILD_IDENTITY={source}:{tag}");
}
