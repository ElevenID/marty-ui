fn main() {
    for name in [
        "MARTY_CI_EXECUTION_SOURCE_SHA",
        "MARTY_CI_EXECUTION_RELEASE_TAG",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    let source =
        std::env::var("MARTY_CI_EXECUTION_SOURCE_SHA").unwrap_or_else(|_| "unknown".into());
    let tag =
        std::env::var("MARTY_CI_EXECUTION_RELEASE_TAG").unwrap_or_else(|_| "unreleased".into());
    println!("cargo:rustc-env=MARTY_CI_EXECUTION_BUILD_IDENTITY={source}:{tag}");
}
