fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    std::env::set_var("PROTOC", protoc);

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(
            &[
                "../../../proto/v1/issuance_service.proto",
                "../../../proto/v1/organization_service.proto",
                "../../../proto/v1/credential_template_service.proto",
                "../../../proto/v1/revocation_profile_service.proto",
            ],
            &["../../../proto/v1"],
        )?;

    for source in [
        "issuance_service.proto",
        "organization_service.proto",
        "credential_template_service.proto",
        "revocation_profile_service.proto",
        "google/api/annotations.proto",
        "google/api/http.proto",
    ] {
        println!("cargo:rerun-if-changed=../../../proto/v1/{source}");
    }
    Ok(())
}
