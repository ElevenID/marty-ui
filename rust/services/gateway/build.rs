fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    std::env::set_var("PROTOC", protoc);

    tonic_prost_build::configure()
        .build_server(false)
        .build_client(true)
        .compile_protos(
            &[
                "../../../proto/v1/auth_service.proto",
                "../../../proto/v1/organization_service.proto",
                "../../../proto/v1/event_stream_service.proto",
            ],
            &["../../../proto/v1"],
        )?;

    println!("cargo:rerun-if-changed=../../../proto/v1/auth_service.proto");
    println!("cargo:rerun-if-changed=../../../proto/v1/organization_service.proto");
    println!("cargo:rerun-if-changed=../../../proto/v1/event_stream_service.proto");
    println!("cargo:rerun-if-changed=../../../proto/v1/google/api/annotations.proto");
    println!("cargo:rerun-if-changed=../../../proto/v1/google/api/http.proto");
    Ok(())
}
