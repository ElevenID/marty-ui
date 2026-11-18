pub mod bus;
pub mod config;
pub mod grpc;
pub mod http;

pub mod proto {
    tonic::include_proto!("marty.ui.event_stream.v1");
}
