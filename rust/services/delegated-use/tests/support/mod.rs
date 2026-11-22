pub mod crypto;
pub mod database;
pub mod host;
pub mod owned;

pub type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
