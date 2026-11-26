//! Explicit, default-off delegated-use serving composition.
//! Public caller routes require a separate mutual-TLS-only selection.
//! Local owners retain authority/evidence; consumers retain business execution.
pub mod config;
pub mod database;
pub mod health;
pub mod runtime;
