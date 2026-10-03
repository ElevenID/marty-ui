//! Lossless response text and JSON values shared by service boundaries.

#![forbid(unsafe_code)]

pub mod canvas_response_json;
pub mod lossless_json;
pub mod lossless_json_tree;
mod lossless_json_write;
pub mod owned_json_value;
pub mod python_text;
pub mod python_value;
