#![doc = include_str!("../README.md")]

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CTLogError {
    #[error("parse error: {0}")]
    ParseUrlError(#[from] url::ParseError),
    #[error("reqwest error: {0}")]
    ReqwestError(#[from] reqwest::Error),
    #[error("deku error: {0}")]
    DekuError(#[from] deku::DekuError),
    #[error("base64 error: {0}")]
    Base64Error(#[from] base64::DecodeError),
}

pub mod client;
pub use client::CTLogV1;

pub mod ct;
