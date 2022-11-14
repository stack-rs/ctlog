#![doc = include_str!("../README.md")]

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CTLogError {
    #[error("parse error: {0}")]
    ParseUrlError(#[from] url::ParseError),
    #[error("reqwest error: {0}")]
    ReqwestError(#[from] reqwest::Error),
}

pub mod client;
pub use client::CTLogV1;

pub mod ct;
