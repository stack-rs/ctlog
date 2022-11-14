use url::Url;

mod v1;
pub use v1::CTLogV1;

#[derive(Debug)]
struct CTLog {
    inner: reqwest::Client,
    log_server: Url,
}
