# `ctlog`

[![crates.io](https://img.shields.io/crates/v/ctlog.svg)](https://crates.io/crates/ctlog)

A simple certificate transparency log client API wrapper powered by
[reqwest](https://github.com/seanmonstar/reqwest)

## Usage

```rust
use anyhow::Result;

use ctlog::CTLogV1;

#[tokio::main]
async fn main() -> Result<()> {
    // Create a new CTLogV1 client for TrustAsia logs
    let ctlog = CTLogV1::new("https://ct.trustasia.com/log2023/")?;

    // Get the sth
    let sth = ctlog.get_sth().await?;

    println!("{:#?}", sth);

    Ok(())
}
```

## Notice

Currently only supports v1 API (RFC6962)

## [Documentation](https://docs.rs/crate/ctlog)

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](./LICENSE-APACHE) or
  http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](./LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
