// use anyhow::Result;
use reqwest::Client;

use crate::client::CTLog;
use crate::ct::v1::*;
use crate::CTLogError;

#[derive(Debug)]
pub struct CTLogV1(CTLog);

impl CTLogV1 {
    pub fn new(log_server: &str) -> Result<Self, CTLogError> {
        Ok(Self(CTLog {
            inner: Client::new(),
            log_server: log_server.parse()?,
        }))
    }

    /// Add Chain to Log
    ///
    /// [RFC 6962 4.1](https://datatracker.ietf.org/doc/html/rfc6962#section-4.1)
    pub async fn add_chain(&self, chain: Vec<String>) -> Result<AddChainResponse, CTLogError> {
        let url = self.0.log_server.join("ct/v1/add-chain")?;
        let response = self
            .0
            .inner
            .post(url)
            .json(&chain)
            .send()
            .await?
            .json()
            .await?;
        Ok(response)
    }

    /// Add PreCertChain to Log
    ///
    /// [RFC 6962 4.2](https://datatracker.ietf.org/doc/html/rfc6962#section-4.2)
    pub async fn add_pre_chain(&self, chain: Vec<String>) -> Result<AddChainResponse, CTLogError> {
        let url = self.0.log_server.join("ct/v1/add-pre-chain")?;
        let response = self
            .0
            .inner
            .post(url)
            .json(&chain)
            .send()
            .await?
            .json()
            .await?;
        Ok(response)
    }

    /// Retrieve Latest Signed Tree Head
    ///
    /// [RFC 6962 4.3](https://datatracker.ietf.org/doc/html/rfc6962#section-4.3)
    pub async fn get_sth(&self) -> Result<GetSthResponse, CTLogError> {
        let url = self.0.log_server.join("ct/v1/get-sth")?;
        let response = self.0.inner.get(url).send().await?.json().await?;
        Ok(response)
    }

    /// Retrieve Merkle Consistency Proof between Two Signed Tree Heads
    ///
    /// [RFC 6962 4.4](https://datatracker.ietf.org/doc/html/rfc6962#section-4.4)
    pub async fn get_sth_consistency(
        &self,
        first: u64,
        second: u64,
    ) -> Result<GetSthConsistencyResponse, CTLogError> {
        let url = self.0.log_server.join(&format!(
            "ct/v1/get-sth-consistency?first={first}&second={second}"
        ))?;
        let response = self.0.inner.get(url).send().await?.json().await?;
        Ok(response)
    }

    /// Retrieve Merkle Audit Proof from Log by Leaf Hash
    ///
    /// [RFC 6962 4.5](https://datatracker.ietf.org/doc/html/rfc6962#section-4.5)
    pub async fn get_proof_by_hash(
        &self,
        hash: &str,
        tree_size: u64,
    ) -> Result<GetProofByHashResponse, CTLogError> {
        let url = self.0.log_server.join(&format!(
            "ct/v1/get-proof-by-hash?hash={hash}&tree_size={tree_size}",
        ))?;
        let response = self.0.inner.get(url).send().await?.json().await?;
        Ok(response)
    }

    /// Retrieve Entries from Log
    ///
    /// [RFC 6962 4.6](https://datatracker.ietf.org/doc/html/rfc6962#section-4.6)
    pub async fn get_entries(
        &self,
        start: u64,
        end: u64,
    ) -> Result<GetEntriesResponse, CTLogError> {
        let url = self
            .0
            .log_server
            .join(&format!("ct/v1/get-entries?start={start}&end={end}"))?;
        let response = self.0.inner.get(url).send().await?.json().await?;
        Ok(response)
    }

    /// Retrieve Accepted Root Certificates
    ///
    /// [RFC 6962 4.7](https://datatracker.ietf.org/doc/html/rfc6962#section-4.7)
    pub async fn get_roots(&self) -> Result<GetRootsResponse, CTLogError> {
        let url = self.0.log_server.join("ct/v1/get-roots")?;
        let response = self.0.inner.get(url).send().await?.json().await?;
        Ok(response)
    }

    /// Retrieve Entry + Merkle Audit Proof from Log
    ///
    /// [RFC 6962 4.8](https://datatracker.ietf.org/doc/html/rfc6962#section-4.8)
    pub async fn get_entry_and_proof(
        &self,
        leaf_index: u64,
        tree_size: u64,
    ) -> Result<GetEntryAndProofResponse, CTLogError> {
        let url = self.0.log_server.join(&format!(
            "ct/v1/get-entry-and-proof?leaf_index={leaf_index}&tree_size={tree_size}"
        ))?;
        let response = self.0.inner.get(url).send().await?.json().await?;
        Ok(response)
    }
}
