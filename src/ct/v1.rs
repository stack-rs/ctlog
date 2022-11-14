use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct AddChainResponse {
    /// The version of the SignedCertificateTimestamp
    /// structure, in decimal.  A compliant v1 implementation MUST NOT
    /// expect this to be 0 (i.e., v1).
    pub sct_version: u8,

    /// The log ID, base64 encoded.  Since log clients who request an
    /// SCT for inclusion in TLS handshakes are not required to verify
    /// it, we do not assume they know the ID of the log.
    pub id: String,

    /// The SCT timestamp, in decimal.
    pub timestamp: u64,

    /// An opaque type for future expansion.  It is likely
    /// that not all participants will need to understand data in this
    /// field.  Logs should set this to the empty string.  Clients
    /// should decode the base64-encoded data and include it in the
    /// SCT.
    pub extensions: String,

    /// The SCT signature, base64 encoded.
    pub signature: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetSthResponse {
    /// The size of the tree, in entries, in decimal.
    pub tree_size: u64,

    /// The timestamp, in decimal.
    pub timestamp: u64,

    /// The Merkle Tree Hash of the tree, in base64.
    pub sha256_root_hash: String,

    /// A TreeHeadSignature for the above data.
    pub tree_head_signature: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetSthConsistencyResponse {
    /// An array of Merkle Tree nodes, base64 encoded.
    pub consistency: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetProofByHashResponse {
    /// The 0-based index of the end entity corresponding to
    /// the "hash" parameter.
    pub leaf_index: u64,

    /// An array of base64-encoded Merkle Tree nodes proving
    /// the inclusion of the chosen certificate.
    pub audit_path: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Entry {
    /// The base64-encoded MerkleTreeLeaf structure.
    pub leaf_input: String,

    /// The base64-encoded unsigned data pertaining to the
    /// log entry.  In the case of an X509ChainEntry, this is the
    /// "certificate_chain".  In the case of a PrecertChainEntry,
    /// this is the whole "PrecertChainEntry".
    pub extra_data: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetEntriesResponse {
    /// An array of entries.
    ///
    /// see [Entry] for more details.
    pub entries: Vec<Entry>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetRootsResponse {
    /// An array of base64-encoded root certificates that
    /// are acceptable to the log.
    pub certificates: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetEntryAndProofResponse {
    /// The base64-encoded MerkleTreeLeaf structure.
    pub leaf_input: String,

    /// The base64-encoded unsigned data, same as in [Entry].
    pub extra_data: String,

    /// An array of base64-encoded Merkle Tree nodes proving
    /// the inclusion of the chosen certificate.
    pub audit_path: Vec<String>,
}
