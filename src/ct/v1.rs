use deku::prelude::*;
use serde::{Deserialize, Serialize};
use x509_parser::prelude::*;

use crate::CTLogError;

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

#[derive(Debug, PartialEq, Eq, Clone, DekuRead)]
#[deku(type = "u16", endian = "big")]
pub enum LogEntryType {
    X509Entry = 0,
    PrecertEntry = 1,
}

#[derive(Debug, Clone, DekuRead)]
pub struct ASN1Cert<'a> {
    #[deku(bytes = 3, endian = "big")]
    pub length: u32,
    #[deku(
        count = "length",
        map = "|v: &'a [u8]| -> Result<_, DekuError> { Ok(X509Certificate::from_der(v).unwrap().1) }"
    )]
    pub certificate: X509Certificate<'a>,
}

#[derive(Debug, Clone, DekuRead)]
pub struct ASN1CertChain<'a> {
    #[deku(bytes = 3, endian = "big")]
    pub length: u32,
    #[deku(bytes_read = "length")]
    pub certificates: Vec<ASN1Cert<'a>>,
}

#[derive(Debug, Clone, DekuRead)]
pub struct PrecertChainEntry<'a> {
    pub pre_certificate: ASN1Cert<'a>,
    pub precertificate_chain: ASN1CertChain<'a>,
}

#[derive(Debug, PartialEq, Eq, Clone, DekuRead)]
#[deku(type = "u8")]
pub enum Version {
    V1 = 0,
}

#[derive(Debug, Clone, DekuRead)]
pub struct PreCert<'a> {
    pub issuer_key_hash: [u8; 32],
    #[deku(bytes = 3, endian = "big")]
    pub length: u32,
    #[deku(
        count = "length",
        map = "|v: &'a [u8]| -> Result<_, DekuError> { println!(\"{:?}\", v);Ok(TbsCertificate::from_der(v).unwrap().1) }"
    )]
    pub tbs_certificate: TbsCertificate<'a>,
}

#[derive(Debug, Clone, DekuRead)]
pub struct CtExtensions {
    #[deku(endian = "big")]
    pub length: u16,
    #[deku(count = "length")]
    pub extensions: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq, Clone, DekuRead)]
#[deku(type = "u8")]
pub enum MerkleLeafType {
    TimestampedEntry = 0,
}

#[derive(Debug, Clone, DekuRead)]
#[deku(ctx = "entry_type: LogEntryType", id = "entry_type")]
pub enum TimestampedEntrySignedInner<'a> {
    #[deku(id = "LogEntryType::X509Entry")]
    X509(ASN1Cert<'a>),
    #[deku(id = "LogEntryType::PrecertEntry")]
    Precert(PreCert<'a>),
}

#[derive(Debug, Clone, DekuRead)]
pub struct TimestampedEntry<'a> {
    #[deku(endian = "big")]
    pub timestamp: u64,
    pub entry_type: LogEntryType,
    #[deku(ctx = "entry_type.clone()")]
    pub signed_entry: TimestampedEntrySignedInner<'a>,
    pub extensions: CtExtensions,
}

#[derive(Debug, Clone, DekuRead)]
pub struct MerkleTreeLeaf<'a> {
    pub version: Version,
    pub leaf_type: MerkleLeafType,
    pub timestamped_entry: TimestampedEntry<'a>,
}

#[derive(Debug, Clone)]
pub enum DecodedEntryInner<'a> {
    X509(ASN1CertChain<'a>),
    Precert(PrecertChainEntry<'a>),
}

/// A structure representing a log entry (parsed from the response of /ct/v1/get-entries).
#[derive(Debug, Clone)]
pub struct DecodedEntry<'a> {
    pub leaf: MerkleTreeLeaf<'a>,
    pub extra_data: DecodedEntryInner<'a>,
}
