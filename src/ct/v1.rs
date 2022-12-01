use std::fmt;

use chrono::TimeZone;
use deku::prelude::*;
use oid_registry::{format_oid, OidRegistry};
use ouroboros::self_referencing;
use serde::{Deserialize, Serialize};
use x509_parser::prelude::*;

use crate::{
    utils::{print_x509_extension, print_x509_ski},
    CTLogError,
};

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

#[derive(Serialize, Deserialize, Debug, Clone)]
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

#[self_referencing(pub_extras)]
#[derive(Debug)]
pub struct WrapX509Certificate {
    raw: Vec<u8>,
    #[borrows(raw)]
    #[covariant]
    pub certificate: X509Certificate<'this>,
}

impl WrapX509Certificate {
    pub fn from_bytes(v: &[u8]) -> Result<Self, DekuError> {
        Ok(WrapX509CertificateBuilder {
            raw: v.to_vec(),
            certificate_builder: |raw: &Vec<u8>| X509Certificate::from_der(raw).unwrap().1,
        }
        .build())
    }
}

impl fmt::Display for WrapX509Certificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let certificate = self.borrow_certificate();
        writeln!(f, "Certificate:")?;
        writeln!(f, "  Data:")?;
        writeln!(f, "    Version: {}", certificate.version())?;
        writeln!(
            f,
            "    Serial Number: {} ({})",
            certificate.serial,
            certificate.raw_serial_as_string()
        )?;
        writeln!(
            f,
            "  Signature Algorithm: {}",
            format_oid(
                certificate.signature_algorithm.oid(),
                &OidRegistry::default().with_all_crypto()
            )
        )?;
        writeln!(f, "    Issuer: {}", certificate.issuer())?;
        writeln!(f, "    Validity:")?;
        writeln!(f, "      Not Before: {}", certificate.validity().not_before)?;
        writeln!(f, "      Not After : {}", certificate.validity().not_after)?;
        writeln!(f, "    Subject: {}", certificate.subject())?;
        writeln!(f, "    Subject Public Key Info:")?;
        print_x509_ski(f, certificate.public_key(), 6)?;

        if !certificate.extensions().is_empty() {
            writeln!(f, "    X509v3 extensions:")?;
            for extension in certificate.extensions() {
                print_x509_extension(f, &extension.oid, extension, 6)?;
            }
        }

        Ok(())
    }
}

#[self_referencing(pub_extras)]
#[derive(Debug)]
pub struct WrapTbsCertificate {
    raw: Vec<u8>,
    #[borrows(raw)]
    #[covariant]
    pub certificate: TbsCertificate<'this>,
}

impl WrapTbsCertificate {
    pub fn from_bytes(v: &[u8]) -> Result<Self, DekuError> {
        Ok(WrapTbsCertificateBuilder {
            raw: v.to_vec(),
            certificate_builder: |raw: &Vec<u8>| TbsCertificate::from_der(raw).unwrap().1,
        }
        .build())
    }
}

impl fmt::Display for WrapTbsCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let certificate = self.borrow_certificate();

        writeln!(f, "Certificate:")?;
        writeln!(f, "  Data:")?;
        writeln!(f, "    Version: {}", certificate.version())?;
        writeln!(
            f,
            "    Serial Number: {} ({})",
            certificate.serial,
            certificate.raw_serial_as_string()
        )?;
        writeln!(
            f,
            "  Signature Algorithm: {}",
            format_oid(
                certificate.signature.oid(),
                &OidRegistry::default().with_all_crypto()
            )
        )?;
        writeln!(f, "    Issuer: {}", certificate.issuer())?;
        writeln!(f, "    Validity:")?;
        writeln!(f, "      Not Before: {}", certificate.validity().not_before)?;
        writeln!(f, "      Not After : {}", certificate.validity().not_after)?;
        writeln!(f, "    Subject: {}", certificate.subject())?;
        writeln!(f, "    Subject Public Key Info:")?;
        print_x509_ski(f, certificate.public_key(), 6)?;

        if !certificate.extensions().is_empty() {
            writeln!(f, "    X509v3 extensions:")?;
            for extension in certificate.extensions() {
                print_x509_extension(f, &extension.oid, extension, 6)?;
            }
        }

        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, Clone, DekuRead)]
#[deku(type = "u16", endian = "big")]
pub enum LogEntryType {
    X509Entry = 0,
    PrecertEntry = 1,
}

#[derive(Debug, DekuRead)]
pub struct ASN1Cert {
    #[deku(bytes = 3, endian = "big")]
    pub length: u32,
    #[deku(
        count = "length",
        map = "|v: &[u8]| -> Result<_, DekuError> { Ok(Box::new(WrapX509Certificate::from_bytes(v).unwrap())) }"
    )]
    pub certificate: Box<WrapX509Certificate>,
}

impl fmt::Display for ASN1Cert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.certificate.fmt(f)
    }
}

#[derive(Debug, DekuRead)]
pub struct ASN1CertChain {
    #[deku(bytes = 3, endian = "big")]
    pub length: u32,
    #[deku(bytes_read = "length")]
    pub certificates: Vec<ASN1Cert>,
}

#[derive(Debug, DekuRead)]
pub struct PrecertChainEntry {
    pub pre_certificate: ASN1Cert,
    pub precertificate_chain: ASN1CertChain,
}

#[derive(Debug, PartialEq, Eq, Clone, DekuRead)]
#[deku(type = "u8")]
pub enum Version {
    V1 = 0,
}

#[derive(Debug, DekuRead)]
pub struct IssuerKeyHash([u8; 32]);

impl fmt::LowerHex for IssuerKeyHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

#[derive(Debug, DekuRead)]
pub struct PreCert {
    pub issuer_key_hash: IssuerKeyHash,
    #[deku(bytes = 3, endian = "big")]
    pub length: u32,
    #[deku(
        count = "length",
        map = "|v: &[u8]| -> Result<_, DekuError> { Ok(Box::new(WrapTbsCertificate::from_bytes(v).unwrap())) }"
    )]
    pub tbs_certificate: Box<WrapTbsCertificate>,
}

impl fmt::Display for PreCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.tbs_certificate.fmt(f)
    }
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

#[derive(Debug, DekuRead)]
#[deku(ctx = "entry_type: LogEntryType", id = "entry_type")]
pub enum TimestampedEntrySignedInner {
    #[deku(id = "LogEntryType::X509Entry")]
    X509(ASN1Cert),
    #[deku(id = "LogEntryType::PrecertEntry")]
    Precert(PreCert),
}

#[derive(Debug, DekuRead)]
pub struct TimestampedEntry {
    #[deku(endian = "big")]
    pub timestamp: u64,
    pub entry_type: LogEntryType,
    #[deku(ctx = "entry_type.clone()")]
    pub signed_entry: TimestampedEntrySignedInner,
    pub extensions: CtExtensions,
}

#[derive(Debug, DekuRead)]
pub struct MerkleTreeLeaf {
    pub version: Version,
    pub leaf_type: MerkleLeafType,
    pub timestamped_entry: TimestampedEntry,
}

#[derive(Debug)]
pub enum DecodedEntryInner {
    X509(ASN1CertChain),
    Precert(PrecertChainEntry),
}

/// A structure representing a log entry (parsed from the response of /ct/v1/get-entries).
#[derive(Debug)]
pub struct DecodedEntry {
    pub leaf: MerkleTreeLeaf,
    pub extra_data: DecodedEntryInner,
}

impl TryFrom<&Entry> for DecodedEntry {
    type Error = CTLogError;

    fn try_from(entry: &Entry) -> Result<Self, CTLogError> {
        let leaf = MerkleTreeLeaf::from_bytes((&base64::decode(entry.leaf_input.clone())?, 0))?.1;

        let extra_data = match leaf.timestamped_entry.entry_type {
            LogEntryType::X509Entry => {
                let cert_chain =
                    ASN1CertChain::from_bytes((&base64::decode(&entry.extra_data)?, 0))?.1;
                DecodedEntryInner::X509(cert_chain)
            }
            LogEntryType::PrecertEntry => {
                let precert_chain =
                    PrecertChainEntry::from_bytes((&base64::decode(&entry.extra_data)?, 0))?.1;
                DecodedEntryInner::Precert(precert_chain)
            }
        };

        Ok(Self { leaf, extra_data })
    }
}

impl fmt::Display for DecodedEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Timestamp={} ({}) ",
            self.leaf.timestamped_entry.timestamp,
            chrono::Utc
                .timestamp_millis_opt(self.leaf.timestamped_entry.timestamp as i64)
                .unwrap()
        )?;

        match (
            &self.leaf.timestamped_entry.entry_type,
            &self.leaf.timestamped_entry.signed_entry,
        ) {
            (LogEntryType::X509Entry, TimestampedEntrySignedInner::X509(certificate)) => {
                writeln!(f, "X.509 certificate:")?;
                writeln!(f, "{certificate}")?;

                // TODO: print the chain
            }
            (LogEntryType::PrecertEntry, TimestampedEntrySignedInner::Precert(certificate)) => {
                writeln!(
                    f,
                    "pre-certificate from issuer with keyhash {:x}:",
                    certificate.issuer_key_hash
                )?;
                writeln!(f, "{certificate}")?;

                // TODO: print the chain
            }
            _ => unreachable!(),
        }

        Ok(())
    }
}
