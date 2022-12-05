use chrono::TimeZone;
use ctlog::ct::v1::{DecodedEntry, LogEntryType, TimestampedEntrySignedInner};
use oid_registry::{format_oid, OidRegistry};
use serde::{Deserialize, Serialize};
use x509_parser::prelude::X509Extension;

#[derive(Debug, Serialize, Deserialize)]
pub struct Cert {
    pub index: u64,
    pub is_precert: bool,
    pub version: String,
    pub is_ca: bool,
    /// Common Name of Subject
    pub cn: Option<String>,
    /// Subject Alternative Names
    pub sans: Option<Vec<String>>,
    /// Issuer Common Name
    pub icn: Option<String>,
    /// Serial Number
    pub serial: String,
    /// Not Before
    pub not_before: String,
    /// Not After
    pub not_after: String,
    /// Issue Timestamp
    pub issue_at: String,
    /// Raw Extensions
    pub raw_extensions: Vec<Extension>,
}

impl From<&DecodedEntry> for Cert {
    fn from(e: &DecodedEntry) -> Self {
        match (
            &e.leaf.timestamped_entry.entry_type,
            &e.leaf.timestamped_entry.signed_entry,
        ) {
            (LogEntryType::X509Entry, TimestampedEntrySignedInner::X509(certificate)) => {
                let cert = certificate.certificate.borrow_certificate();
                Self {
                    index: 0,
                    is_precert: false,
                    version: cert.version().to_string(),
                    is_ca: cert.is_ca(),
                    cn: cert
                        .subject()
                        .iter_common_name()
                        .next()
                        .and_then(|cn| cn.as_str().ok().map(|s| s.to_string())),
                    sans: cert.subject_alternative_name().unwrap().map(|sans| {
                        sans.value
                            .general_names
                            .iter()
                            .map(|gn| gn.to_string())
                            .collect()
                    }),
                    icn: cert
                        .issuer()
                        .iter_common_name()
                        .next()
                        .and_then(|cn| cn.as_str().ok().map(|s| s.to_string())),
                    serial: cert.raw_serial_as_string(),
                    not_before: cert.validity().not_before.to_datetime().to_string(),
                    not_after: cert.validity().not_after.to_datetime().to_string(),
                    issue_at: chrono::Utc
                        .timestamp_millis_opt(e.leaf.timestamped_entry.timestamp as i64)
                        .unwrap()
                        .to_string(),
                    raw_extensions: cert.extensions().iter().map(|ext| ext.into()).collect(),
                }
            }
            (LogEntryType::PrecertEntry, TimestampedEntrySignedInner::Precert(certificate)) => {
                let cert = certificate.tbs_certificate.borrow_certificate();
                Self {
                    index: 0,
                    is_precert: true,
                    version: cert.version().to_string(),
                    is_ca: cert.is_ca(),
                    cn: cert
                        .subject()
                        .iter_common_name()
                        .next()
                        .and_then(|cn| cn.as_str().ok().map(|s| s.to_string())),
                    sans: cert.subject_alternative_name().unwrap().map(|sans| {
                        sans.value
                            .general_names
                            .iter()
                            .map(|gn| gn.to_string())
                            .collect()
                    }),
                    icn: cert
                        .issuer()
                        .iter_common_name()
                        .next()
                        .and_then(|cn| cn.as_str().ok().map(|s| s.to_string())),
                    serial: cert.raw_serial_as_string(),
                    not_before: cert.validity().not_before.to_datetime().to_string(),
                    not_after: cert.validity().not_after.to_datetime().to_string(),
                    issue_at: chrono::Utc
                        .timestamp_millis_opt(e.leaf.timestamped_entry.timestamp as i64)
                        .unwrap()
                        .to_string(),
                    raw_extensions: cert.extensions().iter().map(|ext| ext.into()).collect(),
                }
            }
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Extension {
    pub oid: String,
    pub critical: bool,
    pub value: String,
}

impl From<&X509Extension<'_>> for Extension {
    fn from(ext: &X509Extension) -> Self {
        Self {
            oid: format_oid(&ext.oid, &OidRegistry::default().with_x509()),
            critical: ext.critical,
            value: format_number_to_hex_with_colon(ext.value, 16).join(""),
        }
    }
}

fn format_number_to_hex_with_colon(b: &[u8], row_size: usize) -> Vec<String> {
    let mut v = Vec::with_capacity(1 + b.len() / row_size);
    for r in b.chunks(row_size) {
        let s = r.iter().fold(String::with_capacity(3 * r.len()), |a, b| {
            a + &format!("{:02x}:", b)
        });
        v.push(s)
    }
    v
}
