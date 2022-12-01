// Based on https://github.com/rusticata/x509-parser/blob/master/examples/print-cert.rs

use std::net::{Ipv4Addr, Ipv6Addr};
use std::{cmp::min, fmt};

use oid_registry::{format_oid, Oid, OidRegistry};
use x509_parser::nom::HexDisplay;
use x509_parser::prelude::{GeneralName, ParsedExtension, X509Extension};
use x509_parser::utils::format_serial;
#[allow(unused_imports)]
use x509_parser::{public_key::PublicKey, x509::SubjectPublicKeyInfo};

#[allow(dead_code)]
fn format_hex_dump(bytes: &[u8], max_len: usize) -> String {
    let m = min(bytes.len(), max_len);
    if bytes.len() > max_len {
        bytes[..m].to_hex(16) + "... <continued>\n"
    } else {
        bytes[..m].to_hex(16)
    }
}

#[allow(dead_code)]
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

pub fn print_x509_ski(
    f: &mut fmt::Formatter<'_>,
    public_key: &SubjectPublicKeyInfo,
    indent: usize,
) -> fmt::Result {
    writeln!(
        f,
        "{:indent$}Public Key Algorithm: {}",
        "",
        format_oid(
            public_key.algorithm.oid(),
            &OidRegistry::default().with_all_crypto()
        ),
        indent = indent,
    )?;
    // match public_key.parsed() {
    //     Ok(PublicKey::RSA(rsa)) => {
    //         writeln!(
    //             f,
    //             "{:indent$}RSA Public Key: ({} bit)",
    //             "",
    //             rsa.key_size(),
    //             indent = indent + 2,
    //         )?;
    //         for l in format_number_to_hex_with_colon(rsa.modulus, 16) {
    //             writeln!(f, "{:indent$}{}", "", l, indent = indent + 4)?;
    //         }
    //         if let Ok(e) = rsa.try_exponent() {
    //             writeln!(
    //                 f,
    //                 "{:indent$}Exponent: {} (0x{:x})",
    //                 "",
    //                 e,
    //                 e,
    //                 indent = indent + 2,
    //             )?;
    //         } else {
    //             writeln!(f, "{:indent$}Exponent: <Invalid>", "", indent = indent + 2)?;
    //             writeln!(
    //                 f,
    //                 "{:indent$}{}",
    //                 "",
    //                 format_hex_dump(rsa.exponent, 32),
    //                 indent = indent + 4
    //             )?;
    //         }
    //     }
    //     Ok(_) => {
    //         writeln!(
    //             f,
    //             "{:indent$}Unsupported public key algorithm",
    //             "",
    //             indent = indent + 2
    //         )?;
    //     }
    //     Err(_) => {
    //         writeln!(f, "{:indent$}Invalid Public Key", "", indent = indent + 2)?;
    //     }
    // }

    Ok(())
}

pub fn print_x509_extension(
    f: &mut fmt::Formatter<'_>,
    _oid: &Oid,
    extension: &X509Extension,
    indent: usize,
) -> fmt::Result {
    match extension.parsed_extension() {
        ParsedExtension::AuthorityKeyIdentifier(aki) => {
            writeln!(
                f,
                "{:indent$}X509v3 Authority Key Identifier:",
                "",
                indent = indent
            )?;
            if let Some(key_id) = &aki.key_identifier {
                writeln!(
                    f,
                    "{:indent$}KeyIdentifier: {:x}",
                    "",
                    key_id,
                    indent = indent + 2,
                )?;
            }
            if let Some(issuer) = &aki.authority_cert_issuer {
                for name in issuer {
                    writeln!(
                        f,
                        "{:indent$}Cert Issuer: {}",
                        "",
                        name,
                        indent = indent + 2
                    )?;
                }
            }
            if let Some(serial) = &aki.authority_cert_serial {
                writeln!(
                    f,
                    "{:indent$}Cert Serial: {}",
                    "",
                    format_serial(serial),
                    indent = indent + 2,
                )?;
            }
        }
        ParsedExtension::BasicConstraints(bc) => {
            writeln!(
                f,
                "{:indent$}X509v3 CA:\n{:indent2$}{}",
                "",
                "",
                bc.ca,
                indent = indent,
                indent2 = indent + 2
            )?;
        }
        ParsedExtension::CRLDistributionPoints(points) => {
            writeln!(
                f,
                "{:indent$}X509v3 CRL Distribution Points:",
                "",
                indent = indent
            )?;

            for point in points {
                if let Some(name) = &point.distribution_point {
                    writeln!(
                        f,
                        "{:indent$}Full Name: {:?}",
                        "",
                        name,
                        indent = indent + 2
                    )?;
                }
                if let Some(reasons) = &point.reasons {
                    writeln!(f, "{:indent$}Reasons: {}", "", reasons, indent = indent + 2)?;
                }
                if let Some(crl_issuer) = &point.crl_issuer {
                    write!(f, "{:indent$}CRL Issuer: ", "", indent = indent + 2)?;
                    for gn in crl_issuer {
                        write!(f, "{} ", gn)?;
                    }
                    writeln!(f)?;
                }
                writeln!(f)?;
            }
        }
        ParsedExtension::KeyUsage(ku) => {
            writeln!(
                f,
                "{:indent$}X509v3 Key Usage:\n{:indent2$}{}",
                "",
                "",
                ku,
                indent = indent,
                indent2 = indent + 2
            )?;
        }
        ParsedExtension::NSCertType(ty) => {
            writeln!(
                f,
                "{:indent$}Netscape Cert Type:\n{:indent2$}{}",
                "",
                "",
                ty,
                indent = indent,
                indent2 = indent + 2
            )?;
        }
        ParsedExtension::SubjectAlternativeName(san) => {
            for name in &san.general_names {
                let s = match name {
                    GeneralName::DNSName(s) => {
                        format!("DNS:{}", s)
                    }
                    GeneralName::IPAddress(b) => {
                        let ip = match b.len() {
                            4 => {
                                let b = <[u8; 4]>::try_from(*b).unwrap();
                                let ip = Ipv4Addr::from(b);
                                format!("{}", ip)
                            }
                            16 => {
                                let b = <[u8; 16]>::try_from(*b).unwrap();
                                let ip = Ipv6Addr::from(b);
                                format!("{}", ip)
                            }
                            l => format!("invalid (len={})", l),
                        };
                        format!("IP Address:{}", ip)
                    }
                    _ => {
                        format!("{:?}", name)
                    }
                };
                writeln!(
                    f,
                    "{:indent$}X509v3 Subject Alternative Name:\n{:indent2$}{}",
                    "",
                    "",
                    s,
                    indent = indent,
                    indent2 = indent + 2
                )?;
            }
        }
        ParsedExtension::SubjectKeyIdentifier(id) => {
            writeln!(
                f,
                "{:indent$}X509v3 Subject Key Identifier:\n{:indent2$}{:x}",
                "",
                "",
                id,
                indent = indent,
                indent2 = indent + 2
            )?;
        }
        x => {
            writeln!(
                f,
                "{:indent$}X509v3 Unknown Extension:\n{:indent2$}{:?}",
                "",
                "",
                x,
                indent = indent,
                indent2 = indent + 2
            )?;
        }
    }
    Ok(())
}
