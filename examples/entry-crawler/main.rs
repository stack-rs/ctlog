use std::io::Write;
use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use oid_registry::{format_oid, OidRegistry};
use serde_cert::Cert;
use tokio::time::{sleep, Duration};
use x509_parser::prelude::*;

mod serde_cert;

#[derive(Parser)]
#[command(name = "entry-crawler")]
struct Opts {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Crawl the entries
    Crawl {
        /// The URL of logs to crawl
        #[clap(short, long)]
        url: String,

        /// The output file
        #[clap(short, long, default_value = "entries.json")]
        output: PathBuf,
    },

    /// Convert the entries
    Convert {
        /// The input file
        #[clap(short, long, default_value = "entries.json")]
        input: PathBuf,

        /// The output file
        #[clap(short, long, default_value = "entries.json")]
        output: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts = Opts::parse();

    match opts.cmd {
        Commands::Crawl { url, output } => crawl(url, output).await?,
        Commands::Convert { input, output } => convert(input, output).await?,
    }

    Ok(())
}

async fn crawl(url: String, output: PathBuf) -> Result<()> {
    let mut out = std::fs::File::create(output)?;

    println!("Start Crawling {}", url);

    let ctlog = ctlog::CTLogV1::new(&url)?;

    // Get the tree size
    let sth = ctlog.get_sth().await?;
    let tree_size = sth.tree_size;

    println!("Tree Size: {}", tree_size);

    writeln!(out, "[")?;

    // Get the entries, 200 at a time
    for i in (0..tree_size).step_by(200) {
        // Get the entries
        let entries = ctlog.get_entries_decoded(i, i + 199).await?;
        println!(
            "Getting entries {} to {}, len {}",
            i,
            i + 199,
            entries.len()
        );

        // Write the entries to the file
        entries
            .iter()
            .enumerate()
            .try_for_each(|(ii, e)| -> Result<()> {
                let mut e: Cert = e.into();
                e.index = i + ii as u64;
                serde_json::to_writer_pretty(&out, &e)?;
                writeln!(out, ",")?;

                Ok(())
            })?;

        // Sleep for 10 ms
        sleep(Duration::from_millis(10)).await;
    }

    writeln!(out, "]")?;

    Ok(())
}

async fn convert(input: PathBuf, output: PathBuf) -> Result<()> {
    let input = std::fs::File::open(input)?;

    let mut entries: Vec<Cert> = serde_json::from_reader(input)?;

    // Example of parsing the AuthorityInfoAccess and CrlDistributionPoint extension

    println!("Converting {} entries", entries.len());

    let mut idx = 0;
    let total = entries.len();

    for entry in &mut entries {
        println!("Converting entry {idx}/{total}");
        idx += 1;
        for ext in &mut entry.raw_extensions {
            let flag = if ext.oid
                == format_oid(
                    &oid_registry::OID_PKIX_AUTHORITY_INFO_ACCESS,
                    &OidRegistry::default().with_x509(),
                ) {
                0
            } else if ext.oid
                == format_oid(
                    &oid_registry::OID_X509_EXT_CRL_DISTRIBUTION_POINTS,
                    &OidRegistry::default().with_x509(),
                )
            {
                1
            } else {
                continue;
            };

            let value: Vec<u8> = ext
                .value
                .split_terminator(":")
                .map(|s| u8::from_str_radix(s, 16).unwrap())
                .collect();

            match flag {
                0 => {
                    let (_, access) = extensions::AuthorityInfoAccess::from_der(&value).unwrap();
                    let format_access: Vec<String> = access
                        .accessdescs
                        .iter()
                        .map(|a| {
                            let method =
                                format_oid(&a.access_method, &OidRegistry::default().with_x509());
                            let location = a.access_location.to_string();
                            format!("{}: {}", method, location)
                        })
                        .collect();

                    ext.value = format_access.join(",").to_string();
                }
                1 => {
                    let (_, points) = extensions::CRLDistributionPoints::from_der(&value).unwrap();
                    let format_points: Vec<String> = points
                        .points
                        .iter()
                        .map(|p| {
                            let name = &p
                                .distribution_point
                                .clone()
                                .map(|n| format!("{n:?}"))
                                .unwrap_or("".to_string());
                            let reasons = &p
                                .reasons
                                .clone()
                                .map(|r| format!("{r}"))
                                .unwrap_or("".to_string());
                            let issuer = &p
                                .crl_issuer
                                .clone()
                                .map(|i| format!("{i:?}"))
                                .unwrap_or("".to_string());
                            format!("{}:{}:{}", name, reasons, issuer)
                        })
                        .collect();

                    ext.value = format_points.join(";").to_string();
                }
                _ => unreachable!(),
            }
        }
    }

    let mut output = std::fs::File::create(output)?;
    serde_json::to_writer_pretty(&mut output, &entries)?;

    Ok(())
}
