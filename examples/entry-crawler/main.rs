use std::io::Write;
use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use serde_cert::Cert;
use tokio::time::{sleep, Duration};

mod serde_cert;

#[derive(Parser)]
#[command(name = "entry-crawler")]
struct Opts {
    /// The URL of logs to crawl
    #[clap(short, long)]
    url: String,

    /// The output file
    #[clap(short, long, default_value = "entries.json")]
    output: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts = Opts::parse();

    let mut out = std::fs::File::create(opts.output)?;

    println!("Start Crawling {}", opts.url);

    let ctlog = ctlog::CTLogV1::new(&opts.url)?;

    // Get the tree size
    let sth = ctlog.get_sth().await?;
    let tree_size = sth.tree_size;

    println!("Tree Size: {}", tree_size);

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

    Ok(())
}
