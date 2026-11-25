use anyhow::{bail, Context, Result};
use chrono::Utc;
use homeshield_core::blocklist::{load_whitelist_from_file, BlocklistCompiler};
use homeshield_core::config::HomeShieldConfig;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{BufReader, Cursor};
use std::path::Path;
use std::time::Duration;
use tokio::task::JoinSet;

#[derive(Debug, Serialize)]
pub struct CompileMetadata {
    pub generated_at_utc: String,
    pub feeds_succeeded: usize,
    pub feeds_total: usize,
    pub whitelist_entries: usize,
    pub domain_count: usize,
    pub payload_bytes: usize,
    pub sha256: String,
}

pub async fn run(
    out_dir: &Path,
    whitelist_path: &Path,
    conf_path: &Path,
    min_domains: usize,
) -> Result<CompileMetadata> {
    let whitelist = load_whitelist_from_file(whitelist_path)
        .with_context(|| format!("failed to load whitelist from {}", whitelist_path.display()))?;
    let whitelist_entries = whitelist.len();

    let cfg = HomeShieldConfig::from_file(conf_path)
        .with_context(|| format!("failed to load config from {}", conf_path.display()))?;
    let feed_urls = cfg.blocklist_urls;
    let feeds_total = feed_urls.len();

    let client = reqwest::Client::builder()
        .user_agent("HomeShield-Tier0-Compiler/1.0")
        .timeout(Duration::from_secs(45))
        .build()
        .context("failed to build HTTP client")?;

    let mut join_set = JoinSet::new();
    for (idx, url) in feed_urls.iter().cloned().enumerate() {
        let client = client.clone();
        join_set.spawn(async move {
            let res = fetch_feed(&client, &url).await;
            (idx, url, res)
        });
    }

    let mut results: Vec<Option<Vec<u8>>> = vec![None; feeds_total];
    while let Some(joined) = join_set.join_next().await {
        match joined {
            Ok((idx, _url, Ok(bytes))) => {
                results[idx] = Some(bytes);
            }
            Ok((_idx, url, Err(err))) => {
                eprintln!("[warn] Failed to fetch {url}: {err}");
            }
            Err(err) => {
                eprintln!("[warn] Feed download task failed: {err}");
            }
        }
    }

    let capacity_hint = (feeds_total * 15_000).max(300_000);
    let mut compiler = BlocklistCompiler::with_capacity(whitelist, capacity_hint);
    let mut feeds_succeeded = 0usize;

    for bytes in results.into_iter().flatten() {
        let line_count = bytes.iter().filter(|&&b| b == b'\n').count();
        if line_count > 50 {
            compiler.process_reader(BufReader::new(Cursor::new(bytes)))?;
            feeds_succeeded += 1;
        }
    }

    compiler.inject_anti_bypass(cfg.block_canary_doh, cfg.block_apple_private_relay);

    let domain_count = compiler.unique_domains_count();
    if domain_count < min_domains {
        bail!(
            "Compiled domain count ({domain_count}) below safety threshold ({min_domains}); aborting publish."
        );
    }

    let mut payload = Vec::with_capacity(domain_count * 32);
    compiler.write_hosts(&mut payload)?;

    let mut hasher = Sha256::new();
    hasher.update(&payload);
    let sha256 = format!("{:x}", hasher.finalize());
    let payload_bytes = payload.len();

    fs::create_dir_all(out_dir)
        .with_context(|| format!("failed to create output dir {}", out_dir.display()))?;
    fs::write(out_dir.join("hosts.txt"), &payload).context("failed to write hosts.txt")?;

    let meta = CompileMetadata {
        generated_at_utc: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        feeds_succeeded,
        feeds_total,
        whitelist_entries,
        domain_count,
        payload_bytes,
        sha256,
    };

    let meta_json = serde_json::to_string_pretty(&meta)? + "\n";
    fs::write(out_dir.join("metadata.json"), &meta_json)
        .context("failed to write metadata.json")?;

    println!("{meta_json}");
    Ok(meta)
}

async fn fetch_feed(client: &reqwest::Client, url: &str) -> Result<Vec<u8>> {
    let resp = client.get(url).send().await?.error_for_status()?;
    let bytes = resp.bytes().await?;
    Ok(bytes.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compiler_parity_with_core() {
        let mut compiler = BlocklistCompiler::new(Default::default());
        let sample = b"0.0.0.0 ads.example.com\n||tracker.example.org^\nbad.example.net\n";
        compiler
            .process_reader(BufReader::new(Cursor::new(sample)))
            .unwrap();
        compiler.inject_anti_bypass(true, true);
        assert_eq!(compiler.unique_domains_count(), 7);
    }
}
