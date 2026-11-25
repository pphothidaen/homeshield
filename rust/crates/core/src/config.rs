use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub const DEFAULT_CONF_PATH: &str = "/userconfig/adblock.conf";
pub const DEFAULT_BLOCKLIST_URLS: &[&str] = &[
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/multi.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.samsung.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.lgwebos.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.xiaomi.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.tiktok.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/popupads.txt",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling/hosts",
    "https://raw.githubusercontent.com/froggeric/DNS-blocklists/main/NoYouTubeAdsDNS",
    "https://raw.githubusercontent.com/Turtlecute33/adblocktest/master/src/d3host.txt",
    "https://raw.githubusercontent.com/Turtlecute33/adblocktest/master/src/d3host.adblock",
];

/// Normalize GitHub web URLs (`github.com/.../blob/...`) to direct raw endpoints (`raw.githubusercontent.com/...`).
pub fn normalize_feed_url(url: &str) -> String {
    let trimmed = url.trim();
    if let Some(rest) = trimmed
        .strip_prefix("https://github.com/")
        .or_else(|| trimmed.strip_prefix("http://github.com/"))
    {
        let parts: Vec<&str> = rest.split('/').collect();
        if parts.len() >= 5 && parts[2] == "blob" {
            let owner = parts[0];
            let repo = parts[1];
            let branch_and_path = parts[3..].join("/");
            return format!("https://raw.githubusercontent.com/{owner}/{repo}/{branch_and_path}");
        }
    }
    trimmed.to_string()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeShieldConfig {
    pub primary_cdn_url: Option<String>,
    pub blocklist_urls: Vec<String>,
    pub update_interval_seconds: u64,
    pub whitelist_file: PathBuf,
    pub backup_file: PathBuf,
    pub last_update_file: PathBuf,
    pub last_epoch_file: PathBuf,
    pub paused_file: PathBuf,
    pub ram_hosts_file: PathBuf,
    pub base_hosts_file: PathBuf,
    pub system_hosts_file: PathBuf,
    pub block_dot: bool,
    pub block_canary_doh: bool,
    pub block_apple_private_relay: bool,
    pub min_valid_lines: usize,
}

impl Default for HomeShieldConfig {
    fn default() -> Self {
        Self {
            primary_cdn_url: None,
            blocklist_urls: DEFAULT_BLOCKLIST_URLS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            update_interval_seconds: 86_400,
            whitelist_file: PathBuf::from("/userconfig/whitelist.txt"),
            backup_file: PathBuf::from("/userconfig/adblock.hosts"),
            last_update_file: PathBuf::from("/userconfig/adblock.last_update"),
            last_epoch_file: PathBuf::from("/userconfig/adblock.last_update_epoch"),
            paused_file: PathBuf::from("/var/tmp/adblock.paused"),
            ram_hosts_file: PathBuf::from("/var/tmp/adblock.hosts"),
            base_hosts_file: PathBuf::from("/var/tmp/hosts.base"),
            system_hosts_file: PathBuf::from("/var/tmp/hosts"),
            block_dot: true,
            block_canary_doh: true,
            block_apple_private_relay: true,
            min_valid_lines: 1000,
        }
    }
}

impl HomeShieldConfig {
    /// Load configuration from a shell-compatible `adblock.conf` file.
    /// Falls back to defaults if the file does not exist.
    pub fn from_file(path: &Path) -> io::Result<Self> {
        match fs::read_to_string(path) {
            Ok(content) => Ok(Self::from_conf_str(&content)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e),
        }
    }

    /// Parse shell-style `KEY=VALUE` configuration content.
    pub fn from_conf_str(content: &str) -> Self {
        let mut cfg = Self::default();
        let mut has_urls_plural = false;
        let mut fallback_url_singular: Option<String> = None;

        for raw_line in content.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let Some((raw_key, raw_val)) = line.split_once('=') else {
                continue;
            };
            let key = raw_key.trim();
            let val = unquote_shell_value(raw_val.trim());

            match key {
                "PRIMARY_CDN_URL" => {
                    if !val.is_empty() {
                        cfg.primary_cdn_url = Some(val);
                    }
                }
                "BLOCKLIST_URLS" => {
                    let urls: Vec<String> =
                        val.split_whitespace().map(normalize_feed_url).collect();
                    if !urls.is_empty() {
                        cfg.blocklist_urls = urls;
                        has_urls_plural = true;
                    }
                }
                "BLOCKLIST_URL" => {
                    if !val.is_empty() {
                        fallback_url_singular = Some(normalize_feed_url(&val));
                    }
                }
                "UPDATE_INTERVAL_SECONDS" => {
                    if let Ok(secs) = val.parse::<u64>() {
                        cfg.update_interval_seconds = secs;
                    }
                }
                "WHITELIST_FILE" => {
                    if !val.is_empty() {
                        cfg.whitelist_file = PathBuf::from(val);
                    }
                }
                "BACKUP_FILE" => {
                    if !val.is_empty() {
                        cfg.backup_file = PathBuf::from(val);
                    }
                }
                "LAST_UPDATE_FILE" => {
                    if !val.is_empty() {
                        cfg.last_update_file = PathBuf::from(val);
                    }
                }
                "LAST_EPOCH_FILE" => {
                    if !val.is_empty() {
                        cfg.last_epoch_file = PathBuf::from(val);
                    }
                }
                "PAUSED_FILE" => {
                    if !val.is_empty() {
                        cfg.paused_file = PathBuf::from(val);
                    }
                }
                "RAM_HOSTS_FILE" => {
                    if !val.is_empty() {
                        cfg.ram_hosts_file = PathBuf::from(val);
                    }
                }
                "BASE_HOSTS_FILE" => {
                    if !val.is_empty() {
                        cfg.base_hosts_file = PathBuf::from(val);
                    }
                }
                "SYSTEM_HOSTS_FILE" => {
                    if !val.is_empty() {
                        cfg.system_hosts_file = PathBuf::from(val);
                    }
                }
                "BLOCK_DOT" => {
                    cfg.block_dot = parse_bool_flag(&val, cfg.block_dot);
                }
                "BLOCK_CANARY_DOH" => {
                    cfg.block_canary_doh = parse_bool_flag(&val, cfg.block_canary_doh);
                }
                "BLOCK_APPLE_PRIVATE_RELAY" => {
                    cfg.block_apple_private_relay =
                        parse_bool_flag(&val, cfg.block_apple_private_relay);
                }
                _ => {}
            }
        }

        if !has_urls_plural {
            if let Some(url) = fallback_url_singular {
                cfg.blocklist_urls = vec![url];
            }
        }

        cfg
    }
}

fn unquote_shell_value(raw: &str) -> String {
    if raw.len() >= 2
        && ((raw.starts_with('"') && raw.ends_with('"'))
            || (raw.starts_with('\'') && raw.ends_with('\'')))
    {
        return raw[1..raw.len() - 1].trim().to_string();
    }
    // Strip trailing inline comment if unquoted
    match raw.find(" #") {
        Some(idx) => raw[..idx].trim().to_string(),
        None => raw.trim().to_string(),
    }
}

fn parse_bool_flag(val: &str, default: bool) -> bool {
    match val.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => true,
        "0" | "false" | "no" | "off" => false,
        _ => default,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_parse_repo_adblock_conf() {
        let repo_conf = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../config/adblock.conf");
        let cfg = HomeShieldConfig::from_file(&repo_conf).expect("read config/adblock.conf");

        assert_eq!(cfg.blocklist_urls.len(), 29);
        assert!(cfg
            .blocklist_urls
            .iter()
            .any(|u| u.contains("native.apple")));
        assert!(cfg
            .blocklist_urls
            .iter()
            .any(|u| u.contains("native.huawei")));
        assert!(cfg
            .blocklist_urls
            .iter()
            .any(|u| u.contains("native.winoffice")));
        assert!(cfg
            .blocklist_urls
            .iter()
            .any(|u| u.contains("WindowsSpyBlocker")));
        assert!(cfg.blocklist_urls[0].contains("hagezi"));
        assert!(cfg.blocklist_urls[0].contains("multi.txt"));
        assert!(cfg
            .blocklist_urls
            .iter()
            .any(|u| u.contains("native.lgwebos")));
        assert!(cfg.blocklist_urls.iter().any(|u| u.contains("StevenBlack")));
        assert!(cfg
            .blocklist_urls
            .iter()
            .any(|u| u.contains("NoYouTubeAdsDNS")));
        assert!(cfg.blocklist_urls.iter().any(|u| u.contains("d3host.txt")));
        assert!(cfg
            .blocklist_urls
            .iter()
            .any(|u| u.contains("d3host.adblock")));
        assert!(cfg.primary_cdn_url.is_some());
        assert_eq!(cfg.update_interval_seconds, 86_400);
        assert_eq!(
            cfg.whitelist_file,
            PathBuf::from("/userconfig/whitelist.txt")
        );
        assert_eq!(cfg.backup_file, PathBuf::from("/userconfig/adblock.hosts"));
        assert!(cfg.block_dot);
        assert!(cfg.block_canary_doh);
        assert!(cfg.block_apple_private_relay);
    }

    #[test]
    fn test_singular_url_fallback_and_bool_flags() {
        let conf = r#"
# Custom override
BLOCKLIST_URL="https://example.com/list.txt"
UPDATE_INTERVAL_SECONDS=3600
BLOCK_DOT=0
BLOCK_CANARY_DOH=false
BLOCK_APPLE_PRIVATE_RELAY=1
"#;
        let cfg = HomeShieldConfig::from_conf_str(conf);
        assert_eq!(cfg.blocklist_urls, vec!["https://example.com/list.txt"]);
        assert_eq!(cfg.update_interval_seconds, 3600);
        assert!(!cfg.block_dot);
        assert!(!cfg.block_canary_doh);
        assert!(cfg.block_apple_private_relay);
    }

    #[test]
    fn test_normalize_github_blob_url() {
        let blob = "https://github.com/Turtlecute33/adblocktest/blob/master/src/d3host.txt";
        assert_eq!(
            normalize_feed_url(blob),
            "https://raw.githubusercontent.com/Turtlecute33/adblocktest/master/src/d3host.txt"
        );
        let blob_adblock =
            "https://github.com/Turtlecute33/adblocktest/blob/master/src/d3host.adblock";
        assert_eq!(
            normalize_feed_url(blob_adblock),
            "https://raw.githubusercontent.com/Turtlecute33/adblocktest/master/src/d3host.adblock"
        );
        let regular = "https://example.com/hosts.txt";
        assert_eq!(normalize_feed_url(regular), regular);
    }
}
