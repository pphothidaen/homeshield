use std::borrow::Cow;
use std::collections::HashSet;
use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;

pub const CANARY_DOH_DOMAINS: &[&str] = &["use-application-dns.net"];
pub const APPLE_PRIVATE_RELAY_DOMAINS: &[&str] = &[
    "mask.icloud.com",
    "mask-h2.icloud.com",
    "mask-api.fe.apple-dns.net",
];

const RESERVED_HOSTNAMES: &[&str] = &[
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
    "0.0.0.0",
];

/// Load whitelist domains from any buffered reader.
pub fn load_whitelist<R: BufRead>(mut reader: R) -> io::Result<HashSet<String>> {
    let mut wl = HashSet::new();
    let mut line = String::with_capacity(128);
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let clean = match trimmed.find('#') {
            Some(idx) => trimmed[..idx].trim(),
            None => trimmed,
        };
        if let Some(token) = clean.split_whitespace().next() {
            let normalized = token.to_ascii_lowercase();
            if !normalized.is_empty() {
                wl.insert(normalized);
            }
        }
    }
    Ok(wl)
}

/// Load whitelist from file if present; returns an empty set if missing.
pub fn load_whitelist_from_file(path: &Path) -> io::Result<HashSet<String>> {
    match File::open(path) {
        Ok(file) => load_whitelist(BufReader::new(file)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(HashSet::new()),
        Err(e) => Err(e),
    }
}

/// Check if a domain string is syntactically valid for DNS sinkholing.
pub fn is_valid_domain(domain: &str) -> bool {
    let len = domain.len();
    if len == 0 || len > 253 {
        return false;
    }
    if domain.starts_with('.')
        || domain.ends_with('.')
        || domain.starts_with('-')
        || domain.ends_with('-')
        || domain.contains("..")
    {
        return false;
    }

    let Some(dot_pos) = domain.rfind('.') else {
        return false;
    };
    let tld = &domain[dot_pos + 1..];
    if tld.is_empty()
        || !tld.bytes().all(|b| b.is_ascii_alphanumeric())
        || !tld.bytes().any(|b| b.is_ascii_alphabetic())
    {
        return false;
    }

    if !domain
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
    {
        return false;
    }

    !RESERVED_HOSTNAMES
        .iter()
        .any(|reserved| domain.eq_ignore_ascii_case(reserved))
}

/// Extract a sinkholeable domain from a single blocklist line.
///
/// Supports:
/// - Hosts format (`0.0.0.0 domain`, `127.0.0.1 domain`)
/// - Adblock Plus / AdGuard domain rules (`||domain^`, `||domain^$third-party`)
/// - Plain domain list (`ads.example.com`)
pub fn parse_domain_line(raw_line: &str) -> Option<Cow<'_, str>> {
    let trimmed = raw_line.trim();
    if trimmed.is_empty()
        || trimmed.starts_with('#')
        || trimmed.starts_with('!')
        || trimmed.starts_with('[')
        || trimmed.starts_with("@@")
    {
        return None;
    }

    let candidate: &str = if let Some(rest) = trimmed
        .strip_prefix("0.0.0.0")
        .or_else(|| trimmed.strip_prefix("127.0.0.1"))
    {
        if !rest.starts_with(|c: char| c.is_ascii_whitespace()) {
            return None;
        }
        let after_ip = rest.trim_start();
        let no_comment = match after_ip.find('#') {
            Some(idx) => after_ip[..idx].trim_end(),
            None => after_ip,
        };
        no_comment.split_whitespace().next()?
    } else if let Some(rest) = trimmed.strip_prefix("||") {
        let end = rest
            .find(|c: char| c == '^' || c == '$' || c == '/' || c == '#' || c.is_ascii_whitespace())
            .unwrap_or(rest.len());
        let domain = &rest[..end];
        if domain.contains('*') {
            return None;
        }
        domain
    } else {
        let no_comment = match trimmed.find('#') {
            Some(idx) => trimmed[..idx].trim(),
            None => trimmed,
        };
        if no_comment.split_whitespace().count() != 1 {
            return None;
        }
        no_comment
    };

    if !is_valid_domain(candidate) {
        return None;
    }

    if candidate.bytes().any(|b| b.is_ascii_uppercase()) {
        Some(Cow::Owned(candidate.to_ascii_lowercase()))
    } else {
        Some(Cow::Borrowed(candidate))
    }
}

/// Streaming multi-source blocklist compiler with O(1) deduplication and whitelist filtering.
/// Uses `Rc<str>` so `seen` and `domains` share a single heap allocation per unique domain.
///
/// # Design Patterns
/// - **Builder & Strategy Patterns**: `with_capacity()` pre-sizes internal collections to avoid
///   O(n) rehashing when processing 300k+ domains across 29+ feeds.
/// - **Flyweight Pattern**: `whitelist` is stored behind `Arc<HashSet<String>>` via
///   `with_shared_whitelist()`, allowing zero-clone fallback rebuilds.
pub struct BlocklistCompiler {
    whitelist: Arc<HashSet<String>>,
    seen: HashSet<Rc<str>>,
    domains: Vec<Rc<str>>,
    raw_lines: usize,
}

impl BlocklistCompiler {
    /// Create a compiler with a default small capacity (suitable for unit tests / small feeds).
    pub fn new(whitelist: HashSet<String>) -> Self {
        Self::with_capacity(whitelist, 4_096)
    }

    /// Create a compiler with a caller-supplied capacity hint (Builder Pattern).
    pub fn with_capacity(whitelist: HashSet<String>, capacity_hint: usize) -> Self {
        Self::with_shared_whitelist(Arc::new(whitelist), capacity_hint)
    }

    /// Create a compiler sharing an existing immutable whitelist via `Arc` (Flyweight Pattern).
    pub fn with_shared_whitelist(whitelist: Arc<HashSet<String>>, capacity_hint: usize) -> Self {
        Self {
            whitelist,
            seen: HashSet::with_capacity(capacity_hint),
            domains: Vec::with_capacity(capacity_hint),
            raw_lines: 0,
        }
    }

    /// Stream and parse lines from a reader without retaining raw source text in memory.
    /// Returns the number of newly added unique domains from this reader.
    pub fn process_reader<R: BufRead>(&mut self, mut reader: R) -> io::Result<usize> {
        let mut line = String::with_capacity(256);
        let mut added = 0usize;

        loop {
            line.clear();
            if reader.read_line(&mut line)? == 0 {
                break;
            }
            self.raw_lines += 1;

            if let Some(domain) = parse_domain_line(&line) {
                let d_ref = domain.as_ref();
                if !self.whitelist.contains(d_ref) && !self.seen.contains(d_ref) {
                    let shared: Rc<str> = Rc::from(d_ref);
                    self.seen.insert(Rc::clone(&shared));
                    self.domains.push(shared);
                    added += 1;
                }
            }
        }

        Ok(added)
    }

    /// Inject anti-bypass Canary DoH & Apple Private Relay domains unless explicitly whitelisted.
    pub fn inject_anti_bypass(&mut self, block_canary_doh: bool, block_apple_private_relay: bool) {
        if block_canary_doh {
            for &domain in CANARY_DOH_DOMAINS {
                self.insert_domain(domain);
            }
        }
        if block_apple_private_relay {
            for &domain in APPLE_PRIVATE_RELAY_DOMAINS {
                self.insert_domain(domain);
            }
        }
    }

    fn insert_domain(&mut self, domain: &str) {
        if !self.whitelist.contains(domain) && !self.seen.contains(domain) {
            let shared: Rc<str> = Rc::from(domain);
            self.seen.insert(Rc::clone(&shared));
            self.domains.push(shared);
        }
    }

    pub fn raw_lines_count(&self) -> usize {
        self.raw_lines
    }

    pub fn unique_domains_count(&self) -> usize {
        self.domains.len()
    }

    pub fn domains(&self) -> &[Rc<str>] {
        &self.domains
    }

    /// Write canonical `0.0.0.0 <domain>` lines to a writer using a 128 KB buffer.
    pub fn write_hosts<W: Write>(&self, writer: W) -> io::Result<usize> {
        let mut buf = BufWriter::with_capacity(128 * 1024, writer);
        for domain in &self.domains {
            buf.write_all(b"0.0.0.0 ")?;
            buf.write_all(domain.as_bytes())?;
            buf.write_all(b"\n")?;
        }
        buf.flush()?;
        Ok(self.domains.len())
    }
}

/// Stream a pre-compiled, pre-sorted Tier 0 CDN blocklist directly to a writer with O(1) RAM
/// (~256 KB I/O buffers instead of a 50+ MB `HashSet`), applying local whitelist filtering,
/// adjacent duplicate suppression, and optional anti-bypass domain injection.
///
/// Returns `(cdn_domains_written, total_domains_written_including_anti_bypass)`.
pub fn stream_precompiled_hosts<R: BufRead, W: Write>(
    mut reader: R,
    writer: W,
    whitelist: &HashSet<String>,
    block_canary_doh: bool,
    block_apple_private_relay: bool,
) -> io::Result<(usize, usize)> {
    let mut buf = BufWriter::with_capacity(128 * 1024, writer);
    let mut line = String::with_capacity(256);
    let mut prev = String::with_capacity(128);
    let mut cdn_count = 0usize;
    let mut seen_canary = false;
    let mut seen_apple = [false; 3];

    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        if let Some(domain) = parse_domain_line(&line) {
            let d_ref = domain.as_ref();
            if whitelist.contains(d_ref) || d_ref == prev.as_str() {
                continue;
            }
            if d_ref == CANARY_DOH_DOMAINS[0] {
                seen_canary = true;
            } else {
                for (i, &ad) in APPLE_PRIVATE_RELAY_DOMAINS.iter().enumerate() {
                    if d_ref == ad {
                        seen_apple[i] = true;
                    }
                }
            }
            buf.write_all(b"0.0.0.0 ")?;
            buf.write_all(d_ref.as_bytes())?;
            buf.write_all(b"\n")?;
            prev.clear();
            prev.push_str(d_ref);
            cdn_count += 1;
        }
    }

    let mut total_count = cdn_count;
    if block_canary_doh {
        let d = CANARY_DOH_DOMAINS[0];
        if !seen_canary && !whitelist.contains(d) {
            buf.write_all(b"0.0.0.0 ")?;
            buf.write_all(d.as_bytes())?;
            buf.write_all(b"\n")?;
            total_count += 1;
        }
    }
    if block_apple_private_relay {
        for (i, &d) in APPLE_PRIVATE_RELAY_DOMAINS.iter().enumerate() {
            if !seen_apple[i] && !whitelist.contains(d) {
                buf.write_all(b"0.0.0.0 ")?;
                buf.write_all(d.as_bytes())?;
                buf.write_all(b"\n")?;
                total_count += 1;
            }
        }
    }

    buf.flush()?;
    Ok((cdn_count, total_count))
}

/// Merge `base_hosts` and `adblock_hosts` into a dual-stack (`0.0.0.0` + `::`) hosts file
/// in a single streaming pass without spawning `awk` or `cat`.
pub fn write_dual_stack_hosts<R: BufRead, W: Write>(
    base_hosts_content: &str,
    mut adblock_reader: R,
    writer: W,
) -> io::Result<usize> {
    let mut buf = BufWriter::with_capacity(128 * 1024, writer);
    if !base_hosts_content.is_empty() {
        buf.write_all(base_hosts_content.as_bytes())?;
        if !base_hosts_content.ends_with('\n') {
            buf.write_all(b"\n")?;
        }
    }

    let mut line = String::with_capacity(128);
    let mut count = 0usize;
    loop {
        line.clear();
        if adblock_reader.read_line(&mut line)? == 0 {
            break;
        }
        let trimmed = line.trim();
        if let Some(domain) = trimmed.strip_prefix("0.0.0.0 ") {
            let domain = domain.trim();
            if !domain.is_empty() {
                buf.write_all(b"0.0.0.0 ")?;
                buf.write_all(domain.as_bytes())?;
                buf.write_all(b"\n:: ")?;
                buf.write_all(domain.as_bytes())?;
                buf.write_all(b"\n")?;
                count += 1;
            }
        }
    }

    buf.flush()?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_universal_parser_and_whitelist_parity() {
        let wl = load_whitelist(Cursor::new("kasikornbank.com\nais.co.th # Thai portal\n"))
            .expect("load whitelist");
        let raw_feed = "\
# Comment line
! Adblock comment
[Adblock Plus 2.0]
0.0.0.0 localhost
0.0.0.0 doubleclick.net
127.0.0.1 pagead2.googlesyndication.com # inline comment
||s.youtube.com^
||ads.youtube.com^$third-party
@@||whitelist-exception.example.com^
||*.wildcard.example.com^
r1---sn-test.googlevideo.com
0.0.0.0 kasikornbank.com
||AIS.CO.TH^
0.0.0.0 DOUBLECLICK.NET
192.168.1.1
";

        let mut compiler = BlocklistCompiler::new(wl);
        compiler
            .process_reader(Cursor::new(raw_feed))
            .expect("process feed");
        compiler.inject_anti_bypass(true, true);

        let mut out = Vec::new();
        compiler.write_hosts(&mut out).expect("write hosts");
        let text = String::from_utf8(out).expect("utf8");
        let lines: Vec<&str> = text.lines().collect();

        assert!(lines.contains(&"0.0.0.0 doubleclick.net"));
        assert!(lines.contains(&"0.0.0.0 pagead2.googlesyndication.com"));
        assert!(lines.contains(&"0.0.0.0 s.youtube.com"));
        assert!(lines.contains(&"0.0.0.0 ads.youtube.com"));
        assert!(lines.contains(&"0.0.0.0 r1---sn-test.googlevideo.com"));
        assert!(lines.contains(&"0.0.0.0 use-application-dns.net"));
        assert!(lines.contains(&"0.0.0.0 mask.icloud.com"));
        assert!(lines.contains(&"0.0.0.0 mask-h2.icloud.com"));
        assert!(lines.contains(&"0.0.0.0 mask-api.fe.apple-dns.net"));

        assert!(!lines.contains(&"0.0.0.0 kasikornbank.com"));
        assert!(!lines.contains(&"0.0.0.0 ais.co.th"));
        assert!(!lines.contains(&"0.0.0.0 localhost"));
        assert!(!lines.contains(&"0.0.0.0 192.168.1.1"));

        // 5 unique parsed domains + 1 canary + 3 apple relay = 9
        assert_eq!(lines.len(), 9);
    }

    #[test]
    fn test_load_real_repo_whitelist() {
        let wl_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../config/whitelist.txt");
        let wl = load_whitelist_from_file(&wl_path).expect("read config/whitelist.txt");
        assert!(wl.contains("kasikornbank.com"));
        assert!(wl.contains("aisplay.ais.co.th"));
        assert!(wl.contains("fcm.googleapis.com"));
    }

    #[test]
    fn test_dual_stack_hosts_generation() {
        let base = "127.0.0.1 localhost.localdomain localhost\n";
        let adblock = "0.0.0.0 doubleclick.net\n0.0.0.0 ads.youtube.com\n";
        let mut out = Vec::new();
        let cnt =
            write_dual_stack_hosts(base, Cursor::new(adblock), &mut out).expect("write dual stack");
        assert_eq!(cnt, 2);

        let text = String::from_utf8(out).expect("utf8");
        assert_eq!(
            text,
            "127.0.0.1 localhost.localdomain localhost\n\
             0.0.0.0 doubleclick.net\n\
             :: doubleclick.net\n\
             0.0.0.0 ads.youtube.com\n\
             :: ads.youtube.com\n"
        );
    }

    #[test]
    fn test_stream_precompiled_hosts_filters_whitelist_dedups_and_injects_anti_bypass() {
        let input = "\
# Tier 0 pre-compiled
0.0.0.0 a.ads.test
0.0.0.0 a.ads.test
0.0.0.0 b.whitelisted.test
0.0.0.0 mask.icloud.com
";
        let mut wl = HashSet::new();
        wl.insert("b.whitelisted.test".to_string());

        let mut out = Vec::new();
        let (cdn_count, total_count) =
            stream_precompiled_hosts(Cursor::new(input), &mut out, &wl, true, true).unwrap();
        assert_eq!(cdn_count, 2);
        assert_eq!(total_count, 5);

        let text = String::from_utf8(out).unwrap();
        assert_eq!(text.matches("0.0.0.0 a.ads.test\n").count(), 1);
        assert_eq!(text.matches("0.0.0.0 mask.icloud.com\n").count(), 1);
        assert!(!text.contains("b.whitelisted.test"));
        assert!(text.contains("0.0.0.0 use-application-dns.net\n"));
        assert!(text.contains("0.0.0.0 mask-h2.icloud.com\n"));
        assert!(text.contains("0.0.0.0 mask-api.fe.apple-dns.net\n"));
    }
}
