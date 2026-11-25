use crate::commands::router::connect_router;
use crate::TvCommands;
use anyhow::{bail, Context, Result};
use chrono::Local;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::process::Command;
use tokio::task::JoinSet;
use tokio::time::timeout;

const CLEANYOURTV_FACTS_URL: &str = "https://raw.githubusercontent.com/udhaykumarbala/cleanyourtv-app/main/core/spec/src/main/resources/tv/cleanyour/core/spec/facts.tsv";
const CACHE_FILE: &str = "config/cleanyourtv_facts.tsv";
const BACKUP_DIR: &str = "backups";

const PROTECTED_PACKAGES: &[&str] = &[
    "android",
    "com.android.systemui",
    "com.android.settings",
    "com.android.tv.settings",
    "com.android.vending",
    "com.google.android.gms",
    "com.google.android.gsf",
    "com.android.packageinstaller",
    "com.google.android.packageinstaller",
    "com.android.providers.settings",
    "com.android.providers.media",
    "com.android.providers.telephony",
    "com.android.bluetooth",
    "com.android.keyguard",
    "com.android.externalstorage",
    "com.android.inputmethod.latin",
    "com.google.android.inputmethod.latin",
    "com.android.server.telecom",
    "com.android.phone",
    "com.android.dialer",
    "com.android.contacts",
    "com.android.mms",
    "com.android.wifi.resources",
    "com.google.android.tungsten.setupwraith",
    "com.android.tv.frameworkpackagestubs",
    "com.google.android.tvlauncher",
    "com.google.android.leanbacklauncher",
    "com.google.android.apps.tv.launcherx",
    "com.amazon.firehomestarter",
    "com.amazon.tv.launcher",
    "com.miui.home",
    "com.sec.android.app.launcher",
    "com.huawei.android.launcher",
    "com.oppo.launcher",
    "com.android.networkstack",
    "com.google.android.networkstack",
];

/// Built-in OEM telemetry packages across phones, tablets, set-top boxes, and IoT Android builds.
/// Merged via Composite Pattern with CleanYourTV's upstream `facts.tsv`.
const BUILTIN_DEVICE_TELEMETRY_FACTS: &[(&str, &str, &str, &str)] = &[
    (
        "com.miui.analytics",
        "MIUI Analytics",
        "Xiaomi background usage & ad telemetry service",
        "tracking",
    ),
    (
        "com.miui.msa.global",
        "MIUI System Ads",
        "Xiaomi system-wide ad serving daemon (MSA)",
        "ads",
    ),
    (
        "com.xiaomi.joyose",
        "Xiaomi Joyose",
        "Xiaomi cloud gaming/device telemetry & ad service",
        "tracking",
    ),
    (
        "com.samsung.android.da.daagent",
        "Samsung Diagnostic Agent",
        "Samsung device analytics & diagnostic uploader",
        "tracking",
    ),
    (
        "com.samsung.android.rubin.app",
        "Samsung Customization Service",
        "Samsung cross-app behavioral profiling service",
        "tracking",
    ),
    (
        "com.huawei.bd",
        "Huawei BigData",
        "Huawei/Honor HiAnalytics background telemetry reporter",
        "tracking",
    ),
    (
        "com.facebook.system",
        "Meta App Installer",
        "Preloaded Meta system telemetry & silent installer",
        "preloads",
    ),
    (
        "com.facebook.appmanager",
        "Meta App Manager",
        "Preloaded Meta background update & telemetry agent",
        "preloads",
    ),
    (
        "com.facebook.services",
        "Meta Services",
        "Preloaded Meta background analytics helper",
        "preloads",
    ),
];

const SAFE_DISABLE_CATEGORIES: &[&str] = &["ads", "tracking", "preloads", "brand", "demo"];

/// Device keyword taxonomy covering all Android ADB-capable IoT devices.
///
/// # Design Pattern: Strategy Pattern
/// Each keyword slice is a separate detection "strategy".  The combined list is applied via a
/// single `.any()` scan over hostname / model strings, keeping O(k) match cost with zero
/// additional trait objects or dynamic dispatch overhead.
///
/// Covers:
/// - Smart TVs & streaming sticks (all major brands)
/// - Android smartphones / tablets (OEM telemetry: Xiaomi, Huawei, OPPO, Vivo, Realme, Samsung)
/// - Android set-top boxes (MiBox, Mecool, NVidia Shield, Fire TV)
/// - IP cameras with Android OS (Reolink, Dahua, Hikvision)
/// - Smart speakers and home automation hubs (Echo, Google Home, Nest)
/// - Gaming consoles with Android bridge (Android TV Stick + console keyword)
const DEVICE_KEYWORDS: &[&str] = &[
    // ── Smart TVs & Streaming Sticks ─────────────────────────────────
    "tv",
    "box",
    "stick",
    "mibox",
    "playbox",
    "trueid",
    "bravia",
    "sony",
    "tcl",
    "hisense",
    "shield",
    "firetv",
    "firestick",
    "roku",
    "chromecast",
    "google-tv",
    "androidtv",
    "smarttv",
    "vestel",
    "haier",
    "skyworth",
    "changhong",
    "panasonic",
    "philips",
    "sharp",
    "toshiba",
    "formuler",
    "mecool",
    // ── Smartphones / Tablets (OEM telemetry-heavy) ──────────────────
    "xiaomi",
    "mitv",
    "redmi",
    "mi-",
    "poco",
    "huawei",
    "honor",
    "oppo",
    "vivo",
    "realme",
    "oneplus",
    "samsung",
    "galaxy",
    "lg",
    // ── Android Boxes / Streaming Hubs ───────────────────────────────
    "nvidia",
    "amlogic",
    "rockchip",
    // ── IP Cameras (Android-based) ───────────────────────────────────
    "reolink",
    "dahua",
    "hikvision",
    "arlo",
    "ezviz",
    // ── Smart Speakers / Home Automation ─────────────────────────────
    "echo",
    "alexa",
    "googlenest",
    "nest",
    "homehub",
    "homemini",
    "tuya",
    "smartlife",
];

/// Legacy alias kept for backward compatibility with existing tests and callers.
#[allow(dead_code)]
const TV_KEYWORDS: &[&str] = DEVICE_KEYWORDS;

#[derive(Debug, Clone)]
pub struct PackageFact {
    pub name: String,
    pub description: String,
    pub category: String,
}

#[derive(Debug, Clone)]
pub struct DisableCandidate {
    pub package: String,
    pub name: String,
    pub category: String,
    pub description: String,
    pub already_disabled: bool,
}

#[derive(Debug, Clone)]
pub struct AnalysisReport {
    pub total_packages: usize,
    pub currently_disabled: usize,
    pub protected_count: usize,
    pub to_disable: Vec<DisableCandidate>,
    pub summary_by_category: BTreeMap<String, usize>,
}

#[derive(Debug, Serialize, Deserialize)]
struct TvSnapshot {
    tv_ip: String,
    timestamp: String,
    all_packages: Vec<String>,
    originally_disabled: Vec<String>,
    newly_disabled: Vec<String>,
}

pub fn parse_facts_tsv(raw: &str) -> HashMap<String, PackageFact> {
    let mut facts = HashMap::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = trimmed.split('\t').collect();
        if parts.len() >= 4 {
            let pkg = parts[0].trim().to_string();
            facts.insert(
                pkg,
                PackageFact {
                    name: parts[1].trim().to_string(),
                    description: parts[2].trim().to_string(),
                    category: parts[3].trim().to_string(),
                },
            );
        }
    }
    facts
}

async fn fetch_facts(
    cache_file: &Path,
    force_refresh: bool,
) -> Result<HashMap<String, PackageFact>> {
    let raw_text = if force_refresh || !cache_file.exists() {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(8))
            .user_agent("HomeShield-TVManager/1.0")
            .build()?;

        match client.get(CLEANYOURTV_FACTS_URL).send().await {
            Ok(resp) if resp.status().is_success() => {
                let text = resp.text().await?;
                if let Some(parent) = cache_file.parent() {
                    let _ = tokio::fs::create_dir_all(parent).await;
                }
                let _ = tokio::fs::write(cache_file, &text).await;
                text
            }
            _ if cache_file.exists() => tokio::fs::read_to_string(cache_file).await?,
            _ => String::new(),
        }
    } else {
        tokio::fs::read_to_string(cache_file).await?
    };

    Ok(parse_facts_tsv(&raw_text))
}

fn is_ipv4(token: &str) -> bool {
    let mut count = 0;
    for part in token.split('.') {
        if part.parse::<u8>().is_err() {
            return false;
        }
        count += 1;
    }
    count == 4
}

fn is_mac(token: &str) -> bool {
    let sep = if token.contains(':') {
        ':'
    } else if token.contains('-') {
        '-'
    } else {
        return false;
    };
    let parts: Vec<&str> = token.split(sep).collect();
    parts.len() == 6
        && parts
            .iter()
            .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
}

pub fn parse_router_leases(leases_output: &str) -> Vec<(String, String, String, bool)> {
    let mut candidates = Vec::new();
    let mut seen_ips = HashSet::new();

    for line in leases_output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("IP address") {
            continue;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        let mut ip_match: Option<String> = None;
        let mut mac_match: Option<String> = None;
        let mut hostname = String::new();

        for token in &parts {
            if is_ipv4(token) {
                ip_match = Some((*token).to_string());
            } else if is_mac(token) {
                mac_match = Some(token.to_ascii_lowercase());
            }
        }

        if parts.len() >= 4 && parts[3] != "*" && !is_mac(parts[3]) {
            hostname = parts[3].to_string();
        }

        let Some(ip) = ip_match else { continue };
        if ip.starts_with("127.") || !seen_ips.insert(ip.clone()) {
            continue;
        }

        let lower_host = hostname.to_ascii_lowercase();
        let is_tv_candidate = TV_KEYWORDS.iter().any(|kw| lower_host.contains(kw));
        candidates.push((
            ip,
            mac_match.unwrap_or_else(|| "unknown".to_string()),
            if hostname.is_empty() {
                "(unnamed)".to_string()
            } else {
                hostname
            },
            is_tv_candidate,
        ));
    }

    candidates
}

async fn is_port_open(ip: &str, port: u16, timeout_ms: u64) -> bool {
    let addr = format!("{ip}:{port}");
    matches!(
        timeout(Duration::from_millis(timeout_ms), TcpStream::connect(&addr)).await,
        Ok(Ok(_))
    )
}

async fn run_adb(args: &[&str], timeout_secs: u64) -> Result<(i32, String)> {
    let fut = Command::new("adb").args(args).output();
    match timeout(Duration::from_secs(timeout_secs), fut).await {
        Ok(Ok(out)) => {
            let code = out.status.code().unwrap_or(-1);
            let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
            combined.push_str(&String::from_utf8_lossy(&out.stderr));
            Ok((code, combined))
        }
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            bail!("`adb` executable not found on host system")
        }
        Ok(Err(e)) => Err(e.into()),
        Err(_) => bail!("ADB command timed out"),
    }
}

/// Device classification taxonomy (Strategy Pattern).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceCategory {
    SmartTv,
    SmartphoneTablet,
    IpCamera,
    SmartSpeaker,
    GamingConsole,
    GenericAndroid,
}

impl std::fmt::Display for DeviceCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeviceCategory::SmartTv => write!(f, "Smart TV / Streaming"),
            DeviceCategory::SmartphoneTablet => write!(f, "Smartphone / Tablet"),
            DeviceCategory::IpCamera => write!(f, "IP Camera / NVR"),
            DeviceCategory::SmartSpeaker => write!(f, "Smart Speaker / Hub"),
            DeviceCategory::GamingConsole => write!(f, "Gaming Console"),
            DeviceCategory::GenericAndroid => write!(f, "Android / IoT Device"),
        }
    }
}

/// Classify any LAN/ADB device by hostname, product model, and `ro.build.characteristics`.
pub fn classify_device(
    hostname: &str,
    model: Option<&str>,
    characteristics: Option<&str>,
) -> DeviceCategory {
    let chars = characteristics.unwrap_or("").to_ascii_lowercase();
    if chars.contains("tv") || chars.contains("leanback") {
        return DeviceCategory::SmartTv;
    }

    let combined = format!(
        "{} {}",
        hostname.to_ascii_lowercase(),
        model.unwrap_or("").to_ascii_lowercase()
    );

    if [
        "reolink",
        "dahua",
        "hikvision",
        "arlo",
        "ezviz",
        "ipcam",
        "camera",
    ]
    .iter()
    .any(|k| combined.contains(k))
    {
        return DeviceCategory::IpCamera;
    }
    if [
        "echo",
        "alexa",
        "googlenest",
        "nest",
        "homehub",
        "homemini",
        "tuya",
        "smartlife",
    ]
    .iter()
    .any(|k| combined.contains(k))
    {
        return DeviceCategory::SmartSpeaker;
    }
    if ["playstation", "ps4", "ps5", "xbox", "nintendo", "switch"]
        .iter()
        .any(|k| combined.contains(k))
    {
        return DeviceCategory::GamingConsole;
    }
    if [
        "redmi", "mi-", "poco", "xiaomi", "galaxy", "samsung", "oppo", "vivo", "realme", "oneplus",
        "huawei", "honor", "pixel", "ipad", "iphone",
    ]
    .iter()
    .any(|k| combined.contains(k))
    {
        return DeviceCategory::SmartphoneTablet;
    }
    if [
        "tv",
        "box",
        "stick",
        "mibox",
        "playbox",
        "trueid",
        "bravia",
        "sony",
        "tcl",
        "hisense",
        "shield",
        "firetv",
        "firestick",
        "roku",
        "chromecast",
        "google-tv",
        "androidtv",
        "smarttv",
        "vestel",
        "haier",
        "skyworth",
        "changhong",
        "panasonic",
        "philips",
        "sharp",
        "toshiba",
        "lg",
        "formuler",
        "mecool",
        "mitv",
    ]
    .iter()
    .any(|k| combined.contains(k))
    {
        return DeviceCategory::SmartTv;
    }

    DeviceCategory::GenericAndroid
}

fn builtin_device_fact(pkg: &str) -> Option<PackageFact> {
    BUILTIN_DEVICE_TELEMETRY_FACTS
        .iter()
        .find(|(p, _, _, _)| *p == pkg)
        .map(|(_, name, desc, cat)| PackageFact {
            name: (*name).to_string(),
            description: (*desc).to_string(),
            category: (*cat).to_string(),
        })
}

async fn connect_and_verify_device(target_ip: &str) -> Result<DeviceCategory> {
    let target = format!("{target_ip}:5555");
    println!("[*] Connecting to Android/IoT device at {target}...");
    let (_code, out) = run_adb(&["connect", &target], 8).await?;
    if !out.contains("connected to") && !out.contains("already connected") {
        let msg = out.trim();
        bail!(
            "Connection failed: {}",
            if msg.is_empty() {
                "Connection timed out"
            } else {
                msg
            }
        );
    }

    let (_dcode, dev_out) = run_adb(&["devices"], 5).await?;
    for line in dev_out.lines() {
        if line.contains(&target) && line.contains("unauthorized") {
            bail!("Device is unauthorized. Please check the device screen and select 'Always allow from this computer'.");
        }
    }

    let (_, chars_raw) = run_adb(
        &[
            "-s",
            &target,
            "shell",
            "getprop",
            "ro.build.characteristics",
        ],
        5,
    )
    .await?;
    let (_, model_raw) =
        run_adb(&["-s", &target, "shell", "getprop", "ro.product.model"], 5).await?;
    let chars = chars_raw.trim().to_ascii_lowercase();
    let model = model_raw.trim();
    let category = classify_device("", Some(model), Some(&chars));

    println!(
        "[*] Device Verified: Model: {}, Profile: {}, Characteristics: {}",
        if model.is_empty() { "Unknown" } else { model },
        category,
        if chars.is_empty() { "standard" } else { &chars }
    );
    Ok(category)
}

async fn get_installed_packages(tv_ip: &str) -> Result<(Vec<String>, Vec<String>)> {
    let target = format!("{tv_ip}:5555");
    let (_, all_out) = run_adb(&["-s", &target, "shell", "pm", "list", "packages"], 15).await?;
    let (_, dis_out) = run_adb(
        &["-s", &target, "shell", "pm", "list", "packages", "-d"],
        15,
    )
    .await?;

    let parse_pkgs = |raw: &str| -> Vec<String> {
        let mut pkgs: Vec<String> = raw
            .lines()
            .filter_map(|l| {
                l.trim()
                    .strip_prefix("package:")
                    .map(|s| s.trim().to_string())
            })
            .collect();
        pkgs.sort();
        pkgs
    };

    Ok((parse_pkgs(&all_out), parse_pkgs(&dis_out)))
}

pub fn analyze_packages_from_lists(
    all_pkgs: &[String],
    disabled_pkgs: &[String],
    facts: &HashMap<String, PackageFact>,
) -> AnalysisReport {
    let disabled_set: HashSet<&str> = disabled_pkgs.iter().map(String::as_str).collect();
    let protected_set: HashSet<&str> = PROTECTED_PACKAGES.iter().copied().collect();
    let disable_cats: HashSet<&str> = SAFE_DISABLE_CATEGORIES.iter().copied().collect();

    let mut protected_count = 0usize;
    let mut to_disable = Vec::new();
    let mut summary_by_category: BTreeMap<String, usize> = BTreeMap::new();

    for pkg in all_pkgs {
        if protected_set.contains(pkg.as_str()) {
            protected_count += 1;
            continue;
        }
        let fact_opt = facts.get(pkg).cloned().or_else(|| builtin_device_fact(pkg));
        if let Some(fact) = fact_opt {
            *summary_by_category
                .entry(fact.category.clone())
                .or_insert(0) += 1;
            if disable_cats.contains(fact.category.as_str()) {
                to_disable.push(DisableCandidate {
                    package: pkg.clone(),
                    name: fact.name,
                    category: fact.category,
                    description: fact.description,
                    already_disabled: disabled_set.contains(pkg.as_str()),
                });
            }
        }
    }

    AnalysisReport {
        total_packages: all_pkgs.len(),
        currently_disabled: disabled_pkgs.len(),
        protected_count,
        to_disable,
        summary_by_category,
    }
}

async fn create_snapshot_and_rollback_script(
    backup_dir: &Path,
    tv_ip: &str,
    all_pkgs: &[String],
    disabled_pkgs: &[String],
    target_disable: &[String],
) -> Result<(PathBuf, PathBuf)> {
    tokio::fs::create_dir_all(backup_dir).await?;
    let timestamp = Local::now().format("%Y%m%d_%H%M%S").to_string();
    let safe_ip = tv_ip.replace('.', "_");

    let snapshot_file = backup_dir.join(format!("tv_snapshot_{safe_ip}_{timestamp}.json"));
    let restore_sh_file = backup_dir.join(format!("restore_{safe_ip}_{timestamp}.sh"));

    let snapshot = TvSnapshot {
        tv_ip: tv_ip.to_string(),
        timestamp: timestamp.clone(),
        all_packages: all_pkgs.to_vec(),
        originally_disabled: disabled_pkgs.to_vec(),
        newly_disabled: target_disable.to_vec(),
    };
    tokio::fs::write(&snapshot_file, serde_json::to_string_pretty(&snapshot)?).await?;

    let mut lines = vec![
        "#!/bin/sh".to_string(),
        format!("# Standalone Rollback Script for Smart TV at {tv_ip}"),
        format!("# Generated by HomeShield on {timestamp}"),
        "# Usage: sh restore.sh [TV_IP]".to_string(),
        String::new(),
        format!("TV_TARGET=\"${{1:-{tv_ip}:5555}}\""),
        "echo \"Connecting to ${TV_TARGET}...\"".to_string(),
        "adb connect \"${TV_TARGET}\"".to_string(),
        "echo \"Re-enabling packages...\"".to_string(),
    ];
    for pkg in target_disable {
        lines.push(format!("adb -s \"${{TV_TARGET}}\" shell pm enable {pkg}"));
    }
    lines.push(String::new());
    lines.push("echo \"Rollback complete! All packages restored.\"".to_string());
    lines.push(String::new());

    tokio::fs::write(&restore_sh_file, lines.join("\n")).await?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o755);
        std::fs::set_permissions(&restore_sh_file, perms)?;
    }

    Ok((snapshot_file, restore_sh_file))
}

async fn cmd_discover(router_ip: &str) -> Result<()> {
    println!("[*] Discovering Smart TVs, Smartphones, Cameras & IoT devices on LAN via Router ({router_ip})...");
    let leases_output = match connect_router(router_ip).await {
        Ok(mut session) => session
            .run_cmd(
                "cat /tmp/dhcp.leases 2>/dev/null || \
                     cat /var/lib/misc/dnsmasq.leases 2>/dev/null || \
                     cat /var/tmp/dnsmasq.leases 2>/dev/null || \
                     cat /proc/net/arp 2>/dev/null",
                Duration::from_secs(10),
            )
            .await
            .unwrap_or_default(),
        Err(_) => String::new(),
    };

    let candidates = parse_router_leases(&leases_output);

    // Scatter-Gather Pattern: probe all LAN hosts on ADB port 5555 concurrently via JoinSet
    // so discovery takes ~800ms total instead of N * 800ms sequentially.
    let mut probe_set = JoinSet::new();
    for (idx, (ip, mac, hostname, is_device)) in candidates.into_iter().enumerate() {
        probe_set.spawn(async move {
            let adb_ready = is_port_open(&ip, 5555, 800).await;
            (idx, ip, mac, hostname, is_device, adb_ready)
        });
    }

    let mut probed = Vec::new();
    while let Some(Ok(item)) = probe_set.join_next().await {
        probed.push(item);
    }
    probed.sort_by_key(|item| item.0);

    let mut found = Vec::new();
    for (_idx, ip, mac, hostname, is_device, adb_ready) in probed {
        if adb_ready || is_device {
            let category = classify_device(&hostname, None, None);
            found.push((ip, mac, hostname, category, adb_ready));
        }
    }

    if found.is_empty() {
        println!("[-] No candidate IoT/Android devices found in router DHCP/ARP table.");
        println!(
            "    Note: Network-wide DNS telemetry shielding is already active on all LAN devices."
        );
        println!("    For deep package debloating, enable 'Network Debugging' (ADB) on Android TVs/devices.");
        return Ok(());
    }

    println!("\nFound {} device(s):", found.len());
    println!(
        "{:<16} {:<18} {:<22} {:<22} {:<12}",
        "IP Address", "MAC Address", "Hostname", "Device Type", "ADB (5555)"
    );
    println!("{}", "-".repeat(94));
    for (ip, mac, hostname, category, adb_ready) in found {
        let adb_str = if adb_ready {
            "READY (OPEN)"
        } else {
            "DNS SHIELDED"
        };
        println!(
            "{ip:<16} {mac:<18} {hostname:<22} {:<22} {adb_str:<12}",
            category.to_string()
        );
    }
    Ok(())
}

async fn cmd_analyze(tv_ip: &str) -> Result<()> {
    let category = connect_and_verify_device(tv_ip).await?;
    println!("[*] Fetching package facts (CleanYourTV + built-in OEM telemetry rules)...");
    let facts = fetch_facts(Path::new(CACHE_FILE), false).await?;
    println!("[*] Analyzing installed packages on {tv_ip} ({category})...");
    let (all_pkgs, dis_pkgs) = get_installed_packages(tv_ip).await?;
    let report = analyze_packages_from_lists(&all_pkgs, &dis_pkgs, &facts);

    println!("\n=== DEVICE TELEMETRY & PACKAGE AUDIT REPORT ({category}) ===");
    println!("Total Installed Packages: {}", report.total_packages);
    println!("Currently Disabled:       {}", report.currently_disabled);
    println!("Protected System Core:    {}", report.protected_count);
    println!("Candidates to Debloat:    {}", report.to_disable.len());
    println!("\nBreakdown by Category (Candidates):");
    for (cat, cnt) in &report.summary_by_category {
        println!("  - {cat:<15}: {cnt} package(s)");
    }

    println!("\nTop Candidates to Disable:");
    for item in report.to_disable.iter().take(15) {
        let status = if item.already_disabled {
            "(already disabled)"
        } else {
            ""
        };
        println!(
            "  [{}] {} - {} {}",
            item.category.to_ascii_uppercase(),
            item.package,
            item.name,
            status
        );
        if !item.description.is_empty() {
            println!("       Info: {}", item.description);
        }
    }
    if report.to_disable.len() > 15 {
        println!("  ... and {} more packages.", report.to_disable.len() - 15);
    }
    Ok(())
}

async fn cmd_clean(tv_ip: &str, dry_run: bool) -> Result<()> {
    let category = connect_and_verify_device(tv_ip).await?;
    println!("[*] Running Safe Debloat on {tv_ip} ({category}, Dry Run: {dry_run})...");
    let facts = fetch_facts(Path::new(CACHE_FILE), false).await?;
    let (all_pkgs, dis_pkgs) = get_installed_packages(tv_ip).await?;
    let report = analyze_packages_from_lists(&all_pkgs, &dis_pkgs, &facts);

    let to_disable: Vec<String> = report
        .to_disable
        .into_iter()
        .filter(|c| !c.already_disabled)
        .map(|c| c.package)
        .collect();

    let (snapshot_file, rollback_script) = create_snapshot_and_rollback_script(
        Path::new(BACKUP_DIR),
        tv_ip,
        &all_pkgs,
        &dis_pkgs,
        &to_disable,
    )
    .await?;

    let mut disabled_count = 0usize;
    let mut failed = Vec::new();

    if !dry_run {
        let target = format!("{tv_ip}:5555");
        for pkg in &to_disable {
            let (code, out) = run_adb(
                &[
                    "-s",
                    &target,
                    "shell",
                    "pm",
                    "disable-user",
                    "--user",
                    "0",
                    pkg,
                ],
                15,
            )
            .await?;
            if out.contains("new state: disabled") || code == 0 {
                disabled_count += 1;
            } else {
                failed.push((pkg.clone(), out.trim().to_string()));
            }
        }
    }

    println!("\n=== CLEAN OPERATION SUMMARY ===");
    println!("Target Packages to Disable: {}", to_disable.len());
    println!("Successfully Disabled:      {disabled_count}");
    println!("Snapshot Backup Created:    {}", snapshot_file.display());
    println!("Standalone Rollback Script: {}", rollback_script.display());
    if !failed.is_empty() {
        println!("\nFailed to disable ({}):", failed.len());
        for (pkg, err) in failed {
            println!("  - {pkg}: {err}");
        }
    }
    println!("\nNote: You can rollback anytime with:");
    println!("  homeshield tv restore --target {tv_ip}");
    println!("  OR directly on host: sh {}", rollback_script.display());
    Ok(())
}

fn find_latest_snapshot(backup_dir: &Path, tv_ip: &str) -> Result<PathBuf> {
    let safe_ip = tv_ip.replace('.', "_");
    let prefix = format!("tv_snapshot_{safe_ip}_");
    let mut matches: Vec<PathBuf> = std::fs::read_dir(backup_dir)
        .with_context(|| format!("Failed to read backup dir {}", backup_dir.display()))?
        .filter_map(|e| e.ok().map(|entry| entry.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(&prefix) && n.ends_with(".json"))
        })
        .collect();
    matches.sort();
    matches
        .pop()
        .with_context(|| format!("No snapshots found for {tv_ip} in {}", backup_dir.display()))
}

async fn cmd_restore(tv_ip: &str, snapshot: Option<PathBuf>) -> Result<()> {
    let _category = connect_and_verify_device(tv_ip).await?;
    println!("[*] Restoring disabled packages on {tv_ip}...");
    let snap_path = match snapshot {
        Some(p) => p,
        None => find_latest_snapshot(Path::new(BACKUP_DIR), tv_ip)?,
    };

    let raw = tokio::fs::read_to_string(&snap_path).await?;
    let snap: TvSnapshot = serde_json::from_str(&raw)?;
    let target = format!("{tv_ip}:5555");
    let mut restored = 0usize;

    for pkg in &snap.newly_disabled {
        let (code, out) = run_adb(&["-s", &target, "shell", "pm", "enable", pkg], 15).await?;
        if out.contains("new state: enabled") || code == 0 {
            restored += 1;
        }
    }

    println!("[+] Successfully restored {restored} package(s)!");
    println!("    Snapshot used: {}", snap_path.display());
    Ok(())
}

/// Dispatch `homeshield tv` subcommands.
pub async fn run(action: TvCommands) -> Result<()> {
    match action {
        TvCommands::Discover { ip } => cmd_discover(ip.as_deref().unwrap_or("192.168.1.1")).await,
        TvCommands::Analyze { target } => cmd_analyze(&target).await,
        TvCommands::Clean { target, dry_run } => cmd_clean(&target, dry_run).await,
        TvCommands::Restore { target, snapshot } => cmd_restore(&target, snapshot).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_router_leases_filters_tv_candidates() {
        let leases = "\
1700000000 aa:bb:cc:dd:ee:01 192.168.1.50 MiBox4 *
1700000000 aa:bb:cc:dd:ee:02 192.168.1.51 MacBook-Pro *
1700000000 00:11:22:33:44:55 127.0.0.1 localhost *
";
        let parsed = parse_router_leases(leases);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0, "192.168.1.50");
        assert!(parsed[0].3);
        assert_eq!(parsed[1].0, "192.168.1.51");
        assert!(!parsed[1].3);
    }

    #[test]
    fn test_analyze_protects_core_and_targets_ads() {
        let tsv = "com.android.systemui\tSystem UI\tCore UI\tads\ncom.example.adservice\tAd Service\tTracks ads\tads\ncom.example.player\tMedia Player\tVideo\tmedia\n";
        let facts = parse_facts_tsv(tsv);
        let all = vec![
            "com.android.systemui".to_string(),
            "com.example.adservice".to_string(),
            "com.example.player".to_string(),
        ];
        let disabled = vec![];
        let report = analyze_packages_from_lists(&all, &disabled, &facts);
        assert_eq!(report.protected_count, 1);
        assert_eq!(report.to_disable.len(), 1);
        assert_eq!(report.to_disable[0].package, "com.example.adservice");
    }

    #[test]
    fn test_classify_device_all_iot_types() {
        assert_eq!(
            classify_device("MiBox4", None, None),
            DeviceCategory::SmartTv
        );
        assert_eq!(
            classify_device("Redmi-Note-12", None, None),
            DeviceCategory::SmartphoneTablet
        );
        assert_eq!(
            classify_device("Reolink-Cam-01", None, None),
            DeviceCategory::IpCamera
        );
        assert_eq!(
            classify_device("Amazon-Echo-Dot", None, None),
            DeviceCategory::SmartSpeaker
        );
        assert_eq!(
            classify_device("PS5-LivingRoom", None, None),
            DeviceCategory::GamingConsole
        );
        assert_eq!(
            classify_device("unknown", Some("Pixel 8"), Some("tv,leanback")),
            DeviceCategory::SmartTv
        );
    }

    #[test]
    fn test_analyze_protects_phone_core_and_catches_builtin_oem_telemetry() {
        let facts = HashMap::new();
        let all = vec![
            "com.android.phone".to_string(),
            "com.miui.home".to_string(),
            "com.miui.analytics".to_string(),
            "com.miui.msa.global".to_string(),
            "com.samsung.android.da.daagent".to_string(),
        ];
        let report = analyze_packages_from_lists(&all, &[], &facts);
        assert_eq!(report.protected_count, 2);
        assert_eq!(report.to_disable.len(), 3);
    }
}
