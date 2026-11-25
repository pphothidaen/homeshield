use crate::engine::AdblockEngine;
use crate::supervisor::Supervisor;
use crate::system::{format_utc_timestamp, CommandOutput, SystemOps};
use homeshield_core::blocklist::BlocklistCompiler;
use homeshield_core::config::HomeShieldConfig;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use std::io::{self, Cursor};
use std::path::PathBuf;
use std::rc::Rc;

#[derive(Default)]
struct MockState {
    epoch: u64,
    connected: bool,
    hup_count: usize,
    feeds: HashMap<String, String>,
    existing_iptables_rules: Vec<Vec<String>>,
    recorded_commands: Vec<(String, Vec<String>)>,
    daemon_pids: Vec<u32>,
}

#[derive(Clone)]
struct MockSystem {
    state: Rc<RefCell<MockState>>,
}

impl MockSystem {
    fn new(epoch: u64, connected: bool) -> Self {
        Self {
            state: Rc::new(RefCell::new(MockState {
                epoch,
                connected,
                ..Default::default()
            })),
        }
    }
}

impl SystemOps for MockSystem {
    fn now_epoch(&self) -> u64 {
        self.state.borrow().epoch
    }

    fn format_timestamp(&self, epoch: u64) -> String {
        format_utc_timestamp(epoch)
    }

    fn run_command(&self, program: &str, args: &[&str]) -> io::Result<CommandOutput> {
        let arg_vec: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        let mut st = self.state.borrow_mut();
        st.recorded_commands
            .push((program.to_string(), arg_vec.clone()));

        if program == "iptables" || program == "ip6tables" {
            // Simulate -C rule check vs -I rule insertion
            if let Some(c_pos) = arg_vec.iter().position(|a| a == "-C") {
                let mut check_sig = vec![program.to_string()];
                if c_pos >= 2 && arg_vec[0] == "-t" {
                    check_sig.push(arg_vec[1].clone());
                } else {
                    check_sig.push("filter".to_string());
                }
                check_sig.extend(arg_vec[c_pos + 1..].iter().cloned());
                let exists = st.existing_iptables_rules.contains(&check_sig);
                return Ok(CommandOutput {
                    status_code: if exists { 0 } else { 1 },
                    stdout: String::new(),
                    stderr: String::new(),
                });
            }
            if let Some(i_pos) = arg_vec.iter().position(|a| a == "-I") {
                let mut rule_sig = vec![program.to_string()];
                if i_pos >= 2 && arg_vec[0] == "-t" {
                    rule_sig.push(arg_vec[1].clone());
                } else {
                    rule_sig.push("filter".to_string());
                }
                rule_sig.push(arg_vec[i_pos + 1].clone()); // chain
                rule_sig.extend(arg_vec[i_pos + 3..].iter().cloned()); // skip index "1"
                st.existing_iptables_rules.push(rule_sig);
                return Ok(CommandOutput {
                    status_code: 0,
                    stdout: String::new(),
                    stderr: String::new(),
                });
            }
        }

        Ok(CommandOutput {
            status_code: 1,
            stdout: String::new(),
            stderr: String::new(),
        })
    }

    fn fetch_url_lines(&self, url: &str, compiler: &mut BlocklistCompiler) -> io::Result<usize> {
        let body = self.state.borrow().feeds.get(url).cloned();
        match body {
            Some(content) => compiler.process_reader(Cursor::new(content)),
            None => Err(io::Error::new(io::ErrorKind::NotFound, "mock 404")),
        }
    }

    fn signal_dnsmasq_hup(&self) -> io::Result<()> {
        self.state.borrow_mut().hup_count += 1;
        Ok(())
    }

    fn find_process_pids(&self, _name_substr: &str) -> Vec<u32> {
        self.state.borrow().daemon_pids.clone()
    }

    fn check_connectivity(&self) -> bool {
        self.state.borrow().connected
    }

    fn sleep_seconds(&self, _secs: u64) {}
}

struct TempWorkspace {
    dir: PathBuf,
}

impl TempWorkspace {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("homeshield_test_{name}_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp workspace");
        Self { dir }
    }

    fn config(&self) -> HomeShieldConfig {
        HomeShieldConfig {
            primary_cdn_url: None,
            blocklist_urls: vec![
                "https://mock.local/hosts".to_string(),
                "https://mock.local/yt".to_string(),
            ],
            update_interval_seconds: 604_800,
            whitelist_file: self.dir.join("whitelist.txt"),
            backup_file: self.dir.join("backup_adblock.hosts"),
            last_update_file: self.dir.join("last_update"),
            last_epoch_file: self.dir.join("last_epoch"),
            paused_file: self.dir.join("adblock.paused"),
            ram_hosts_file: self.dir.join("ram_adblock.hosts"),
            base_hosts_file: self.dir.join("hosts.base"),
            system_hosts_file: self.dir.join("hosts"),
            block_dot: true,
            block_canary_doh: true,
            block_apple_private_relay: true,
            min_valid_lines: 5,
        }
    }
}

impl Drop for TempWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn test_update_pause_resume_and_status_lifecycle() {
    let ws = TempWorkspace::new("lifecycle");
    let cfg = ws.config();
    fs::write(&cfg.whitelist_file, "kasikornbank.com\naisplay.ais.co.th\n").unwrap();
    fs::write(&cfg.system_hosts_file, "127.0.0.1 localhost\n").unwrap();

    let sys = MockSystem::new(1_750_000_000, true);
    {
        let mut st = sys.state.borrow_mut();
        st.feeds.insert(
            "https://mock.local/hosts".to_string(),
            "0.0.0.0 doubleclick.net\n\
             0.0.0.0 kasikornbank.com\n\
             0.0.0.0 ads.yahoo.com\n\
             127.0.0.1 tracker.example.com\n"
                .to_string(),
        );
        st.feeds.insert(
            "https://mock.local/yt".to_string(),
            "||s.youtube.com^\n\
             ||aisplay.ais.co.th^\n\
             r1---sn-ad.googlevideo.com\n"
                .to_string(),
        );
        st.daemon_pids = vec![4242];
    }

    let engine = AdblockEngine::new(cfg.clone(), sys.clone());
    assert!(engine.do_update().expect("do_update"));

    // Verify RAM & Backup created, dual-stack written, and dnsmasq reloaded
    let sys_hosts = fs::read_to_string(&cfg.system_hosts_file).unwrap();
    assert!(sys_hosts.contains("127.0.0.1 localhost"));
    assert!(sys_hosts.contains("0.0.0.0 doubleclick.net"));
    assert!(sys_hosts.contains(":: doubleclick.net"));
    assert!(sys_hosts.contains("0.0.0.0 s.youtube.com"));
    assert!(sys_hosts.contains("0.0.0.0 use-application-dns.net"));
    assert!(sys_hosts.contains("0.0.0.0 mask.icloud.com"));
    assert!(!sys_hosts.contains("kasikornbank.com"));
    assert!(!sys_hosts.contains("aisplay.ais.co.th"));
    assert_eq!(sys.state.borrow().hup_count, 1);

    // Status should report ACTIVE, 9 domains (5 parsed + 1 canary + 3 apple relay), and PID 4242
    let status = engine.do_status().unwrap();
    assert!(status.active);
    assert_eq!(status.blocked_domains, 9);
    let report = status.format_report();
    assert!(report.contains("STATUS: ACTIVE"));
    assert!(report.contains("BLOCKED_DOMAINS: 9"));
    assert!(report.contains("Rust Daemon PID 4242"));

    // Pause should clear adblock entries from system hosts
    engine.do_stop().unwrap();
    let paused_hosts = fs::read_to_string(&cfg.system_hosts_file).unwrap();
    assert!(!paused_hosts.contains("doubleclick.net"));
    assert!(paused_hosts.contains("127.0.0.1 localhost"));
    assert_eq!(sys.state.borrow().hup_count, 2);
    assert!(!engine.do_status().unwrap().active);

    // Resume should immediately re-apply from RAM
    assert!(engine.do_start().unwrap());
    let resumed_hosts = fs::read_to_string(&cfg.system_hosts_file).unwrap();
    assert!(resumed_hosts.contains("0.0.0.0 doubleclick.net"));
    assert_eq!(sys.state.borrow().hup_count, 3);
}

#[test]
fn test_fail_closed_preserves_existing_blocklist() {
    let ws = TempWorkspace::new("failclosed");
    let cfg = ws.config();
    fs::write(&cfg.ram_hosts_file, "0.0.0.0 preserved-ad.com\n").unwrap();
    fs::write(&cfg.backup_file, "0.0.0.0 preserved-ad.com\n").unwrap();

    // Feeds return 20 comment lines + 1 domain (< min_valid_lines=5 unique domains)
    let sys = MockSystem::new(1_750_000_000, true);
    let mut padded = "# comment\n".repeat(20);
    padded.push_str("0.0.0.0 tiny.ad.com\n");
    sys.state
        .borrow_mut()
        .feeds
        .insert("https://mock.local/hosts".to_string(), padded);

    let engine = AdblockEngine::new(cfg.clone(), sys);
    assert!(!engine.do_update().expect("fail-closed returns false"));
    let ram = fs::read_to_string(&cfg.ram_hosts_file).unwrap();
    assert_eq!(ram, "0.0.0.0 preserved-ad.com\n");
}

#[test]
fn test_check_pre_ntp_and_reboot_ram_recovery() {
    let ws = TempWorkspace::new("recovery");
    let cfg = ws.config();
    fs::write(&cfg.backup_file, "0.0.0.0 recovered-ad.com\n").unwrap();

    // Clock < 1_700_000_000 (pre-NTP): must recover from flash without calling update
    let sys = MockSystem::new(1000, true);
    let engine = AdblockEngine::new(cfg.clone(), sys.clone());
    assert!(engine.do_check().unwrap());
    assert!(cfg.ram_hosts_file.exists());
    let sys_hosts = fs::read_to_string(&cfg.system_hosts_file).unwrap();
    assert!(sys_hosts.contains("0.0.0.0 recovered-ad.com"));
    assert!(sys_hosts.contains(":: recovered-ad.com"));
}

#[test]
fn test_supervisor_enforces_iptables_idempotently() {
    let ws = TempWorkspace::new("supervisor");
    let cfg = ws.config();
    fs::write(&cfg.backup_file, "0.0.0.0 recovered-ad.com\n").unwrap();
    fs::write(&cfg.last_epoch_file, "1750000000\n").unwrap();

    let sys = MockSystem::new(1_750_000_100, false);
    let engine = AdblockEngine::new(cfg.clone(), sys.clone());
    let mut sup = Supervisor::new(engine);

    sup.tick();

    let st = sys.state.borrow();
    // Should have inserted IPv4 NAT/DoT + IPv6 DNS/DoT anti-bypass rules
    assert!(st.existing_iptables_rules.iter().any(|r| {
        r == &vec![
            "iptables",
            "filter",
            "FORWARD",
            "-p",
            "tcp",
            "--dport",
            "853",
            "-j",
            "REJECT",
            "--reject-with",
            "tcp-reset",
        ]
    }));
    assert!(st.existing_iptables_rules.iter().any(|r| {
        r == &vec![
            "ip6tables",
            "filter",
            "FORWARD",
            "-i",
            "br0",
            "-p",
            "udp",
            "--dport",
            "53",
            "-j",
            "REJECT",
        ]
    }));
    assert!(st.existing_iptables_rules.iter().any(|r| {
        r == &vec![
            "ip6tables",
            "filter",
            "FORWARD",
            "-p",
            "tcp",
            "--dport",
            "853",
            "-j",
            "REJECT",
            "--reject-with",
            "tcp-reset",
        ]
    }));
    assert!(st.existing_iptables_rules.iter().any(|r| {
        r == &vec![
            "iptables",
            "nat",
            "PREROUTING",
            "-i",
            "br0",
            "-p",
            "udp",
            "--dport",
            "53",
            "-j",
            "REDIRECT",
            "--to-ports",
            "53",
        ]
    }));
    assert!(st.existing_iptables_rules.iter().any(|r| {
        r == &vec![
            "iptables",
            "nat",
            "PREROUTING",
            "-i",
            "br0",
            "-p",
            "tcp",
            "--dport",
            "53",
            "-j",
            "REDIRECT",
            "--to-ports",
            "53",
        ]
    }));
    drop(st);

    // Ticks 1..5 must skip iptables forks (stride=6); tick 6 re-checks -C without -I duplicates
    let cmds_before = sys.state.borrow().recorded_commands.len();
    for _ in 1..6 {
        sup.tick();
    }
    {
        let st = sys.state.borrow();
        let mid_cmds = &st.recorded_commands[cmds_before..];
        assert!(
            !mid_cmds
                .iter()
                .any(|(prog, _)| prog == "iptables" || prog == "ip6tables"),
            "intermediate ticks within stride must not spawn firewall subprocesses"
        );
    }

    let cmds_before_stride = sys.state.borrow().recorded_commands.len();
    sup.tick();
    {
        let st = sys.state.borrow();
        let stride_cmds = &st.recorded_commands[cmds_before_stride..];
        assert!(
            stride_cmds
                .iter()
                .any(|(prog, args)| prog == "iptables" && args.contains(&"-C".to_string())),
            "stride tick must re-verify iptables rules with -C"
        );
        assert!(
            !stride_cmds
                .iter()
                .any(|(prog, args)| (prog == "iptables" || prog == "ip6tables")
                    && args.contains(&"-I".to_string())),
            "firewall rules should be idempotent on stride tick"
        );
    }
}

#[test]
fn test_tier0_cdn_primary_and_automatic_fallback() {
    let ws = TempWorkspace::new("tier0cdn");
    let mut cfg = ws.config();
    cfg.primary_cdn_url = Some("https://cdn.local/hosts.txt".to_string());
    cfg.min_valid_lines = 2;

    // 1. Primary CDN succeeds -> skips direct fallback feeds
    let sys_cdn_ok = MockSystem::new(1_750_000_000, true);
    sys_cdn_ok.state.borrow_mut().feeds.insert(
        "https://cdn.local/hosts.txt".to_string(),
        "0.0.0.0 cdn-ad1.com\n0.0.0.0 cdn-ad2.com\n0.0.0.0 cdn-ad3.com\n".to_string(),
    );
    let eng_ok = AdblockEngine::new(cfg.clone(), sys_cdn_ok);
    assert!(eng_ok.do_update().unwrap());
    let hosts_ok = fs::read_to_string(&cfg.system_hosts_file).unwrap();
    assert!(hosts_ok.contains("0.0.0.0 cdn-ad1.com"));

    // 2. Primary CDN down -> automatically falls back to direct blocklist_urls
    let sys_fallback = MockSystem::new(1_750_000_000, true);
    sys_fallback.state.borrow_mut().feeds.insert(
        "https://mock.local/hosts".to_string(),
        "0.0.0.0 direct-ad1.com\n0.0.0.0 direct-ad2.com\n0.0.0.0 direct-ad3.com\n".to_string(),
    );
    let eng_fb = AdblockEngine::new(cfg.clone(), sys_fallback);
    assert!(eng_fb.do_update().unwrap());
    let hosts_fb = fs::read_to_string(&cfg.system_hosts_file).unwrap();
    assert!(hosts_fb.contains("0.0.0.0 direct-ad1.com"));
}

#[test]
fn test_toggle_zero_wear_delta_and_self_healing_hosts_wipe() {
    let ws = TempWorkspace::new("autonomous_enhancements");
    let mut cfg = ws.config();
    cfg.min_valid_lines = 2;

    let sys = MockSystem::new(1_750_000_000, true);
    sys.state.borrow_mut().feeds.insert(
        "https://mock.local/hosts".to_string(),
        "0.0.0.0 ad-one.com\n0.0.0.0 ad-two.com\n0.0.0.0 ad-three.com\n".to_string(),
    );

    let engine = AdblockEngine::new(cfg.clone(), sys.clone());
    assert!(engine.do_update().unwrap());
    assert_eq!(sys.state.borrow().hup_count, 1);

    // 1. Zero-wear delta check: second identical update must NOT rewrite flash or HUP dnsmasq
    fs::remove_file(&cfg.backup_file).unwrap();
    // Recreate backup with exact same content, then remove write permission to prove it is NOT opened for write
    fs::copy(&cfg.ram_hosts_file, &cfg.backup_file).unwrap();
    let mut perms = fs::metadata(&cfg.backup_file).unwrap().permissions();
    perms.set_readonly(true);
    fs::set_permissions(&cfg.backup_file, perms).unwrap();

    assert!(engine.do_update().unwrap());
    assert_eq!(
        sys.state.borrow().hup_count,
        1,
        "identical update must skip redundant dnsmasq HUP"
    );

    // 2. Toggle ACTIVE -> PAUSED -> ACTIVE
    let st_paused = engine.do_toggle().unwrap();
    assert!(!st_paused.active);
    assert_eq!(st_paused.blocked_domains, 0);

    let st_active = engine.do_toggle().unwrap();
    assert!(st_active.active);
    assert!(st_active.blocked_domains >= 3);

    // 3. Self-healing: firmware wipes system_hosts_file back to localhost while ram_hosts_file exists
    fs::write(&cfg.system_hosts_file, "127.0.0.1 localhost\n").unwrap();
    let st_wiped = engine.do_status().unwrap();
    assert_eq!(
        st_wiped.blocked_domains, 0,
        "status must not return stale sidecar count when system_hosts_file was wiped"
    );
    let mut sup = Supervisor::new(AdblockEngine::new(cfg.clone(), sys.clone()));
    sup.tick();
    let healed = fs::read_to_string(&cfg.system_hosts_file).unwrap();
    assert!(
        healed.contains("0.0.0.0 ad-one.com"),
        "supervisor must heal wiped system_hosts_file within 1 tick"
    );
    let st_healed = engine.do_status().unwrap();
    assert!(
        st_healed.blocked_domains >= 3,
        "status must report restored domain count after supervisor heals hosts"
    );

    // Cleanup readonly perm for TempWorkspace Drop
    let mut rw_perms = fs::metadata(&cfg.backup_file).unwrap().permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    rw_perms.set_readonly(false);
    let _ = fs::set_permissions(&cfg.backup_file, rw_perms);
}

#[test]
fn test_large_base_hosts_wipe_and_stale_sidecar_invalidation() {
    let ws = TempWorkspace::new("large_base_and_sidecar");
    let mut cfg = ws.config();
    cfg.min_valid_lines = 2;
    cfg.block_canary_doh = false;
    cfg.block_apple_private_relay = false;

    // Seed a base hosts file LARGER than the 2-domain blocklist (~400 bytes vs ~40 bytes)
    let mut large_base = String::from("127.0.0.1 localhost\n");
    for i in 10..25 {
        large_base.push_str(&format!("192.168.1.{i} lan-device-{i}.home.arpa\n"));
    }
    fs::write(&cfg.system_hosts_file, &large_base).unwrap();

    let sys = MockSystem::new(1_750_000_000, true);
    sys.state.borrow_mut().feeds.insert(
        "https://mock.local/hosts".to_string(),
        "0.0.0.0 ad-alpha.com\n0.0.0.0 ad-beta.com\n".to_string(),
    );

    let engine = AdblockEngine::new(cfg.clone(), sys.clone());
    assert!(engine.do_update().unwrap());
    assert!(
        fs::metadata(&cfg.base_hosts_file).unwrap().len()
            > fs::metadata(&cfg.backup_file).unwrap().len(),
        "precondition: base_hosts_file must be larger than backup_file"
    );
    assert_eq!(engine.do_status().unwrap().blocked_domains, 2);

    // 1. Firmware wipes system_hosts_file back to large_base (still > backup_file.len())
    fs::write(&cfg.system_hosts_file, &large_base).unwrap();
    assert_eq!(
        engine.do_status().unwrap().blocked_domains,
        0,
        "do_status must detect wipe even when base_hosts_file > backup_file"
    );

    // 2. Identical do_update() (flash_changed == false) must still re-apply wiped hosts
    assert!(engine.do_update().unwrap());
    assert_eq!(engine.do_status().unwrap().blocked_domains, 2);

    // 3. Wipe again and verify Supervisor::tick() heals it even when base_hosts_file > ram_hosts_file
    fs::write(&cfg.system_hosts_file, &large_base).unwrap();
    let mut sup = Supervisor::new(AdblockEngine::new(cfg.clone(), sys.clone()));
    sup.tick();
    assert_eq!(engine.do_status().unwrap().blocked_domains, 2);

    // 4. External tool (e.g. adblock.sh) overwrites backup/ram/system hosts with 3 domains
    // without updating the .domain_count sidecar -> do_status() must reject stale sidecar (2)
    let external_hosts = "0.0.0.0 ext-one.com\n0.0.0.0 ext-two.com\n0.0.0.0 ext-three.com\n";
    fs::write(&cfg.backup_file, external_hosts).unwrap();
    fs::write(&cfg.ram_hosts_file, external_hosts).unwrap();
    assert!(engine.apply_hosts().unwrap());
    assert_eq!(
        engine.do_status().unwrap().blocked_domains,
        3,
        "do_status must invalidate stale sidecar when backup_file length changed externally"
    );
}

#[test]
fn test_low_tmpfs_mode_without_ram_copy_stays_healthy_and_heals_wipe() {
    let ws = TempWorkspace::new("low_tmpfs_mode");
    let mut cfg = ws.config();
    cfg.min_valid_lines = 2;
    cfg.block_canary_doh = false;
    cfg.block_apple_private_relay = false;

    let sys = MockSystem::new(1_750_000_000, true);
    sys.state.borrow_mut().feeds.insert(
        "https://mock.local/hosts".to_string(),
        "0.0.0.0 low-one.com\n0.0.0.0 low-two.com\n".to_string(),
    );

    let engine = AdblockEngine::new(cfg.clone(), sys.clone());
    assert!(engine.do_update().unwrap());
    assert_eq!(engine.do_status().unwrap().blocked_domains, 2);

    // Simulate ENOSPC fallback dropping redundant ram_hosts_file while backup_file & system_hosts_file remain intact
    fs::remove_file(&cfg.ram_hosts_file).unwrap();
    assert_eq!(engine.do_status().unwrap().blocked_domains, 2);

    // Supervisor::tick() and do_check() must NOT thrash by recreating ram_hosts_file when system_hosts_file is healthy
    let mut sup = Supervisor::new(AdblockEngine::new(cfg.clone(), sys.clone()));
    sup.tick();
    assert!(
        !cfg.ram_hosts_file.exists(),
        "healthy low-tmpfs state must not needlessly recreate ram_hosts_file"
    );

    // If firmware wipes system_hosts_file, Supervisor::tick() must still heal from backup_file
    fs::write(&cfg.system_hosts_file, "127.0.0.1 localhost\n").unwrap();
    sup.tick();
    assert_eq!(engine.do_status().unwrap().blocked_domains, 2);
}
