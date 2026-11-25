use crate::engine::{file_len, is_nonempty_file, min_applied_hosts_len, AdblockEngine};
use crate::system::SystemOps;
use std::fs;
use std::io::Write;
use std::path::Path;

pub const DEFAULT_CHECK_INTERVAL_SECS: u64 = 1800;
pub const DEFAULT_WATCHDOG_SLEEP_SECS: u64 = 5;
/// Re-verify iptables/routing every 6 ticks (6 * 5s = 30s) to slash fork/exec load by 6x
/// while keeping zero-fork RAM hosts & display checks responsive every 5s.
pub const DEFAULT_FIREWALL_TICK_STRIDE: u64 = 6;

pub struct Supervisor<S: SystemOps> {
    pub engine: AdblockEngine<S>,
    pub last_check_epoch: u64,
    pub check_interval_secs: u64,
    pub sleep_secs: u64,
    pub tick_count: u64,
    pub firewall_tick_stride: u64,
}

impl<S: SystemOps> Supervisor<S> {
    pub fn new(engine: AdblockEngine<S>) -> Self {
        Self {
            engine,
            last_check_epoch: 0,
            check_interval_secs: DEFAULT_CHECK_INTERVAL_SECS,
            sleep_secs: DEFAULT_WATCHDOG_SLEEP_SECS,
            tick_count: 0,
            firewall_tick_stride: DEFAULT_FIREWALL_TICK_STRIDE,
        }
    }

    /// Ensure an iptables or ip6tables rule exists in the given chain; insert at index 1 if absent.
    pub fn ensure_firewall_rule(
        &self,
        program: &str,
        table: Option<&str>,
        chain: &str,
        rule_args: &[&str],
    ) {
        let mut check_args: Vec<&str> = Vec::with_capacity(rule_args.len() + 4);
        if let Some(t) = table {
            check_args.push("-t");
            check_args.push(t);
        }
        check_args.push("-C");
        check_args.push(chain);
        check_args.extend_from_slice(rule_args);

        let exists = self
            .engine
            .sys
            .run_command(program, &check_args)
            .map(|o| o.status_code == 0)
            .unwrap_or(false);

        if !exists {
            let mut insert_args: Vec<&str> = Vec::with_capacity(rule_args.len() + 5);
            if let Some(t) = table {
                insert_args.push("-t");
                insert_args.push(t);
            }
            insert_args.push("-I");
            insert_args.push(chain);
            insert_args.push("1");
            insert_args.extend_from_slice(rule_args);

            let _ = self.engine.sys.run_command(program, &insert_args);
        }
    }

    pub fn ensure_iptables_rule(&self, table: Option<&str>, chain: &str, rule_args: &[&str]) {
        self.ensure_firewall_rule("iptables", table, chain, rule_args);
    }

    /// Enforce Layer 4 Anti-Bypass and Layer 3/7 Transparent DNS Interception rules (IPv4 & IPv6).
    pub fn ensure_firewall_and_routing(&self) {
        // 1. Optional USB serial display hook (if attached)
        self.handle_display_hook();

        // 2. Network routing / bridge hairpin hook (when br0/wlan0 exist)
        self.ensure_bridge_routing();

        // 3. Transparent DNS Interception (LAN IPv4 port 53 -> local dnsmasq)
        self.ensure_iptables_rule(
            Some("nat"),
            "PREROUTING",
            &[
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
            ],
        );
        self.ensure_iptables_rule(
            Some("nat"),
            "PREROUTING",
            &[
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
            ],
        );

        // 4. IPv6 DNS Anti-Bypass: reject external LAN IPv6 DNS (ISP RDNSS/8.8.8.8v6) so clients
        // fall back instantaneously to local router dnsmasq (192.168.1.1 / [fe80::1]).
        self.ensure_firewall_rule(
            "ip6tables",
            None,
            "FORWARD",
            &["-i", "br0", "-p", "udp", "--dport", "53", "-j", "REJECT"],
        );
        self.ensure_firewall_rule(
            "ip6tables",
            None,
            "FORWARD",
            &["-i", "br0", "-p", "tcp", "--dport", "53", "-j", "REJECT"],
        );

        // 5. Layer 4 Anti-Bypass: Reject DNS-over-TLS (port 853, IPv4 + IPv6) with tcp-reset
        if self.engine.config.block_dot {
            self.ensure_iptables_rule(
                None,
                "FORWARD",
                &[
                    "-p",
                    "tcp",
                    "--dport",
                    "853",
                    "-j",
                    "REJECT",
                    "--reject-with",
                    "tcp-reset",
                ],
            );
            self.ensure_firewall_rule(
                "ip6tables",
                None,
                "FORWARD",
                &[
                    "-p",
                    "tcp",
                    "--dport",
                    "853",
                    "-j",
                    "REJECT",
                    "--reject-with",
                    "tcp-reset",
                ],
            );
        }
    }

    fn handle_display_hook(&self) {
        let tty_path = Path::new("/dev/ttyACM0");
        if !tty_path.exists() {
            return;
        }
        let active_conn = fs::read_to_string("/proc/net/tcp")
            .map(|tcp| {
                tcp.lines()
                    .any(|l| l.contains(":1D97 ") && l.contains(" 01 "))
            })
            .unwrap_or(false);
        if !active_conn {
            if let Ok(mut f) = fs::OpenOptions::new().write(true).open(tty_path) {
                let _ = f.write_all(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x6c]);
            }
        }
    }

    fn ensure_bridge_routing(&self) {
        if let Ok(out) = self
            .engine
            .sys
            .run_command("ip", &["addr", "show", "dev", "br0"])
        {
            if out.status_code == 0 && !out.stdout.contains("192.168.168.1") {
                let _ = self
                    .engine
                    .sys
                    .run_command("ip", &["addr", "add", "192.168.168.1/24", "dev", "br0"]);
            }
        }
        if let Ok(out) = self
            .engine
            .sys
            .run_command("ip", &["route", "show", "table", "250"])
        {
            if out.status_code == 0 && !out.stdout.contains("192.168.168.0") {
                let _ = self.engine.sys.run_command(
                    "ip",
                    &[
                        "route",
                        "add",
                        "192.168.168.0/24",
                        "dev",
                        "br0",
                        "table",
                        "250",
                    ],
                );
            }
        }

        ensure_sysfs_one(Path::new("/proc/sys/net/ipv4/ip_forward"));
        ensure_sysfs_one(Path::new("/sys/class/net/br0/brif/wlan0/hairpin_mode"));

        self.ensure_iptables_rule(
            Some("nat"),
            "POSTROUTING",
            &[
                "-o",
                "br0",
                "-s",
                "192.168.1.0/24",
                "-d",
                "192.168.168.0/24",
                "-j",
                "MASQUERADE",
            ],
        );
        self.ensure_iptables_rule(
            Some("nat"),
            "POSTROUTING",
            &[
                "-o",
                "br0",
                "-s",
                "192.168.168.0/24",
                "-d",
                "192.168.1.0/24",
                "-j",
                "MASQUERADE",
            ],
        );
    }

    /// Execute one watchdog supervision cycle.
    pub fn tick(&mut self) {
        #[allow(clippy::manual_is_multiple_of)]
        // MSRV 1.83 compatibility in cross-compile container
        if self.firewall_tick_stride <= 1 || self.tick_count % self.firewall_tick_stride == 0 {
            self.ensure_firewall_and_routing();
        } else {
            self.handle_display_hook();
        }
        self.tick_count = self.tick_count.wrapping_add(1);

        // Self-healing guard: restore sinkhole immediately if RAM cache vanished OR if firmware
        // (e.g. ZTE cspd during WAN reconnect) wiped /var/tmp/hosts smaller than active blocklist.
        let cfg = &self.engine.config;
        if !cfg.paused_file.exists() {
            let active_src = if is_nonempty_file(&cfg.ram_hosts_file) {
                Some(&cfg.ram_hosts_file)
            } else if is_nonempty_file(&cfg.backup_file) {
                Some(&cfg.backup_file)
            } else {
                None
            };
            if let Some(src) = active_src {
                let sys_len = file_len(&cfg.system_hosts_file);
                let min_applied_len = min_applied_hosts_len(&cfg.base_hosts_file, src);
                if sys_len < min_applied_len {
                    let _ = self.engine.do_start();
                }
            }
        }

        let now = self.engine.sys.now_epoch();
        if self.last_check_epoch == 0
            || now.saturating_sub(self.last_check_epoch) >= self.check_interval_secs
        {
            let _ = self.engine.do_check();
            self.last_check_epoch = now;
        }
    }

    /// Run indefinitely as the single resident HomeShield daemon.
    pub fn run_forever(&mut self) -> ! {
        loop {
            self.tick();
            self.engine.sys.sleep_seconds(self.sleep_secs);
        }
    }
}

fn ensure_sysfs_one(path: &Path) {
    if !path.exists() {
        return;
    }
    if let Ok(val) = fs::read_to_string(path) {
        if val.trim() != "1" {
            let _ = fs::write(path, b"1");
        }
    }
}
