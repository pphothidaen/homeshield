# Changelog

All notable changes to **HomeShield** are documented here. Versions follow [Semantic Versioning](https://semver.org/).

## 1.2.0 (2026-11-25)

### Performance Fine-Tuning (Design Patterns) & Universal IoT Telemetry Shield
- **Builder & Strategy Pattern (`BlocklistCompiler::with_capacity`):** Pre-sizes `HashSet` & `Vec` to `300,000+` capacity across `homeshield-daemon` and `homeshield-cli compile`, eliminating repeated O(n) rehashing on embedded ARMv7 and CI builds.
- **Flyweight Pattern (`Arc<HashSet<String>>`):** Shares immutable whitelist via `BlocklistCompiler::with_shared_whitelist` for zero-clone CDN fallback rebuilds.
- **Cache-Aside Pattern (`domain_count` Sidecar):** Writes verified unique domain count during `do_update()` so `do_status()` reads in O(1) without scanning 8 MB+ hosts files (reporting `0` cleanly when `PAUSED`).
- **Buffer Reuse Pattern & 128 KB Streaming I/O:** Upgraded `file_len_and_fnv1a`, `write_hosts`, `write_dual_stack_hosts`, `apply_hosts`, `ensure_base_hosts`, and fallback `count_blocked_v4_domains` to 128 KB buffers and single reused `String` line buffers (eliminating 600k+ heap allocations).
- **Single-Pass Visitor Pattern (`/proc` scan):** Added `SystemOps::find_any_process_pids` to locate resident daemon processes in 1 `/proc` directory walk instead of 3.
- **Scatter-Gather Pattern (`JoinSet` LAN Probe):** Parallelized ADB port 5555 discovery across all LAN DHCP/ARP leases (~800 ms total instead of N × 800 ms sequentially).
- **Universal IoT & Device Telemetry Blocking (29 Live Feeds):** Added 8 verified telemetry feeds (`native.amazon.txt`, `native.apple.txt`, `native.huawei.txt`, `native.oppo-realme.txt`, `native.vivo.txt`, `native.roku.txt`, `native.winoffice.txt`, `WindowsSpyBlocker/spy.txt`) + `device` CLI alias + `DeviceCategory` classifier (`Smart TV`, `Smartphone / Tablet`, `IP Camera`, `Smart Speaker`, `Gaming Console`) + built-in OEM telemetry fallback rules & mobile core protection.

## 1.1.1 (2026-11-25)

### Bug Fix: Canary Binary Pull Timeout (`DL_RC=28`)

- **Fixed `deploy_rust_canary` Telnet race condition:** The Telnet `run_cmd` loop was detecting a shell prompt (`# `) before BusyBox `curl` finished downloading the 461 KB ARMv7 daemon, causing it to return early with `DL_RC=28`. The curl process was then orphaned and killed.
- **Fix:** Replaced the synchronous `curl … ; echo DL_RC=$?` block with a **background curl + poll** pattern. Curl runs detached (`&`) and writes its exit code to `/tmp/hs_dl_rc` on completion. The deploy function polls that marker file every second (up to 70 s) before reading the result — completely immune to Telnet prompt-detection timing.
- **Result:** `homeshield deploy --engine rust` now successfully transfers the ARMv7 daemon, passes the RAM Canary check, promotes to `/userconfig/homeshield-daemon`, and reports `ROUTER_AUTONOMY: FULLY_AUTONOMOUS (Rust Daemon PID ...)` on first run.

## 1.1.0 (2026-11-25)

### Unified Rust Management CLI (`homeshield-cli`)
- **Tier 0 Blocklist Pre-Compiler in Rust (`compile`):** Migrated CI blocklist compilation (`.github/workflows/compile-blocklist.yml`) to `homeshield-cli` reusing `homeshield-core::blocklist::BlocklistCompiler` with concurrent `reqwest` feed downloads and fail-closed minimum domain checks.
- **Router Management & Canary Deploy (`deploy`, `status`, `toggle`, `update`, `uninstall`):** Implemented async Telnet client, ZTE Factory Mode AES-192-ECB challenge-response negotiation, and ephemeral HTTP LAN file server in `rust/crates/cli/`.
- **CleanYourTV ADB Manager (`tv discover|analyze|clean|restore`):** Ported Smart TV discovery, CleanYourTV `facts.tsv` audit, safe `pm disable-user --user 0` debloating, JSON snapshots, and POSIX rollback script generation to Rust.
- **Feed Health Cleanup:** Verified all upstream feeds in `config/adblock.conf` and removed 4 dead 404 URLs, keeping 17 healthy feeds passing CI health checks.

## 1.0.0 (2026-11-25)

### HomeShield Rebrand & Anti-Scam Cyber-Shield Positioning
- **Full Clean Cutover to HomeShield:** Rebranded CLI (`homeshield.py`), embedded Rust workspace (`homeshield-core`, `homeshield-daemon`), package metadata (`pyproject.toml`), CI workflows, and visual assets.
- **Integrated TurtleCute Ad Blocker Test Feeds (`d3host.txt` & `d3host.adblock`):** Added automated 24h sync with `Turtlecute33/adblocktest` upstream feeds into `compile_blocklist.py`, `config/adblock.conf`, and `homeshield-core`. Added automatic normalization of GitHub blob URLs (`github.com/.../blob/...` -> `raw.githubusercontent.com/...`) across Python and Rust to ensure robust downloads.
- **Anti-Scam & 4 Core Security Pillars:** Repositioned `README.md` around real-world household cyber threats (fake banking/gov APKs, malvertising inside LINE/Facebook webviews, gambling traps, and Smart TV/IoT telemetry) with a full comparison matrix against Pi-hole, browser extensions, and paid ISP addons.
- **Level 3 Rollback (`uninstall` Subcommand):** Added `python3 homeshield.py uninstall` to cleanly terminate resident daemons, flush `iptables`/`ip6tables` rules, restore `/var/tmp/hosts`, and purge `/userconfig/` persistence.

## 0.3.0 (2026-11-25)

### Autonomous Self-Healing, Zero-Wear Daily Sync & Toggle Feature
- **Daily Autonomous Sync (24h) with Zero-Wear Flash Delta Check:** Tightened `UPDATE_INTERVAL_SECONDS` from `604800` (7 days) to `86400` (24 hours) to stay in lockstep with the daily GitHub Actions Tier 0 CDN build. Added streaming FNV-1a 64-bit checksum + byte-length verification in `AdblockEngine::do_update` so unchanged blocklists skip rewriting the 8.1 MB `/userconfig/adblock.hosts` MTD Flash partition and skip redundant `dnsmasq` reloads.
- **Self-Healing `/var/tmp/hosts` Wipe Recovery:** Extended `Supervisor::tick()` to monitor `file_len(system_hosts_file) < file_len(ram_hosts_file)` via lightweight `stat()` syscalls. If router firmware (`cspd`) resets `/var/tmp/hosts` during a WAN/PPP reconnect, HomeShield automatically re-applies dual-stack sinkholing within 5 seconds.
- **Atomic `toggle` Command:** Added `toggle` subcommand across `homeshield-daemon`, `scripts/adblock.sh`, and `homeshield.py` to flip `ACTIVE <-> PAUSED` in a single command (verified end-to-end with Kapture MCP before/after browser testing).
- **Operations Playbook & 4-Tier Rollback Plan:** Published comprehensive [`docs/PLAYBOOK.md`](docs/PLAYBOOK.md) documenting pre-flight checks, daily routine operations, atomic toggle SOPs, incident response, and 4-tier disaster recovery (Soft-Rollback, Engine Fallback, Gateway Purge, and Smart TV restoration).
- **Hardware & Switch Matrix:** Expanded compatibility documentation across ONTs (ZTE, Huawei, FiberHome, Nokia), OpenWrt SBC gateways (GL.iNet, NanoPi, Raspberry Pi CM4), consumer routers (Asuswrt-Merlin, EdgeOS, RouterOS), and Managed L3 Switches (Cisco Catalyst, Aruba CX, MikroTik CRS) via Policy-Based Routing (PBR) and DHCP Option 6.
- **`Rc<str>` Memory Deduplication:** Shared string allocations between `HashSet` and `Vec` inside `BlocklistCompiler`, cutting heap allocations in half (`VmRSS` down to **408 kB** on ZTE F6107A).

### Expanded Protection & IPv6 Anti-Bypass
- **IPv6 DNS & DoT Anti-Bypass (`ip6tables`):** Closed real-world WAN IPv6 RDNSS bypasses detected in `/proc/net/nf_conntrack` by enforcing `ip6tables FORWARD` rules rejecting external LAN IPv6 port `53` (`icmp6-port-unreachable`) and IPv6 DoT port `853` (`tcp-reset`), forcing dual-stack clients back to local router `dnsmasq`.
- **285,865+ Domains & Smart TV OEM Shields:** Upgraded upstream blocklists to HaGeZi Multi NORMAL (`adblock/multi.txt`) + Samsung/LG webOS/Xiaomi native OEM telemetry shields + TikTok + PopupAds + StevenBlack + NoYouTubeAdsDNS, while expanding `config/whitelist.txt` for Android/Apple connectivity checks (`connectivitycheck.gstatic.com`, `captive.apple.com`, `time.*`).
- **ZTE Firmware Fixes:** Fixed BusyBox `curl` intermittent `SIGTERM` (`trap '' TERM` scoped strictly to curl subprocess), switched dead HaGeZi `hosts/` URLs to `adblock/`, enforced `killall -9` when replacing legacy `watchdog.sh` supervisors, and increased Telnet `run_cmd` timeout to `45.0s`.

## 0.2.0 (2026-11-24)

### Rust Embedded Daemon (`armv7-unknown-linux-musleabi`) & Tier 0 CDN
- Replaced legacy shell loop supervisors with a static soft-float ARMv7 Rust binary (`~445 KB`, `<500 KB` RSS) built via Docker (`rust/Dockerfile.cross`) and GitHub Actions CI (`.github/workflows/rust-daemon.yml`).
- Added ephemeral HTTP LAN server + RAM Canary testing (`--version` & `status`) + automatic rollback to shell fallback on ABI/health failure.
- Added Tier 0 Cloud Edge pre-compiler (`scripts/compile_blocklist.py` + `.github/workflows/compile-blocklist.yml`) publishing single pre-whitelisted `hosts.txt` to GitHub Pages (`gh-pages`).
- Added `core/tv_manager.py` CleanYourTV companion (`discover`, `analyze`, `clean --dry-run`, `restore` via snapshot & shell rollback).

## 0.1.0 (2026-11-24)

### Initial Release
- BusyBox POSIX `adblock.sh` + `watchdog.sh` engine for ZTE ZXHN F6107A (`192.168.1.1`).
- Transparent IPv4 NAT DNS interception (`PREROUTING port 53`), DoT `853` rejection, and Thai infrastructure whitelist.
