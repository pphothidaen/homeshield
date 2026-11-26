<! ---
Vietnamese translation of HomeShield README (machine-translated).
--->
<div align="center">
 <img src="docs/images/banner-3-steps.png" alt="HomeShield Banner" width="100%" />
</div>

# 🛡️ HomeShield
### Autonomous Edge Cyber-Shield & Anti-Scam Gateway for Home Networks

[![Release](https://img.shields.io/badge/version-v1.2.0-blue.svg?style=flat-square)](CHANGELOG.md)
[![Rust](https://img.shields.io/badge/rust-embedded_armv7-orange.svg?style=flat-square&logo=rust)](rust/)
[![Threats Blocked](https://img.shields.io/badge/threats_blocked-552%2C000+-brightgreen.svg?style=flat-square)](https://pphothidaen.github.io/homeshield/hosts.txt)
[![Memory](https://img.shields.io/badge/RAM_RSS-408_kB-success.svg?style=flat-square)](rust/crates/daemon/)
[![Flash Wear](https://img.shields.io/badge/Flash_Wear-Zero--Wear_Delta-purple.svg?style=flat-square)](rust/crates/daemon/src/engine.rs)
[![Rollback](https://img.shields.io/badge/Rollback-4--Tier_Fail--Safe-red.svg?style=flat-square)](docs/PLAYBOOK.md)
[![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](LICENSE)
[![Blocklists](https://img.shields.io/badge/blocklists-29_live_feeds-brightgreen.svg?style=flat-square)](config/adblock.conf)

<p align="center">
  <b>Bảo vệ toàn nhà trước các nhà tài chính lừa đảo, APK giả mạo vay tiền, quảng cáo ngầm, bẫy cờ bạc và phần mềm gián điệp Smart TV — chạy trực tiếp trên router broadband chuẩn mà không cần phần cứng bổ sung.</b>
</p>

[Why HomeShield?](#why-homeshield) • [4 Security Pillars](#4-core-security-pillars) • [Comparison](#the-ultimate-comparison-homeshield-vs-alternatives) • [Before & After (97%)](#real-world-verification-before--after) • [Architecture](#architecture) • [Quick Start](#quick-start) • [Blocklist Sources & Updates](#threat-intelligence-sources--update-lifecycle) • [Playbook & Rollback](docs/PLAYBOOK.md)

<p align="center">
  🌐 <b>Languages / Ngôn ngữ:</b> English | <a href="README.md">English</a> | Tiếng Việt (Vietnamese) | <a href="README.ja.md">日本語 (Japanese)</a> | <a href="README.it.md">Italiano (Italian)</a> | <a href="README.pt.md">Português (Portuguese)</a> | <a href="README.nl.md">Nederlands (Dutch)</a> | <a href="README.de.md">Deutsch (German)</a> | <a href="README.uk.md">Українська (Ukrainian)</a> | <a href="README.uz.md">Özbekcha (Uzbek)</a> | <a href="README.fr.md">Français (French)</a> | <a href="README.el.md">Ελληνικά (Greek)</a> | <a href="README.he.md">עברית (Hebrew)</a> | <a href="README.es.md">Español (Spanish)</a> | <a href="README.ar.md">العربية (Arabic)</a>
</p>
---

## 🏛️ Kiến trúc

HomeShield sử dụng **kiến trúc Zero-Hop Edge tách rời** — router xử lý việc chặn DNS trên toàn mạng.

```mermaid
graph TD
    subgraph Tier0["☁️ Tier 0 Cloud Edge — GitHub Actions Daily"]
        T0A["📥 Pull 29 Live Feeds\nAd / Scam / Thai-SEA / IoT / PC Telemetry"]
        T0B["🔄 Deduplicate 552,000+ domains\n& apply Whitelist filter"]
        T0C["🚀 Publish to CDN\nGitHub Pages — hosts.txt"]
        T0A --> T0B --> T0C
    end
    Tier0 -.-|"⬇️ Daily HTTP Pull (86400s)"| Router
    subgraph Router["🌐 Broadband Gateway — ZTE · Huawei · ASUS · OpenWrt / ARMv7 / dnsmasq"]
        subgraph Daemon["⚙️ homeshield-daemon"]
            D1["408 kB VmRSS Rust"]
            D2["FNV-1a Flash Delta"]
            D3["5s Self-Healing"]
        end
        subgraph IPTables["🔒 iptables & ip6tables Anti-Bypass"]
            IP4["IPv4: NAT REDIRECT\nUDP/TCP 53 → dnsmasq"]
            IP6["IPv6: FORWARD REJECT\nport 53 / 853 (Anti-DoT)"]
        end
        subgraph Dnsmasq["🛡️ dnsmasq Dual-Stack Sinkhole"]
            DS1["🚫 Blocked → 0.0.0.0 & ::"]
            DS2["✅ Whitelisted → Forward to WAN"]
        end
    end
    subgraph Clients["📱 Protected Devices"]
        Mobile["💻 Mobile & PC\niOS · Android · Mac"]
        SmartTV["📺 Smart TV / Android TV\nTelemetry Blocked"]
    end
    Daemon -->|"🔐 Anti-bypass enforcement"| IPTables
    IPTables -->|"↩️ DNS redirection"| Dnsmasq
    Dnsmasq -->|"Sinkhole / Forward"| Mobile
    Dnsmasq -->|"Sinkhole / Forward"| SmartTV
    classDef tier0 fill:#e3f2fd,stroke:#1565c0,stroke-width:2px,color:#0d47a1
    classDef router fill:#fff8e1,stroke:#f57f17,stroke-width:2px,color:#e65100
    classDef daemon fill:#fff3e0,stroke:#ef6c00,stroke-width:1px,color:#bf360c
    classDef client fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#1b5e20
    class Tier0 tier0
    class Router router
    class Daemon,IPTables,Dnsmasq daemon
    class Mobile,SmartTV client
```

➡️ Tài liệu đầy đủ: [README.md](README.md)

