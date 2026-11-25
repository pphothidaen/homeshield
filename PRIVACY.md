# Privacy Policy

**HomeShield** is an open-source local network DNS sinkhole and Smart TV companion toolkit published at [github.com/pphothidaen/homeshield](https://github.com/pphothidaen/homeshield).

Effective date: 2026-11-25.

## The Short Version

- HomeShield collects **no telemetry, analytics, crash reports, or usage logs**.
- Nothing about your router, browsing history, LAN devices, or Smart TV leaves your home network.
- We operate no backend servers; all blocklist compilation runs transparently via GitHub Actions on public open-source blocklists.

## What HomeShield Communicates With

1. **Your Router (`192.168.1.1`) & LAN Devices:**
   - Management commands (`deploy`, `status`, `toggle`, `update`, `test`) communicate strictly over your private LAN via Telnet/HTTP (`192.168.1.x`).
   - On the router, `homeshield-daemon` writes DNS sinkhole mappings only to RAM (`/var/tmp/hosts`) and Flash backup (`/userconfig/adblock.hosts`). No DNS query history is logged to disk.
2. **Tier 0 CDN & Blocklist Sources (Outbound Pull Only):**
   - Once every 24 hours (`UPDATE_INTERVAL_SECONDS=86400`), the router daemon downloads the pre-compiled public `hosts.txt` from [GitHub Pages](https://pphothidaen.github.io/homeshield/hosts.txt) (or falls back directly to `raw.githubusercontent.com` upstream feeds). GitHub sees standard HTTP download metadata (IP address, User-Agent) per [GitHub Privacy Statement](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement); HomeShield sends no device identifiers.
3. **Smart TV Companion (`core/tv_manager.py`, Optional):**
   - Connects strictly over LAN ADB (`port 5555`) only when you run `tv analyze` / `tv clean` / `tv restore`. Disabled apps are backed up locally in `backups/` on your workstation alongside a standalone rollback script.
   - Operator set-top boxes and streaming media devices are left completely untouched (**Zero-Touch**).

## Credentials & Local Config Hygiene

- Router Telnet negotiation runs in memory on your workstation.
- Personal environment files (`.env`, `config/*.json`) are explicitly excluded in [`.gitignore`](.gitignore) and never tracked or pushed.
