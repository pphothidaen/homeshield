# Security Policy

## Reporting a Vulnerability

If you discover a security issue in **HomeShield** (such as unsafe shell command interpolation, privilege issues in `homeshield-daemon`, or credential leakage in deployment scripts), please report it privately through [GitHub Security Advisories](https://github.com/pphothidaen/homeshield/security/advisories/new) instead of opening a public issue.

We aim to acknowledge reports within 48 hours and ship verified fixes promptly.

## Scope

In scope:
- The embedded Rust daemon ([`rust/crates/`](rust/crates/)) and cross-compilation build pipeline
- Router deployment & fallback scripts ([`homeshield.py`](homeshield.py), [`scripts/`](scripts/), [`core/`](core/))
- Tier 0 Cloud Edge pre-compiler ([`scripts/compile_blocklist.py`](scripts/compile_blocklist.py)) and GitHub Actions workflows
- Smart TV companion ADB management ([`core/tv_manager.py`](core/tv_manager.py))

Out of scope:
- Third-party upstream blocklist contents (`HaGeZi`, `StevenBlack`, `NoYouTubeAdsDNS`)
- Router vendor Telnet/Factory Mode firmware interfaces on your own LAN hardware

## Supported Versions

Only the latest release on the `main` branch receives security updates and Tier 0 daily blocklist builds.

## Integrity & Verification

- Every release CI build ([`rust-daemon.yml`](.github/workflows/rust-daemon.yml)) compiles from public source with `cargo clippy --workspace -- -D warnings` and `cargo test --workspace` enabled.
- During `homeshield.py deploy`, the workstation computes a SHA-256 digest and exact byte size before transferring `homeshield-daemon` into `/var/tmp/` for a live RAM Canary execution test (`--version` and `status`). Flash promotion (`/userconfig/homeshield-daemon`) aborts automatically on any mismatch or ABI failure.
- Runtime protection operates exclusively in non-root/router-local network filtering without sideloading or modifying root CA certificates on Smart TVs, streaming sticks, or carrier set-top boxes.
