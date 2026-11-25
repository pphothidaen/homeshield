# Contributing to HomeShield

Thanks for contributing! HomeShield runs directly inside resource-constrained broadband gateways and routers (such as ZTE ZXHN F6107A, Huawei, ASUS, and OpenWrt devices with 256 MB RAM and 8 MB Flash) and protects live home networks, so correctness, safety, and memory efficiency come first.

By contributing, you agree that your work is licensed under the [MIT License](LICENSE). Please report security vulnerabilities privately via [SECURITY.md](SECURITY.md).

## Development Setup

You need:
- **Python 3.9+** (`pytest` for unit & E2E tests)
- **Rust toolchain (`stable`)** with `clippy` for daemon development
- **Docker Desktop** (for ARMv7 soft-float cross-compilation targeting `armv7-unknown-linux-musleabi`)

```bash
git clone https://github.com/pphothidaen/homeshield.git
cd homeshield
```

### Verification Commands

Run all checks locally before opening a pull request:

| Command | What it runs |
| :--- | :--- |
| `cd rust && cargo clippy --workspace -- -D warnings` | Strict Rust static analysis (`0` warnings required) |
| `cd rust && cargo test --workspace` | Core parser, config, engine, and MockSystem supervisor tests |
| `python3 -m pytest tests/ -v` | Full Python + Rust E2E CLI lifecycle, Canary rollback, shell & TV tests |
| `./rust/build-armv7.sh` | Static ARMv7 soft-float (`musleabi`) release cross-compile |
| `sh -n scripts/adblock.sh && sh -n scripts/watchdog.sh` | BusyBox POSIX shell compatibility syntax check |

GitHub Actions ([`rust-daemon.yml`](.github/workflows/rust-daemon.yml)) enforces Clippy, workspace tests, and ARMv7 cross-compilation on every push and pull request.

## Embedded & Safety Rules

1. **Soft-Float ABI Only:** ZTE F6107A Cortex-A9 cores lack VFPv3/NEON hard-float (`armv7-unknown-linux-musleabihf` triggers `SIGILL`). Always target `armv7-unknown-linux-musleabi`.
2. **BusyBox Compatibility:** Router BusyBox v1.17.2 omits `touch`, `wc`, `head`, `which`, `sort`, and `df -h`. Keep shell fallback scripts strictly POSIX/awk-safe (`: > file`, `awk 'END {print NR}'`, `df -k`).
3. **Zero-Wear Flash Discipline:** Never write ephemeral or unchanged files to `/userconfig/`. Process temporary artifacts in `/var/tmp/` (`tmpfs`) and gate Flash backups behind checksum checks.
4. **Fail-Closed Validation:** Never overwrite an active blocklist if upstream feeds return fewer unique valid domains than `min_valid_lines`.
5. **Zero-Touch Client Guarantee:** Network-level rules must protect carrier-provided set-top boxes and smart media devices without sideloading apps or installing custom CA certificates, and must never break items in [`config/whitelist.txt`](config/whitelist.txt).
6. **Commit Hygiene:** Never commit `.env`, router credentials, or `config/*.json` overrides.

## Proposing Whitelist or Feed Changes

- Verify any new feed URL works with BusyBox `curl -skfL` and matches the universal parser (`0.0.0.0`, `||domain^`, or plain domain).
- Test memory and `/var` tmpfs footprint (`< 50 MB` limit on ZTE F6107A) before adding large blocklists to [`config/adblock.conf`](config/adblock.conf) and [`scripts/compile_blocklist.py`](scripts/compile_blocklist.py).
