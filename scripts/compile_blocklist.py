#!/usr/bin/env python3
"""
Tier 0 Cloud Edge Pre-Compiler for HomeShield.
Fetches upstream blocklists, parses Hosts/Adblock/Plain formats, deduplicates,
removes whitelisted Thai/critical domains, injects anti-bypass canary domains,
and writes a single pre-compiled `hosts.txt` payload for fast router download.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Set

DEFAULT_FEEDS = [
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
    # Extended feeds (Shadowrocket, HaGeZi extras)
    "https://raw.githubusercontent.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever/release/sr_ad_only.conf",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/fake.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/gambling.medium.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.mini.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/doh-vpn-proxy-bypass.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/ultimate.txt",
    "https://raw.githubusercontent.com/h2y/Shadowrocket-ADBlock-Rules/master/sr_top500_banlist.conf",
    # Thai & Southeast Asia regional feeds
    "https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts",
    "https://raw.githubusercontent.com/PhyschicWinter9/thai-adblock-list/main/thai-adblock-list.txt",
    "https://raw.githubusercontent.com/Faelayis/AdBlock-Thai-Filters/master/filters/ads.txt",
    "https://raw.githubusercontent.com/Faelayis/AdBlock-Thai-Filters/master/nextdns/abp.txt",
    # Universal IoT, Mobile OEM, Smart Home & PC Telemetry feeds
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.amazon.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.apple.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.huawei.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.oppo-realme.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.vivo.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.roku.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.winoffice.txt",
    "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt",
]

CANARY_DOMAINS = [
    "use-application-dns.net",
    "mask.icloud.com",
    "mask-h2.icloud.com",
    "mask-api.fe.apple-dns.net",
]

RESERVED_HOSTNAMES = {
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
}

DOMAIN_RE = re.compile(r"^[a-z0-9_][-a-z0-9_.]*\.[a-z0-9]*[a-z][a-z0-9]*$")


def load_whitelist(path: Path) -> Set[str]:
    wl: Set[str] = set()
    if not path.exists():
        return wl
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.split("#", 1)[0].strip().lower()
        if line:
            wl.add(line.split()[0])
    return wl


def parse_domain_line(raw_line: str) -> str | None:
    line = raw_line.strip()
    if not line or line[0] in ("#", "!", "[") or line.startswith("@@"):
        return None

    candidate: str | None = None
    if line.startswith(("0.0.0.0 ", "0.0.0.0\t", "127.0.0.1 ", "127.0.0.1\t")):
        parts = line.split("#", 1)[0].split()
        if len(parts) >= 2:
            candidate = parts[1].lower()
    elif line.startswith("||"):
        rest = line[2:]
        for sep in ("^", "$", "/", "#"):
            rest = rest.split(sep, 1)[0]
        rest = rest.split()[0].lower() if rest.split() else ""
        if "*" not in rest:
            candidate = rest
    else:
        clean = line.split("#", 1)[0].strip().lower()
        if clean and len(clean.split()) == 1:
            candidate = clean

    if not candidate or len(candidate) > 253 or ".." in candidate:
        return None
    if candidate in RESERVED_HOSTNAMES:
        return None
    if not DOMAIN_RE.match(candidate):
        return None
    return candidate


def compile_lines(lines: Iterable[str], whitelist: Set[str]) -> list[str]:
    seen: Set[str] = set()
    domains: list[str] = []
    for raw in lines:
        dom = parse_domain_line(raw)
        if dom and dom not in whitelist and dom not in seen:
            seen.add(dom)
            domains.append(dom)

    for canary in CANARY_DOMAINS:
        if canary not in whitelist and canary not in seen:
            seen.add(canary)
            domains.append(canary)

    return domains


def normalize_feed_url(url: str) -> str:
    """Normalize GitHub web blob URLs (github.com/.../blob/...) to raw raw.githubusercontent.com."""
    trimmed = url.strip()
    return re.sub(
        r"^https?://github\.com/([^/]+)/([^/]+)/blob/(.+)$",
        r"https://raw.githubusercontent.com/\1/\2/\3",
        trimmed,
    )


def load_feeds_from_conf(conf_path: Path) -> list[str]:
    """Parse BLOCKLIST_URLS from adblock.conf if present."""
    if not conf_path.exists():
        return list(DEFAULT_FEEDS)
    feeds: list[str] = []
    for raw in conf_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if line.startswith("BLOCKLIST_URLS="):
            val = line.split("=", 1)[1].strip().strip('"').strip("'")
            feeds = [normalize_feed_url(u) for u in val.split() if u]
            break
    return feeds if feeds else list(DEFAULT_FEEDS)


def fetch_url(url: str, timeout: int = 45) -> list[str]:
    clean_url = normalize_feed_url(url)
    req = urllib.request.Request(clean_url, headers={"User-Agent": "HomeShield-Tier0-Compiler/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="ignore").splitlines()


def build_compiled_blocklist(
    output_dir: Path,
    whitelist_path: Path,
    feeds: list[str] | None = None,
    conf_path: Path | None = None,
    min_domains: int = 1000,
) -> dict:
    whitelist = load_whitelist(whitelist_path)
    if feeds is not None:
        feed_urls = [normalize_feed_url(u) for u in feeds]
    elif conf_path is not None and conf_path.exists():
        feed_urls = load_feeds_from_conf(conf_path)
    else:
        feed_urls = list(DEFAULT_FEEDS)

    all_lines: list[str] = []
    succeeded = 0

    for url in feed_urls:
        try:
            fetched = fetch_url(url)
            if len(fetched) > 50:
                all_lines.extend(fetched)
                succeeded += 1
        except Exception as exc:
            print(f"[warn] Failed to fetch {url}: {exc}", file=sys.stderr)

    domains = compile_lines(all_lines, whitelist)
    if len(domains) < min_domains:
        raise RuntimeError(
            f"Compiled domain count ({len(domains)}) below safety threshold ({min_domains}); aborting publish."
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    hosts_path = output_dir / "hosts.txt"
    payload = "\n".join(f"0.0.0.0 {d}" for d in domains) + "\n"
    hosts_path.write_text(payload, encoding="utf-8")

    sha256 = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    meta = {
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "feeds_succeeded": succeeded,
        "feeds_total": len(feed_urls),
        "whitelist_entries": len(whitelist),
        "domain_count": len(domains),
        "payload_bytes": len(payload.encode("utf-8")),
        "sha256": sha256,
    }
    (output_dir / "metadata.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    return meta


def main() -> int:
    parser = argparse.ArgumentParser(description="HomeShield Tier 0 Blocklist Pre-Compiler")
    parser.add_argument("--out-dir", default="dist", help="Output directory for compiled hosts.txt")
    parser.add_argument("--whitelist", default="config/whitelist.txt", help="Whitelist file path")
    parser.add_argument("--conf", default="config/adblock.conf", help="Path to adblock.conf to read BLOCKLIST_URLS")
    parser.add_argument("--min-domains", type=int, default=1000, help="Fail-closed minimum threshold")
    args = parser.parse_args()

    meta = build_compiled_blocklist(
        Path(args.out_dir),
        Path(args.whitelist),
        conf_path=Path(args.conf) if args.conf else None,
        min_domains=args.min_domains,
    )
    print(json.dumps(meta, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
