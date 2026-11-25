#!/bin/sh
# HomeShield Engine (dnsmasq sinkhole) for Embedded Linux & Broadband Routers
# Operates fully autonomously on the router with secondary support from MacBook
CONF="/userconfig/adblock.conf"
[ -f "$CONF" ] && . "$CONF"

[ -z "$BLOCKLIST_URLS" ] && BLOCKLIST_URLS="${BLOCKLIST_URL:-https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/multi.txt https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling/hosts https://raw.githubusercontent.com/froggeric/DNS-blocklists/main/NoYouTubeAdsDNS https://raw.githubusercontent.com/Turtlecute33/adblocktest/master/src/d3host.txt https://raw.githubusercontent.com/Turtlecute33/adblocktest/master/src/d3host.adblock}"
[ -z "$UPDATE_INTERVAL_SECONDS" ] && UPDATE_INTERVAL_SECONDS=86400
[ -z "$WHITELIST_FILE" ] && WHITELIST_FILE="/userconfig/whitelist.txt"
[ -z "$BACKUP_FILE" ] && BACKUP_FILE="/userconfig/adblock.hosts"
[ -z "$LAST_UPDATE_FILE" ] && LAST_UPDATE_FILE="/userconfig/adblock.last_update"
[ -z "$LAST_EPOCH_FILE" ] && LAST_EPOCH_FILE="/userconfig/adblock.last_update_epoch"
[ -z "$PAUSED_FILE" ] && PAUSED_FILE="/var/tmp/adblock.paused"

ensure_base_hosts() {
    if [ ! -f /var/tmp/hosts.base ]; then
        if [ -f /var/tmp/hosts ]; then
            grep -v "^0\.0\.0\.0" /var/tmp/hosts > /var/tmp/hosts.base 2>/dev/null
        fi
        if [ ! -s /var/tmp/hosts.base ]; then
            echo "127.0.0.1 localhost.localdomain localhost" > /var/tmp/hosts.base
        fi
    fi
}

apply_hosts() {
    ensure_base_hosts
    if [ -f "$PAUSED_FILE" ]; then
        cp /var/tmp/hosts.base /var/tmp/hosts
        killall -HUP dnsmasq 2>/dev/null
        return 0
    fi

    src=""
    if [ -f /var/tmp/adblock.hosts ] && [ -s /var/tmp/adblock.hosts ]; then
        src="/var/tmp/adblock.hosts"
    elif [ -f "$BACKUP_FILE" ] && [ -s "$BACKUP_FILE" ]; then
        cp "$BACKUP_FILE" /var/tmp/adblock.hosts
        src="/var/tmp/adblock.hosts"
    fi

    if [ -n "$src" ]; then
        awk '{print; sub(/^0\.0\.0\.0/, "::"); print}' "$src" > /var/tmp/adblock.dual
        cat /var/tmp/hosts.base /var/tmp/adblock.dual > /var/tmp/hosts.new
        mv /var/tmp/hosts.new /var/tmp/hosts
        rm -f /var/tmp/adblock.dual
        killall -HUP dnsmasq 2>/dev/null
        return 0
    fi
    return 1
}

do_update() {
    ensure_base_hosts
    tmp_merged="/var/tmp/adblock_merged.tmp"
    rm -f "$tmp_merged"
    : > "$tmp_merged"

    # 1. Tier 0 CDN Primary (if configured) with automatic fallback to multi-source feeds
    cdn_ok=0
    if [ -n "$PRIMARY_CDN_URL" ]; then
        tmp_cdn="/var/tmp/adblock_cdn.tmp"
        rm -f "$tmp_cdn"
        (trap '' TERM; exec curl -skfL --connect-timeout 10 --max-time 45 "$PRIMARY_CDN_URL") > "$tmp_cdn" 2>/dev/null
        cdn_cnt=$(awk 'END {print NR}' "$tmp_cdn" 2>/dev/null || echo 0)
        [ -z "$cdn_cnt" ] && cdn_cnt=0
        if [ "$cdn_cnt" -gt 1000 ]; then
            cat "$tmp_cdn" > "$tmp_merged"
            cdn_ok=1
        fi
        rm -f "$tmp_cdn"
    fi

    if [ "$cdn_ok" -eq 0 ]; then
        for url in $BLOCKLIST_URLS; do
            tmp_one="/var/tmp/adblock_dl.tmp"
            rm -f "$tmp_one"
            (trap '' TERM; exec curl -skfL --connect-timeout 10 --max-time 90 "$url") > "$tmp_one" 2>/dev/null
            cnt=$(awk 'END {print NR}' "$tmp_one" 2>/dev/null || echo 0)
            [ -z "$cnt" ] && cnt=0
            if [ "$cnt" -gt 50 ]; then
                cat "$tmp_one" >> "$tmp_merged"
            fi
            rm -f "$tmp_one"
        done
    fi

    total_lines=$(awk 'END {print NR}' "$tmp_merged" 2>/dev/null || echo 0)
    [ -z "$total_lines" ] && total_lines=0

    # 2. Strict validation: merged file must contain valid entries (> 1000)
    if [ "$total_lines" -gt 1000 ]; then
        # 3. Universal parser: supports Hosts (0.0.0.0/127.0.0.1), Adblock (||domain^), and Plain domain
        if [ -f "$WHITELIST_FILE" ] && [ -s "$WHITELIST_FILE" ]; then
            awk 'NR==FNR { if ($1 ~ /^#/ || NF==0) next; wl[$1]=1; next }
                 {
                     if ($0 ~ /^#/ || NF==0) next;
                     d = "";
                     if ($1 == "0.0.0.0" || $1 == "127.0.0.1") { d = $2; }
                     else if ($0 ~ /^\|\|/) { d = substr($0, 3); sub(/\^.*$/, "", d); }
                     else if ($0 ~ /^[a-zA-Z0-9_][-a-zA-Z0-9_.]*\.[a-zA-Z0-9]+$/) { d = $1; }
                     if (d != "" && !(d in wl) && !seen[d]++) {
                         print "0.0.0.0", d;
                     }
                 }' "$WHITELIST_FILE" "$tmp_merged" > /var/tmp/adblock.hosts 2>/dev/null
        else
            awk '{
                     if ($0 ~ /^#/ || NF==0) next;
                     d = "";
                     if ($1 == "0.0.0.0" || $1 == "127.0.0.1") { d = $2; }
                     else if ($0 ~ /^\|\|/) { d = substr($0, 3); sub(/\^.*$/, "", d); }
                     else if ($0 ~ /^[a-zA-Z0-9_][-a-zA-Z0-9_.]*\.[a-zA-Z0-9]+$/) { d = $1; }
                     if (d != "" && !seen[d]++) {
                         print "0.0.0.0", d;
                     }
                 }' "$tmp_merged" > /var/tmp/adblock.hosts 2>/dev/null
        fi
        rm -f "$tmp_merged"

        # 4. Anti-Bypass: Append Canary Domains if enabled
        [ -z "$BLOCK_CANARY_DOH" ] && BLOCK_CANARY_DOH=1
        [ -z "$BLOCK_APPLE_PRIVATE_RELAY" ] && BLOCK_APPLE_PRIVATE_RELAY=1

        if [ "$BLOCK_CANARY_DOH" = "1" ]; then
            echo "0.0.0.0 use-application-dns.net" >> /var/tmp/adblock.hosts
        fi
        if [ "$BLOCK_APPLE_PRIVATE_RELAY" = "1" ]; then
            echo "0.0.0.0 mask.icloud.com" >> /var/tmp/adblock.hosts
            echo "0.0.0.0 mask-h2.icloud.com" >> /var/tmp/adblock.hosts
            echo "0.0.0.0 mask-api.fe.apple-dns.net" >> /var/tmp/adblock.hosts
        fi

        # 5. Save persistent flash backup & timestamps
        cp /var/tmp/adblock.hosts "$BACKUP_FILE" 2>/dev/null
        date +"%Y-%m-%d %H:%M:%S" > "$LAST_UPDATE_FILE"
        date +%s > "$LAST_EPOCH_FILE"

        apply_hosts
        return 0
    fi

    # Fail-closed: clean up corrupted temp files, keep existing blocklist intact
    rm -f "$tmp_merged"
    return 1
}

do_check() {
    [ -f "$PAUSED_FILE" ] && return 0
    ensure_base_hosts

    now=$(date +%s 2>/dev/null || echo 0)
    # Check if router NTP time has synchronized (valid epoch > 1700000000)
    if [ "$now" -lt 1700000000 ]; then
        if [ ! -f /var/tmp/adblock.hosts ] || [ ! -s /var/tmp/adblock.hosts ]; then
            if [ -f "$BACKUP_FILE" ] && [ -s "$BACKUP_FILE" ]; then
                cp "$BACKUP_FILE" /var/tmp/adblock.hosts
                apply_hosts
            fi
        fi
        return 0
    fi

    last=$(cat "$LAST_EPOCH_FILE" 2>/dev/null)
    [ -z "$last" ] && last=0
    elapsed=$(awk -v n="$now" -v l="$last" 'BEGIN { print n - l }')

    # Trigger update if past interval (24h) or never updated
    if [ "$last" -eq 0 ] || [ "$elapsed" -ge "$UPDATE_INTERVAL_SECONDS" ]; then
        if ping -c 1 -T 3 8.8.8.8 >/dev/null 2>&1 || ping -c 1 1.1.1.1 >/dev/null 2>&1; then
            do_update
            return 0
        fi
    fi

    # Restore from persistent flash on boot if RAM is empty
    if [ ! -f /var/tmp/adblock.hosts ] || [ ! -s /var/tmp/adblock.hosts ]; then
        if [ -f "$BACKUP_FILE" ] && [ -s "$BACKUP_FILE" ]; then
            cp "$BACKUP_FILE" /var/tmp/adblock.hosts
            apply_hosts
        fi
    fi
    return 0
}

do_start() {
    rm -f "$PAUSED_FILE"
    if [ ! -f /var/tmp/adblock.hosts ] || [ ! -s /var/tmp/adblock.hosts ]; then
        if [ -f "$BACKUP_FILE" ] && [ -s "$BACKUP_FILE" ]; then
            cp "$BACKUP_FILE" /var/tmp/adblock.hosts
        else
            do_update
        fi
    fi
    apply_hosts
}

do_stop() {
    echo "" > "$PAUSED_FILE"
    ensure_base_hosts
    cp /var/tmp/hosts.base /var/tmp/hosts
    killall -HUP dnsmasq 2>/dev/null
}

do_toggle() {
    if [ -f "$PAUSED_FILE" ]; then
        do_start
    else
        do_stop
    fi
    do_status
}

do_status() {
    if [ -f "$PAUSED_FILE" ]; then
        echo "STATUS: PAUSED"
    else
        echo "STATUS: ACTIVE"
    fi
    cnt=$(grep -c "^0\.0\.0\.0 " /var/tmp/hosts 2>/dev/null)
    echo "BLOCKED_DOMAINS: ${cnt:-0}"
    if [ -f "$LAST_UPDATE_FILE" ]; then
        echo "LAST_UPDATE: $(cat "$LAST_UPDATE_FILE" 2>/dev/null)"
    else
        echo "LAST_UPDATE: NEVER"
    fi

    last_ep=$(cat "$LAST_EPOCH_FILE" 2>/dev/null || echo 0)
    now_ep=$(date +%s 2>/dev/null || echo 0)
    if [ "$last_ep" -gt 0 ] && [ "$now_ep" -ge "$last_ep" ]; then
        awk_calc=$(awk -v n="$now_ep" -v l="$last_ep" -v intv="$UPDATE_INTERVAL_SECONDS" 'BEGIN {
            diff = n - l;
            rem = intv - diff;
            if (rem <= 0) {
                printf "DUE_NOW";
            } else {
                days = int(rem / 86400);
                hours = int((rem % 86400) / 3600);
                printf "IN %dd %dh (autonomous)", days, hours;
            }
        }')
        echo "NEXT_UPDATE: $awk_calc"
    else
        echo "NEXT_UPDATE: PENDING"
    fi

    loop_pid=$(ps | grep "adblock.sh loop" | grep -v grep | awk '{print $1; exit}')
    w_pid=$(ps | grep "watchdog.sh" | grep -v grep | awk '{print $1; exit}')
    if [ -n "$loop_pid" ]; then
        echo "ROUTER_AUTONOMY: FULLY_AUTONOMOUS (Loop PID $loop_pid, Watchdog PID ${w_pid:-none})"
    elif [ -n "$w_pid" ]; then
        echo "ROUTER_AUTONOMY: SUPERVISED (Watchdog PID $w_pid active, Loop starting)"
    else
        echo "ROUTER_AUTONOMY: UNMANAGED (No background supervisor running)"
    fi
}

do_loop() {
    while true; do
        sleep 1800
        do_check >/dev/null 2>&1
    done
}

ACTION="$1"
case "$ACTION" in
    start|resume)
        do_start
        ;;
    stop|pause)
        do_stop
        ;;
    toggle)
        do_toggle
        ;;
    restart)
        do_start
        ;;
    update)
        do_update
        ;;
    check)
        do_check
        ;;
    loop)
        do_loop
        ;;
    status)
        do_status
        ;;
    *)
        echo "Usage: $0 {start|stop|pause|resume|toggle|restart|update|check|loop|status}"
        exit 1
        ;;
esac
exit 0
