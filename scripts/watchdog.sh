#!/bin/sh
# HomeShield Resident Watchdog & Transparent DNS Interceptor
trap '' HUP TERM

# Delegate to Rust embedded daemon if installed (unless explicitly disabled)
if [ -x /userconfig/homeshield-daemon ] && [ "${HS_FORCE_SHELL:-0}" != "1" ]; then
    exec /userconfig/homeshield-daemon daemon
fi

while true; do
    # Display power management hook (if display attached to ACM0)
    if ! grep -q -E ":1D97 [0-9A-Fa-f]+:[0-9A-Fa-f]+ 01 " /proc/net/tcp 2>/dev/null; then
        (printf "\x00\x00\x00\x00\x00\x6c" > /dev/ttyACM0) 2>/dev/null
    fi

    # Network routing rules (if applicable)
    if ! ip addr show dev br0 2>/dev/null | grep -q "192.168.168.1"; then
        ip addr add 192.168.168.1/24 dev br0 2>/dev/null
    fi
    if ! ip route show table 250 2>/dev/null | grep -q "192.168.168.0"; then
        ip route add 192.168.168.0/24 dev br0 table 250 2>/dev/null
    fi
    if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" != "1" ]; then
        echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null
    fi
    if [ "$(cat /sys/class/net/br0/brif/wlan0/hairpin_mode 2>/dev/null)" != "1" ]; then
        echo 1 > /sys/class/net/br0/brif/wlan0/hairpin_mode 2>/dev/null
    fi
    if ! iptables -t nat -C POSTROUTING -o br0 -s 192.168.1.0/24 -d 192.168.168.0/24 -j MASQUERADE 2>/dev/null; then
        iptables -t nat -I POSTROUTING 1 -o br0 -s 192.168.1.0/24 -d 192.168.168.0/24 -j MASQUERADE 2>/dev/null
    fi
    if ! iptables -t nat -C POSTROUTING -o br0 -s 192.168.168.0/24 -d 192.168.1.0/24 -j MASQUERADE 2>/dev/null; then
        iptables -t nat -I POSTROUTING 1 -o br0 -s 192.168.168.0/24 -d 192.168.1.0/24 -j MASQUERADE 2>/dev/null
    fi

    # Transparent DNS Interception (Capture LAN DNS port 53 and redirect to local dnsmasq)
    if ! iptables -t nat -C PREROUTING -i br0 -p udp --dport 53 -j REDIRECT --to-ports 53 2>/dev/null; then
        iptables -t nat -I PREROUTING 1 -i br0 -p udp --dport 53 -j REDIRECT --to-ports 53 2>/dev/null
    fi
    if ! iptables -t nat -C PREROUTING -i br0 -p tcp --dport 53 -j REDIRECT --to-ports 53 2>/dev/null; then
        iptables -t nat -I PREROUTING 1 -i br0 -p tcp --dport 53 -j REDIRECT --to-ports 53 2>/dev/null
    fi

    # Anti-Bypass: Reject external IPv6 DNS (ISP RDNSS/external port 53) & DoT (port 853 IPv4+IPv6)
    if ! ip6tables -C FORWARD -i br0 -p udp --dport 53 -j REJECT 2>/dev/null; then
        ip6tables -I FORWARD 1 -i br0 -p udp --dport 53 -j REJECT 2>/dev/null
    fi
    if ! ip6tables -C FORWARD -i br0 -p tcp --dport 53 -j REJECT 2>/dev/null; then
        ip6tables -I FORWARD 1 -i br0 -p tcp --dport 53 -j REJECT 2>/dev/null
    fi
    if ! iptables -C FORWARD -p tcp --dport 853 -j REJECT --reject-with tcp-reset 2>/dev/null; then
        iptables -I FORWARD 1 -p tcp --dport 853 -j REJECT --reject-with tcp-reset 2>/dev/null
    fi
    if ! ip6tables -C FORWARD -p tcp --dport 853 -j REJECT --reject-with tcp-reset 2>/dev/null; then
        ip6tables -I FORWARD 1 -p tcp --dport 853 -j REJECT --reject-with tcp-reset 2>/dev/null
    fi

    # Ensure Adblock is loaded into RAM on boot
    if [ ! -f /var/tmp/adblock.hosts ] && [ -f /userconfig/adblock.hosts ] && [ ! -f /var/tmp/adblock.paused ]; then
        /userconfig/adblock.sh start >/dev/null 2>&1
    fi

    # Ensure Autonomous Adblock ticker loop is running in background
    if ! ps | grep "adblock.sh loop" | grep -v grep >/dev/null 2>&1; then
        if [ -f /userconfig/adblock.sh ] && [ ! -f /var/tmp/adblock.paused ]; then
            /userconfig/adblock.sh loop </dev/null >/dev/null 2>&1 &
        fi
    fi

    sleep 5
done
