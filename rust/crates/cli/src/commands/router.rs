use crate::telnet::client::TelnetSession;
use crate::telnet::factory_mode;
use anyhow::Result;
use std::time::Duration;

const DEFAULT_CMD_TIMEOUT: Duration = Duration::from_secs(10);

/// Negotiate ZTE Factory Mode credentials and open an authenticated Telnet shell session.
pub async fn connect_router(ip: &str) -> Result<TelnetSession> {
    let (user, pass) = factory_mode::negotiate(ip, 80, 5, 3).await?;
    TelnetSession::connect(ip, &user, &pass, 3).await
}

/// Execute an action against the active router engine (Rust daemon if present, else shell).
pub async fn run_remote_engine_cmd(session: &mut TelnetSession, action: &str) -> Result<String> {
    let chk = session
        .run_cmd(
            "test -x /userconfig/homeshield-daemon && echo RUST_OK",
            DEFAULT_CMD_TIMEOUT,
        )
        .await?;
    let cmd = if chk.contains("RUST_OK") {
        format!("/userconfig/homeshield-daemon {action}")
    } else {
        format!("/userconfig/adblock.sh {action}")
    };
    let timeout = if action == "update" {
        Duration::from_secs(45)
    } else {
        Duration::from_secs(15)
    };
    session.run_cmd(&cmd, timeout).await
}

/// Force-stop any running Watchdog/Adblock shell loops and Rust daemons.
pub async fn stop_all_supervisors(session: &mut TelnetSession) -> Result<()> {
    session
        .run_cmd(
            "killall -9 watchdog.sh 2>/dev/null; \
             killall -9 adblock.sh 2>/dev/null; \
             killall homeshield-daemon router-guard-daemon 2>/dev/null; \
             sleep 1; \
             killall -9 homeshield-daemon router-guard-daemon 2>/dev/null",
            DEFAULT_CMD_TIMEOUT,
        )
        .await?;
    Ok(())
}

/// Run `status`, `toggle`, or `update` on the target router.
pub async fn run_action(ip: &str, action: &str) -> Result<()> {
    let mut session = connect_router(ip).await?;
    let out = run_remote_engine_cmd(&mut session, action).await?;
    println!("{out}");
    Ok(())
}

/// Level 3 Rollback: cleanly uninstall HomeShield, flush DNS rules, and restore factory state.
pub async fn uninstall(ip: &str) -> Result<()> {
    println!("[*] Uninstalling HomeShield from {ip} (Level 3 Factory Revert)...");
    let mut session = connect_router(ip).await?;

    stop_all_supervisors(&mut session).await?;
    session
        .run_cmd(
            "iptables -t nat -D PREROUTING -i br0 -p udp --dport 53 -j REDIRECT --to-ports 53 2>/dev/null; \
             iptables -t nat -D PREROUTING -i br0 -p tcp --dport 53 -j REDIRECT --to-ports 53 2>/dev/null; \
             iptables -D FORWARD -p tcp --dport 853 -j REJECT --reject-with tcp-reset 2>/dev/null; \
             ip6tables -D FORWARD -i br0 -p udp --dport 53 -j REJECT 2>/dev/null; \
             ip6tables -D FORWARD -i br0 -p tcp --dport 53 -j REJECT 2>/dev/null; \
             ip6tables -D FORWARD -p tcp --dport 853 -j REJECT --reject-with tcp-reset 2>/dev/null",
            DEFAULT_CMD_TIMEOUT,
        )
        .await?;

    session
        .run_cmd(
            "echo '127.0.0.1 localhost' > /var/tmp/hosts && killall -HUP dnsmasq 2>/dev/null",
            DEFAULT_CMD_TIMEOUT,
        )
        .await?;

    session
        .run_cmd(
            "rm -rf /userconfig/homeshield-daemon /userconfig/router-guard-daemon \
             /userconfig/adblock.* /userconfig/watchdog.sh /userconfig/whitelist.txt \
             /var/tmp/adblock.* /var/tmp/homeshield-daemon.canary 2>/dev/null",
            DEFAULT_CMD_TIMEOUT,
        )
        .await?;

    println!("[+] HomeShield successfully removed. Gateway restored to clean DNS state.");
    Ok(())
}
