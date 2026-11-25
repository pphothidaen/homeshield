use crate::commands::router::{connect_router, stop_all_supervisors};
use crate::server::{local_ip_for_router, EphemeralFileServer};
use crate::telnet::client::TelnetSession;
use crate::EngineMode;
use anyhow::{bail, Result};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::Duration;
use tokio::time::sleep;

const SCRIPT_PATH: &str = "scripts/adblock.sh";
const WATCHDOG_PATH: &str = "scripts/watchdog.sh";
const WHITELIST_PATH: &str = "config/whitelist.txt";
const CONF_PATH: &str = "config/adblock.conf";
const RUST_ARMV7_BIN: &str = "rust/target/armv7-unknown-linux-musleabi/release/homeshield-daemon";
const CANARY_PATH: &str = "/var/tmp/homeshield-daemon.canary";

async fn rollback_to_shell(session: &mut TelnetSession) -> Result<()> {
    println!(
        "  [!] Auto-Rollback triggered: reverting to shell engine (watchdog.sh + adblock.sh)..."
    );
    stop_all_supervisors(session).await?;
    session
        .run_cmd(
            "rm -f /var/tmp/homeshield-daemon.canary /userconfig/homeshield-daemon",
            Duration::from_secs(10),
        )
        .await?;
    session
        .run_cmd(
            "/userconfig/watchdog.sh </dev/null >/dev/null 2>&1 &",
            Duration::from_secs(5),
        )
        .await?;
    session
        .run_cmd("/userconfig/adblock.sh start", Duration::from_secs(15))
        .await?;
    Ok(())
}

async fn deploy_rust_canary(
    session: &mut TelnetSession,
    router_ip: &str,
    bin_path: &Path,
) -> Result<bool> {
    if !bin_path.exists() {
        println!(
            "  [-] Rust ARMv7 binary not found at {}",
            bin_path.display()
        );
        return Ok(false);
    }

    let bytes = tokio::fs::read(bin_path).await?;
    let expected_size = bytes.len();
    let expected_sha = format!("{:x}", Sha256::digest(&bytes));
    let short_sha = &expected_sha[..16.min(expected_sha.len())];

    let local_ip = local_ip_for_router(router_ip)?;
    let mut server = EphemeralFileServer::start(bin_path).await?;
    let filename = bin_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("homeshield-daemon");
    let url = format!(
        "http://{}",
        EphemeralFileServer::local_addr_hint(local_ip, server.port, filename)
    );

    println!("  -> Serving {filename} ({expected_size} bytes, sha256:{short_sha}...) on {url}");

    // Launch curl in background — write exit code to marker file when done.
    // This avoids the run_cmd prompt-detection race where the shell echoes a
    // prompt before curl finishes, causing run_cmd to return early with DL_RC=28.
    session
        .run_cmd(
            &format!(
                "rm -f /tmp/hs_dl_rc /var/tmp/hosts.new {CANARY_PATH}; \
                 (/bin/curl -sf --connect-timeout 5 --max-time 60 '{url}' \
                   -o {CANARY_PATH}; echo $? > /tmp/hs_dl_rc) &"
            ),
            Duration::from_secs(10),
        )
        .await?;

    // Poll /tmp/hs_dl_rc until curl writes its exit code (up to 70 s).
    let mut dl_rc: Option<i32> = None;
    for _ in 0..70 {
        sleep(Duration::from_secs(1)).await;
        let poll = session
            .run_cmd(
                "cat /tmp/hs_dl_rc 2>/dev/null; echo POLL_DONE",
                Duration::from_secs(5),
            )
            .await?;
        if poll.contains("POLL_DONE") {
            for line in poll.lines() {
                let trimmed = line.trim();
                if trimmed == "POLL_DONE" {
                    continue;
                }
                if let Ok(rc) = trimmed.parse::<i32>() {
                    dl_rc = Some(rc);
                    break;
                }
            }
            if dl_rc.is_some() {
                break;
            }
        }
    }
    let _ = session
        .run_cmd("rm -f /tmp/hs_dl_rc", Duration::from_secs(5))
        .await;

    server.shutdown();

    if dl_rc != Some(0) {
        println!("  [-] Router HTTP pull failed: DL_RC={:?}", dl_rc);
        return Ok(false);
    }

    let size_out = session
        .run_cmd(
            &format!("ls -l {CANARY_PATH} | awk '{{print \"SIZE=\" $5}}'"),
            Duration::from_secs(10),
        )
        .await?;
    if !size_out.contains(&format!("SIZE={expected_size}")) {
        println!("  [-] Size mismatch (expected SIZE={expected_size}), got:\n{size_out}");
        let _ = session
            .run_cmd(&format!("rm -f {CANARY_PATH}"), Duration::from_secs(5))
            .await;
        return Ok(false);
    }

    println!("  -> Running RAM Canary check (--version & status)...");
    let canary_out = session
        .run_cmd(
            &format!("chmod 755 {CANARY_PATH} && {CANARY_PATH} --version && {CANARY_PATH} status; echo CANARY_RC=$?"),
            Duration::from_secs(15),
        )
        .await?;
    if !canary_out.contains("CANARY_RC=0") || !canary_out.contains("homeshield-daemon") {
        println!("  [-] RAM Canary failed (ABI or runtime error):\n{canary_out}");
        let _ = session
            .run_cmd(&format!("rm -f {CANARY_PATH}"), Duration::from_secs(5))
            .await;
        return Ok(false);
    }

    println!("  -> RAM Canary PASSED! Promoting to /userconfig/homeshield-daemon...");
    session
        .run_cmd(
            &format!(
                "cp {CANARY_PATH} /userconfig/homeshield-daemon.new && \
                 chmod 755 /userconfig/homeshield-daemon.new && \
                 mv /userconfig/homeshield-daemon.new /userconfig/homeshield-daemon && \
                 rm -f {CANARY_PATH}"
            ),
            Duration::from_secs(15),
        )
        .await?;

    println!("  -> Switching supervisor from shell scripts to Rust Daemon...");
    stop_all_supervisors(session).await?;
    session
        .run_cmd(
            "/userconfig/homeshield-daemon start",
            Duration::from_secs(45),
        )
        .await?;
    session
        .run_cmd(
            "nohup /userconfig/homeshield-daemon daemon </dev/null >/dev/null 2>&1 &",
            Duration::from_secs(10),
        )
        .await?;
    sleep(Duration::from_secs(2)).await;

    let verify_out = session
        .run_cmd(
            "ps | grep 'homeshield-daemon daemon' | grep -v grep; \
             /userconfig/homeshield-daemon status; echo VERIFY_RC=$?",
            Duration::from_secs(15),
        )
        .await?;
    if !verify_out.contains("VERIFY_RC=0") || !verify_out.contains("Rust Daemon PID") {
        println!("  [-] Rust Daemon failed post-switch health check:\n{verify_out}");
        rollback_to_shell(session).await?;
        return Ok(false);
    }

    println!("\n=== HOMESHIELD RUST DAEMON STATUS ===");
    println!("{verify_out}");
    Ok(true)
}

async fn upload_heredoc(
    session: &mut TelnetSession,
    remote_path: &str,
    content: &str,
) -> Result<()> {
    let cmd = format!("cat << 'EOF' > {remote_path}\n{content}\nEOF\n");
    session.run_cmd(&cmd, Duration::from_secs(15)).await?;
    Ok(())
}

/// Deploy HomeShield engine and configuration to the target router.
pub async fn run(ip: &str, engine: EngineMode) -> Result<()> {
    let mode_label = match engine {
        EngineMode::Auto => "auto",
        EngineMode::Rust => "rust",
        EngineMode::Shell => "shell",
    };
    println!("[*] Deploying HomeShield Engine (mode={mode_label}) to {ip}...");

    let script_path = Path::new(SCRIPT_PATH);
    let watchdog_path = Path::new(WATCHDOG_PATH);
    if !script_path.exists() || !watchdog_path.exists() {
        bail!("Missing script templates in scripts/");
    }

    let script_content = tokio::fs::read_to_string(script_path).await?;
    let watchdog_content = tokio::fs::read_to_string(watchdog_path).await?;
    let whitelist_content = if Path::new(WHITELIST_PATH).exists() {
        Some(tokio::fs::read_to_string(WHITELIST_PATH).await?)
    } else {
        None
    };
    let conf_content = if Path::new(CONF_PATH).exists() {
        Some(tokio::fs::read_to_string(CONF_PATH).await?)
    } else {
        None
    };

    let bin_path = Path::new(RUST_ARMV7_BIN);
    let use_rust = matches!(engine, EngineMode::Rust)
        || (matches!(engine, EngineMode::Auto) && bin_path.exists());

    let mut session = connect_router(ip).await?;

    if let Some(conf) = conf_content {
        println!("  -> Updating /userconfig/adblock.conf...");
        upload_heredoc(&mut session, "/userconfig/adblock.conf", &conf).await?;
    }

    let chk_wl = session
        .run_cmd(
            "test -f /userconfig/whitelist.txt && echo EXISTS",
            Duration::from_secs(5),
        )
        .await?;
    if !chk_wl.contains("EXISTS") {
        if let Some(wl) = whitelist_content {
            println!("  -> Creating /userconfig/whitelist.txt...");
            upload_heredoc(&mut session, "/userconfig/whitelist.txt", &wl).await?;
        }
    }

    println!("  -> Installing fallback shell engine (/userconfig/adblock.sh & watchdog.sh)...");
    upload_heredoc(&mut session, "/userconfig/adblock.sh", &script_content).await?;
    session
        .run_cmd("chmod 755 /userconfig/adblock.sh", Duration::from_secs(5))
        .await?;
    upload_heredoc(&mut session, "/userconfig/watchdog.sh", &watchdog_content).await?;
    session
        .run_cmd("chmod 755 /userconfig/watchdog.sh", Duration::from_secs(5))
        .await?;

    if use_rust {
        if deploy_rust_canary(&mut session, ip, bin_path).await? {
            return Ok(());
        }
        if matches!(engine, EngineMode::Rust) {
            bail!("Rust daemon deployment failed");
        }
        println!("  [!] Falling back to shell supervisor after Rust canary abort.");
    }

    println!("  -> Starting shell watchdog daemon...");
    stop_all_supervisors(&mut session).await?;
    session
        .run_cmd(
            "/userconfig/watchdog.sh </dev/null >/dev/null 2>&1 &",
            Duration::from_secs(5),
        )
        .await?;
    session
        .run_cmd("/userconfig/adblock.sh start", Duration::from_secs(15))
        .await?;
    sleep(Duration::from_secs(2)).await;

    let status = session
        .run_cmd("/userconfig/adblock.sh status", Duration::from_secs(10))
        .await?;
    println!("\n=== HOMESHIELD STATUS ===");
    println!("{status}");
    Ok(())
}
