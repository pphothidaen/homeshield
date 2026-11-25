mod commands;
mod server;
mod telnet;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "homeshield",
    version,
    about = "HomeShield CLI: Autonomous Edge Cyber-Shield & Anti-Scam Gateway"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum EngineMode {
    Auto,
    Rust,
    Shell,
}

/// Resolve target router IP: CLI `--ip` > `HOMESHIELD_IP` > `ROUTERGUARD_IP` > `192.168.1.1`.
fn resolve_router_ip(cli_ip: Option<String>) -> String {
    if let Some(ip) = cli_ip.filter(|s| !s.trim().is_empty()) {
        return ip;
    }
    if let Ok(ip) = std::env::var("HOMESHIELD_IP") {
        if !ip.trim().is_empty() {
            return ip;
        }
    }
    if let Ok(ip) = std::env::var("ROUTERGUARD_IP") {
        if !ip.trim().is_empty() {
            return ip;
        }
    }
    "192.168.1.1".to_string()
}

#[derive(Subcommand)]
enum Commands {
    /// Compile upstream blocklists into a pre-whitelisted Tier 0 hosts.txt payload
    Compile {
        /// Output directory for compiled hosts.txt and metadata.json
        #[arg(long, default_value = "dist")]
        out_dir: PathBuf,
        /// Whitelist file path
        #[arg(long, default_value = "config/whitelist.txt")]
        whitelist: PathBuf,
        /// Path to adblock.conf to read BLOCKLIST_URLS
        #[arg(long, default_value = "config/adblock.conf")]
        conf: PathBuf,
        /// Fail-closed minimum domain threshold
        #[arg(long, default_value_t = 1000)]
        min_domains: usize,
    },
    /// Deploy HomeShield engine and configuration to the router
    Deploy {
        /// Target router IP (defaults to HOMESHIELD_IP / ROUTERGUARD_IP / 192.168.1.1)
        #[arg(long)]
        ip: Option<String>,
        #[arg(long, value_enum, default_value_t = EngineMode::Auto)]
        engine: EngineMode,
    },
    /// Force an immediate blocklist update on the router
    Update {
        /// Target router IP (defaults to HOMESHIELD_IP / ROUTERGUARD_IP / 192.168.1.1)
        #[arg(long)]
        ip: Option<String>,
    },
    /// Query current HomeShield status on the router
    Status {
        /// Target router IP (defaults to HOMESHIELD_IP / ROUTERGUARD_IP / 192.168.1.1)
        #[arg(long)]
        ip: Option<String>,
    },
    /// Toggle HomeShield between ACTIVE and PAUSED
    Toggle {
        /// Target router IP (defaults to HOMESHIELD_IP / ROUTERGUARD_IP / 192.168.1.1)
        #[arg(long)]
        ip: Option<String>,
    },
    /// Cleanly uninstall HomeShield from the router and restore /var/tmp/hosts
    Uninstall {
        /// Target router IP (defaults to HOMESHIELD_IP / ROUTERGUARD_IP / 192.168.1.1)
        #[arg(long)]
        ip: Option<String>,
    },
    /// Manage Smart TVs & Android/IoT device telemetry debloating via ADB (`tv` or `device`)
    #[command(visible_alias = "device")]
    Tv {
        #[command(subcommand)]
        action: TvCommands,
    },
}

#[derive(Subcommand)]
pub enum TvCommands {
    /// Discover Smart TVs, smartphones, cameras, & ADB-enabled IoT devices on the LAN
    Discover {
        /// Target router IP (defaults to HOMESHIELD_IP / ROUTERGUARD_IP / 192.168.1.1)
        #[arg(long)]
        ip: Option<String>,
    },
    /// Analyze installed ad/telemetry packages on a connected Android/IoT device
    Analyze {
        #[arg(long, alias = "tv-ip")]
        target: String,
    },
    /// Disable bloatware/telemetry packages on a connected Android/IoT device
    Clean {
        #[arg(long, alias = "tv-ip")]
        target: String,
        #[arg(long)]
        dry_run: bool,
    },
    /// Restore previously disabled device packages
    Restore {
        #[arg(long, alias = "tv-ip")]
        target: String,
        #[arg(long)]
        snapshot: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Compile {
            out_dir,
            whitelist,
            conf,
            min_domains,
        } => {
            commands::compile::run(&out_dir, &whitelist, &conf, min_domains).await?;
        }
        Commands::Deploy { ip, engine } => {
            let ip = resolve_router_ip(ip);
            commands::deploy::run(&ip, engine).await?;
        }
        Commands::Update { ip } => {
            let ip = resolve_router_ip(ip);
            commands::router::run_action(&ip, "update").await?;
        }
        Commands::Status { ip } => {
            let ip = resolve_router_ip(ip);
            commands::router::run_action(&ip, "status").await?;
        }
        Commands::Toggle { ip } => {
            let ip = resolve_router_ip(ip);
            commands::router::run_action(&ip, "toggle").await?;
        }
        Commands::Uninstall { ip } => {
            let ip = resolve_router_ip(ip);
            commands::router::uninstall(&ip).await?;
        }
        Commands::Tv { action } => {
            let action = match action {
                TvCommands::Discover { ip } => TvCommands::Discover {
                    ip: Some(resolve_router_ip(ip)),
                },
                other => other,
            };
            commands::tv::run(action).await?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_router_ip_prefers_cli_over_env() {
        assert_eq!(resolve_router_ip(Some("10.0.0.1".to_string())), "10.0.0.1");
    }
}
