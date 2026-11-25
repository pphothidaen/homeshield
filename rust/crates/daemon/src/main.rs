mod engine;
mod supervisor;
mod system;

use crate::engine::AdblockEngine;
use crate::supervisor::Supervisor;
use crate::system::RealSystem;
use homeshield_core::config::{HomeShieldConfig, DEFAULT_CONF_PATH};
use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

fn print_usage(bin: &str) {
    println!(
        "HomeShield Embedded Daemon v{}\n\
         Usage: {bin} [--config <path>] <command>\n\n\
         Commands:\n\
         \tstart | resume    Enable sinkhole and load hosts into RAM\n\
         \tstop  | pause     Pause sinkhole and restore clean hosts\n\
         \ttoggle            Atomically flip between ACTIVE and PAUSED\n\
         \trestart           Reload sinkhole rules and signal dnsmasq\n\
         \tupdate            Fetch, parse, deduplicate, and apply blocklists\n\
         \tcheck             Verify NTP time, interval expiry, and RAM cache\n\
         \tstatus            Print operational status and autonomy telemetry\n\
         \twatchdog | daemon Run unified resident firewall & blocklist supervisor\n\
         \thelp              Show this help message",
        env!("CARGO_PKG_VERSION")
    );
}

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let mut conf_path = PathBuf::from(DEFAULT_CONF_PATH);
    let mut action: Option<String> = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" | "-c" => {
                if let Some(p) = args.next() {
                    conf_path = PathBuf::from(p);
                } else {
                    eprintln!("Error: --config requires a file path");
                    return ExitCode::from(2);
                }
            }
            "--version" | "-V" => {
                println!("homeshield-daemon {}", env!("CARGO_PKG_VERSION"));
                return ExitCode::SUCCESS;
            }
            "--help" | "-h" | "help" => {
                print_usage("homeshield-daemon");
                return ExitCode::SUCCESS;
            }
            other if action.is_none() => {
                action = Some(other.to_string());
            }
            other => {
                eprintln!("Error: unexpected argument '{other}'");
                return ExitCode::from(2);
            }
        }
    }

    let Some(cmd) = action else {
        print_usage("homeshield-daemon");
        return ExitCode::from(1);
    };

    let config = match HomeShieldConfig::from_file(&conf_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error loading config {}: {e}", conf_path.display());
            return ExitCode::from(1);
        }
    };

    let engine = AdblockEngine::new(config, RealSystem);

    match cmd.as_str() {
        "start" | "resume" | "restart" => match engine.do_start() {
            Ok(_) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("Error starting HomeShield: {e}");
                ExitCode::from(1)
            }
        },
        "stop" | "pause" => match engine.do_stop() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("Error stopping HomeShield: {e}");
                ExitCode::from(1)
            }
        },
        "toggle" => match engine.do_toggle() {
            Ok(st) => {
                print!("{}", st.format_report());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("Error toggling HomeShield: {e}");
                ExitCode::from(1)
            }
        },
        "update" => match engine.do_update() {
            Ok(true) => ExitCode::SUCCESS,
            Ok(false) => {
                eprintln!("Update aborted (fail-closed validation did not pass)");
                ExitCode::from(1)
            }
            Err(e) => {
                eprintln!("Update error: {e}");
                ExitCode::from(1)
            }
        },
        "check" => match engine.do_check() {
            Ok(_) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("Check error: {e}");
                ExitCode::from(1)
            }
        },
        "status" => match engine.do_status() {
            Ok(st) => {
                print!("{}", st.format_report());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("Status error: {e}");
                ExitCode::from(1)
            }
        },
        "watchdog" | "daemon" | "loop" => {
            let mut sup = Supervisor::new(engine);
            sup.run_forever();
        }
        other => {
            eprintln!("Unknown command: {other}");
            print_usage("homeshield-daemon");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests;
