use homeshield_core::blocklist::{stream_precompiled_hosts, BlocklistCompiler};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, BufReader};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    pub status_code: i32,
    pub stdout: String,
    pub stderr: String,
}

pub trait SystemOps {
    fn now_epoch(&self) -> u64;
    fn format_timestamp(&self, epoch: u64) -> String;
    fn run_command(&self, program: &str, args: &[&str]) -> io::Result<CommandOutput>;
    fn fetch_url_lines(&self, url: &str, compiler: &mut BlocklistCompiler) -> io::Result<usize>;
    /// Stream a pre-compiled Tier 0 CDN URL directly to `out_path` with O(1) RAM.
    /// Returns `(cdn_domains, total_domains_with_anti_bypass)`.
    fn stream_url_to_file(
        &self,
        url: &str,
        out_path: &Path,
        whitelist: &HashSet<String>,
        block_canary_doh: bool,
        block_apple_private_relay: bool,
    ) -> io::Result<(usize, usize)> {
        let mut compiler = BlocklistCompiler::new(whitelist.clone());
        self.fetch_url_lines(url, &mut compiler)?;
        let cdn_count = compiler.unique_domains_count();
        compiler.inject_anti_bypass(block_canary_doh, block_apple_private_relay);
        let total_count = compiler.unique_domains_count();
        let f = File::create(out_path)?;
        compiler.write_hosts(f)?;
        Ok((cdn_count, total_count))
    }
    fn signal_dnsmasq_hup(&self) -> io::Result<()>;
    fn find_process_pids(&self, name_substr: &str) -> Vec<u32>;
    /// Single-Pass Visitor Pattern: match any of `patterns` in a single `/proc` scan.
    fn find_any_process_pids(&self, patterns: &[&str]) -> Vec<u32> {
        for &pat in patterns {
            let pids = self.find_process_pids(pat);
            if !pids.is_empty() {
                return pids;
            }
        }
        Vec::new()
    }
    fn check_connectivity(&self) -> bool;
    fn sleep_seconds(&self, secs: u64);
}

#[derive(Debug, Default, Clone, Copy)]
pub struct RealSystem;

impl SystemOps for RealSystem {
    fn now_epoch(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn format_timestamp(&self, epoch: u64) -> String {
        format_utc_timestamp(epoch)
    }

    fn run_command(&self, program: &str, args: &[&str]) -> io::Result<CommandOutput> {
        let out = Command::new(program).args(args).output()?;
        Ok(CommandOutput {
            status_code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }

    fn fetch_url_lines(&self, url: &str, compiler: &mut BlocklistCompiler) -> io::Result<usize> {
        if let Some(local_path) = url.strip_prefix("file://") {
            let file = File::open(local_path)?;
            return compiler.process_reader(BufReader::new(file));
        }

        // Ignore SIGTERM inside the curl child only (ZTE firmware/uClibc AsynchDNS reaper sends
        // spurious SIGTERM to curl), keeping the parent daemon itself responsive to SIGTERM.
        let mut child = Command::new("sh")
            .args([
                "-c",
                "trap '' TERM; exec curl -skfL --connect-timeout 10 --max-time 90 \"$1\"",
                "homeshield-curl",
                url,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "missing curl stdout"))?;
        let added = compiler.process_reader(BufReader::new(stdout))?;
        let status = child.wait()?;
        if !status.success() && added == 0 {
            return Err(io::Error::other(format!(
                "curl failed for {url} with status {status}"
            )));
        }
        Ok(added)
    }

    fn stream_url_to_file(
        &self,
        url: &str,
        out_path: &Path,
        whitelist: &HashSet<String>,
        block_canary_doh: bool,
        block_apple_private_relay: bool,
    ) -> io::Result<(usize, usize)> {
        if let Some(local_path) = url.strip_prefix("file://") {
            let src = File::open(local_path)?;
            let dst = File::create(out_path)?;
            let res = stream_precompiled_hosts(
                BufReader::with_capacity(128 * 1024, src),
                dst,
                whitelist,
                block_canary_doh,
                block_apple_private_relay,
            );
            if res.is_err() {
                let _ = fs::remove_file(out_path);
            }
            return res;
        }

        let mut child = Command::new("sh")
            .args([
                "-c",
                "trap '' TERM; exec curl -skfL --connect-timeout 10 --max-time 90 \"$1\"",
                "homeshield-curl",
                url,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "missing curl stdout"))?;
        let dst = File::create(out_path)?;
        let res = stream_precompiled_hosts(
            BufReader::with_capacity(128 * 1024, stdout),
            dst,
            whitelist,
            block_canary_doh,
            block_apple_private_relay,
        );
        if res.is_err() {
            let _ = child.kill();
            let _ = child.wait();
            let _ = fs::remove_file(out_path);
            return res;
        }
        let status = child.wait()?;
        if !status.success() {
            let _ = fs::remove_file(out_path);
            return Err(io::Error::other(format!(
                "curl failed for {url} with status {status}"
            )));
        }
        res
    }

    fn signal_dnsmasq_hup(&self) -> io::Result<()> {
        let pids = self.find_process_pids("dnsmasq");
        if !pids.is_empty() {
            let mut signaled = false;
            for pid in pids {
                let pid_str = pid.to_string();
                if let Ok(out) = self.run_command("kill", &["-HUP", &pid_str]) {
                    if out.status_code == 0 {
                        signaled = true;
                    }
                }
            }
            if signaled {
                return Ok(());
            }
        }
        // Fallback for non-proc or BusyBox compatibility
        let _ = self.run_command("killall", &["-HUP", "dnsmasq"]);
        Ok(())
    }

    fn find_process_pids(&self, name_substr: &str) -> Vec<u32> {
        self.find_any_process_pids(&[name_substr])
    }

    fn find_any_process_pids(&self, patterns: &[&str]) -> Vec<u32> {
        let mut pids = Vec::new();
        let self_pid = std::process::id();
        let Ok(entries) = fs::read_dir("/proc") else {
            return pids;
        };

        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let Some(name_str) = file_name.to_str() else {
                continue;
            };
            let Ok(pid) = name_str.parse::<u32>() else {
                continue;
            };
            if pid == self_pid {
                continue;
            }

            let cmdline_path = entry.path().join("cmdline");
            if let Ok(raw_cmd) = fs::read(&cmdline_path) {
                let cmd = String::from_utf8_lossy(&raw_cmd).replace('\0', " ");
                if patterns.iter().any(|pat| cmd.contains(pat)) {
                    pids.push(pid);
                    continue;
                }
            }

            let comm_path = entry.path().join("comm");
            if let Ok(comm) = fs::read_to_string(&comm_path) {
                let trimmed = comm.trim();
                if patterns.iter().any(|pat| trimmed.contains(pat)) {
                    pids.push(pid);
                }
            }
        }

        pids.sort_unstable();
        pids
    }

    fn check_connectivity(&self) -> bool {
        let timeout = Duration::from_secs(3);
        let targets = [
            SocketAddr::from(([8, 8, 8, 8], 53)),
            SocketAddr::from(([1, 1, 1, 1], 53)),
        ];
        for addr in targets {
            if TcpStream::connect_timeout(&addr, timeout).is_ok() {
                return true;
            }
        }
        if let Ok(out) = self.run_command("ping", &["-c", "1", "-W", "3", "8.8.8.8"]) {
            if out.status_code == 0 {
                return true;
            }
        }
        false
    }

    fn sleep_seconds(&self, secs: u64) {
        thread::sleep(Duration::from_secs(secs));
    }
}

/// Convert UNIX epoch seconds into `YYYY-MM-DD HH:MM:SS` (UTC) using Howard Hinnant's
/// civil-from-days algorithm, avoiding libc/date subprocess dependencies.
pub fn format_utc_timestamp(epoch: u64) -> String {
    let secs_of_day = (epoch % 86_400) as u32;
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;

    let z = (epoch / 86_400) as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + if m <= 2 { 1 } else { 0 };

    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        year, m, d, hour, minute, second
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_utc_timestamp() {
        assert_eq!(format_utc_timestamp(0), "1970-01-01 00:00:00");
        assert_eq!(format_utc_timestamp(1_700_000_000), "2023-11-14 22:13:20");
    }
}
