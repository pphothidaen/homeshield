use anyhow::{bail, Result};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};

pub struct TelnetSession {
    stream: TcpStream,
}

pub fn candidate_credentials(username: &str, password: &str) -> Vec<(String, String)> {
    let mut creds = vec![(username.to_string(), password.to_string())];
    for &(u, p) in &[("root", "admin"), ("root", "!@#$%12345"), ("root", "root")] {
        if !creds.iter().any(|(cu, cp)| cu == u && cp == p) {
            creds.push((u.to_string(), p.to_string()));
        }
    }
    creds
}

impl TelnetSession {
    pub async fn connect(
        ip: &str,
        username: &str,
        password: &str,
        max_retries: usize,
    ) -> Result<Self> {
        let creds = candidate_credentials(username, password);
        let addr = format!("{ip}:23");

        for attempt in 1..=max_retries {
            for (u, p) in &creds {
                match Self::try_auth(&addr, u, p).await {
                    Ok(session) => return Ok(session),
                    Err(err) => {
                        let msg = err.to_string();
                        if msg.contains("Connection refused") {
                            return Err(err);
                        }
                    }
                }
            }
            if attempt < max_retries {
                sleep(Duration::from_secs(1)).await;
            }
        }

        bail!("Could not connect or authenticate to Telnet at {addr}")
    }

    async fn try_auth(addr: &str, user: &str, pass: &str) -> Result<Self> {
        let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(addr)).await??;

        read_until_ci(&mut stream, b"login:", Duration::from_secs(5)).await?;
        stream.write_all(format!("{user}\r\n").as_bytes()).await?;
        sleep(Duration::from_millis(300)).await;

        read_until_ci(&mut stream, b"password:", Duration::from_secs(5)).await?;
        stream.write_all(format!("{pass}\r\n").as_bytes()).await?;
        sleep(Duration::from_millis(500)).await;

        // Send Ctrl+C to break out of ZTE PLOAM menu
        stream.write_all(b"\x03\r\n").await?;
        sleep(Duration::from_millis(300)).await;

        let mut banner = drain_available(&mut stream, Duration::from_millis(350)).await;
        if has_shell_prompt(&banner) {
            return Ok(Self { stream });
        }

        // Retry Ctrl+C once
        stream.write_all(b"\x03\r\n").await?;
        sleep(Duration::from_millis(300)).await;
        let more = drain_available(&mut stream, Duration::from_millis(350)).await;
        banner.extend_from_slice(&more);

        if has_shell_prompt(&banner) {
            return Ok(Self { stream });
        }

        bail!("No shell prompt after login")
    }

    pub async fn run_cmd(&mut self, cmd: &str, cmd_timeout: Duration) -> Result<String> {
        let line = format!("{}\r\n", cmd.trim());
        self.stream.write_all(line.as_bytes()).await?;
        sleep(Duration::from_millis(400)).await;

        let mut resp = Vec::with_capacity(4096);
        let mut buf = [0u8; 4096];
        let deadline = tokio::time::Instant::now() + cmd_timeout;

        loop {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                break;
            }
            let remaining = deadline - now;
            match timeout(remaining, self.stream.read(&mut buf)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    resp.extend_from_slice(&buf[..n]);
                    if contains_bytes(&resp, b"root@F6107A")
                        || contains_bytes(&resp, b"# ")
                        || contains_bytes(&resp, b"$ ")
                    {
                        break;
                    }
                }
                Ok(Err(_)) | Err(_) => break,
            }
        }

        Ok(String::from_utf8_lossy(&resp).into_owned())
    }
}

fn has_shell_prompt(buf: &[u8]) -> bool {
    buf.contains(&b'#')
        || buf.contains(&b'$')
        || contains_bytes(buf, b"root@")
        || contains_bytes(buf, b"F6107A")
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

async fn read_until_ci(stream: &mut TcpStream, needle: &[u8], max_wait: Duration) -> Result<()> {
    let mut acc = Vec::with_capacity(1024);
    let mut buf = [0u8; 1024];
    let deadline = tokio::time::Instant::now() + max_wait;

    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            bail!(
                "Timed out waiting for {:?}",
                String::from_utf8_lossy(needle)
            );
        }
        let n = timeout(deadline - now, stream.read(&mut buf)).await??;
        if n == 0 {
            bail!(
                "EOF while waiting for {:?}",
                String::from_utf8_lossy(needle)
            );
        }
        acc.extend_from_slice(&buf[..n]);
        let lower: Vec<u8> = acc.iter().map(|b| b.to_ascii_lowercase()).collect();
        if contains_bytes(&lower, needle) {
            return Ok(());
        }
    }
}

async fn drain_available(stream: &mut TcpStream, wait: Duration) -> Vec<u8> {
    let mut acc = Vec::new();
    let mut buf = [0u8; 4096];
    while let Ok(Ok(n)) = timeout(wait, stream.read(&mut buf)).await {
        if n == 0 {
            break;
        }
        acc.extend_from_slice(&buf[..n]);
    }
    acc
}
