use anyhow::Result;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

/// Determine local LAN IP address on the same interface that reaches `router_ip`.
pub fn local_ip_for_router(router_ip: &str) -> Result<IpAddr> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.connect(format!("{router_ip}:23"))?;
    Ok(sock.local_addr()?.ip())
}

pub struct EphemeralFileServer {
    pub port: u16,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl EphemeralFileServer {
    /// Start an ephemeral HTTP/1.1 server on `0.0.0.0:0` serving a single binary file.
    pub async fn start(file_path: &Path) -> Result<Self> {
        let filename = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("payload")
            .to_string();
        let data = Arc::new(tokio::fs::read(file_path).await?);
        let listener = TcpListener::bind("0.0.0.0:0").await?;
        let port = listener.local_addr()?.port();
        let (tx, mut rx) = oneshot::channel::<()>();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut rx => break,
                    accept_res = listener.accept() => {
                        let Ok((mut stream, _addr)) = accept_res else { break; };
                        let data = Arc::clone(&data);
                        let expected_path = format!("/{filename}");
                        tokio::spawn(async move {
                            let mut req_buf = [0u8; 2048];
                            let n = stream.read(&mut req_buf).await.unwrap_or(0);
                            let req_str = String::from_utf8_lossy(&req_buf[..n]);
                            let first_line = req_str.lines().next().unwrap_or("");
                            let req_path = first_line.split_whitespace().nth(1).unwrap_or("");

                            if req_path == expected_path {
                                let header = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
                                    data.len()
                                );
                                let _ = stream.write_all(header.as_bytes()).await;
                                let _ = stream.write_all(&data).await;
                            } else {
                                let body = b"Not Found";
                                let header = format!(
                                    "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                    body.len()
                                );
                                let _ = stream.write_all(header.as_bytes()).await;
                                let _ = stream.write_all(body).await;
                            }
                            let _ = stream.shutdown().await;
                        });
                    }
                }
            }
        });

        Ok(Self {
            port,
            shutdown_tx: Some(tx),
        })
    }

    pub fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }

    pub fn local_addr_hint(ip: IpAddr, port: u16, filename: &str) -> String {
        SocketAddr::new(ip, port).to_string() + "/" + filename
    }
}

impl Drop for EphemeralFileServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}
