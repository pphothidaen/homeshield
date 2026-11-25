use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes192;
use anyhow::{bail, Result};
use rand::Rng;
use reqwest::Client;
use std::time::Duration;
use tokio::time::sleep;
use url::Url;

const AES_KEY_POOL_V1: [u8; 96] = [
    0x7B, 0x56, 0xB0, 0xF7, 0xDA, 0x0E, 0x68, 0x52, 0xC8, 0x19, 0xF3, 0x2B, 0x84, 0x90, 0x79, 0xE5,
    0x62, 0xF8, 0xEA, 0xD2, 0x64, 0x93, 0x87, 0xDF, 0x73, 0xD7, 0xFB, 0xCC, 0xAA, 0xFE, 0x75, 0x43,
    0x1C, 0x29, 0xDF, 0x4C, 0x52, 0x2C, 0x6E, 0x7B, 0x45, 0x3D, 0x1F, 0xF1, 0xDE, 0xBC, 0x27, 0x85,
    0x8A, 0x45, 0x91, 0xBE, 0x38, 0x13, 0xDE, 0x67, 0x32, 0x08, 0x54, 0x11, 0x75, 0xF4, 0xD3, 0xB4,
    0xA4, 0xB3, 0x12, 0x86, 0x67, 0x23, 0x99, 0x4C, 0x61, 0x7F, 0xB1, 0xD2, 0x30, 0xDF, 0x47, 0xF1,
    0x76, 0x93, 0xA3, 0x8C, 0x95, 0xD3, 0x59, 0xBF, 0x87, 0x8E, 0xF3, 0xB3, 0xE4, 0x76, 0x49, 0x88,
];

const AES_KEY_POOL_V2: [u8; 96] = [
    0x8C, 0x23, 0x65, 0xD1, 0xFC, 0x32, 0x45, 0x37, 0x11, 0x28, 0x71, 0x63, 0x07, 0x20, 0x69, 0x14,
    0x73, 0xE7, 0xD4, 0x53, 0x13, 0x24, 0x36, 0xC2, 0xB5, 0xE1, 0xFC, 0xCF, 0x8A, 0x9A, 0x41, 0x89,
    0x3C, 0x49, 0xCF, 0x5C, 0x72, 0x8C, 0x9E, 0xEB, 0x75, 0x0D, 0x3F, 0xD1, 0xFE, 0xCC, 0x57, 0x65,
    0x7A, 0x35, 0x21, 0x3E, 0x68, 0x53, 0x7E, 0x97, 0x02, 0x48, 0x74, 0x71, 0x95, 0x34, 0x53, 0x84,
    0xB4, 0xC3, 0xE2, 0xD6, 0x27, 0x3D, 0xE6, 0x5D, 0x72, 0x9C, 0xBC, 0x3D, 0x03, 0xFD, 0x76, 0xC1,
    0x9C, 0x25, 0xA8, 0x92, 0x47, 0xE4, 0x18, 0x0F, 0x24, 0x3F, 0x4F, 0x67, 0xEC, 0x97, 0xF4, 0x99,
];

const CREDENTIAL_CANDIDATES: &[(&str, &str)] = &[
    ("awnfibre", "fibre@dm!n"),
    ("admin", "aisadmin"),
    ("factorymode", "nE%jA@5b"),
];

fn zero_pad(data: &[u8]) -> Vec<u8> {
    let rem = data.len() % 16;
    let pad_len = 16 - rem;
    let mut out = Vec::with_capacity(data.len() + pad_len);
    out.extend_from_slice(data);
    out.resize(data.len() + pad_len, 0);
    out
}

fn zero_unpad(data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    while out.last() == Some(&0) {
        out.pop();
    }
    out
}

fn ecb_encrypt(cipher: &Aes192, data: &[u8]) -> Vec<u8> {
    let padded = zero_pad(data);
    let mut out = padded.clone();
    for chunk in out.as_chunks_mut::<16>().0 {
        let block = aes::Block::from_mut_slice(chunk);
        cipher.encrypt_block(block);
    }
    out
}

fn ecb_decrypt(cipher: &Aes192, data: &[u8]) -> Option<Vec<u8>> {
    #[allow(clippy::manual_is_multiple_of)]
    if data.is_empty() || data.len() % 16 != 0 {
        return None;
    }
    let mut out = data.to_vec();
    for chunk in out.as_chunks_mut::<16>().0 {
        let block = aes::Block::from_mut_slice(chunk);
        cipher.decrypt_block(block);
    }
    Some(zero_unpad(&out))
}

/// Perform ZTE Factory Mode challenge-response negotiation and return `(username, password)`.
pub async fn negotiate(
    ip: &str,
    port: u16,
    timeout_secs: u64,
    max_retries: usize,
) -> Result<(String, String)> {
    let mut last_err = anyhow::anyhow!("unknown error");

    for attempt in 1..=max_retries {
        match negotiate_once(ip, port, timeout_secs).await {
            Ok(creds) => return Ok(creds),
            Err(err) => {
                last_err = err;
                if attempt < max_retries {
                    sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }

    bail!("Factory Mode negotiation failed after {max_retries} attempts: {last_err}")
}

async fn negotiate_once(ip: &str, port: u16, timeout_secs: u64) -> Result<(String, String)> {
    let client = Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .build()?;
    let web_fac = format!("http://{ip}:{port}/webFac");
    let web_fac_entry = format!("http://{ip}:{port}/webFacEntry");

    let _ = client
        .post(&web_fac)
        .body("SendSq.gch")
        .timeout(Duration::from_secs(2))
        .send()
        .await;
    let _ = client
        .post(&web_fac)
        .body("RequestFactoryMode.gch")
        .timeout(Duration::from_secs(2))
        .send()
        .await;

    sleep(Duration::from_millis(400)).await;

    let rand_val: usize = rand::thread_rng().gen_range(0..60);
    let resp = client
        .post(&web_fac)
        .body(format!("SendSq.gch?rand={rand_val}\r\n"))
        .send()
        .await?;

    if !resp.status().is_success() {
        bail!("SendSq rejected with status {}", resp.status());
    }

    let body = resp.text().await?;
    let (index, key_pool, proto_ver) = if let Some(rest) = body.strip_prefix("newrand=") {
        let newrand: usize = rest.trim().parse()?;
        let idx = ((0x1000193usize.wrapping_mul(rand_val) & 0x3F) ^ newrand) % 60;
        (idx, &AES_KEY_POOL_V2, 2u8)
    } else {
        (rand_val, &AES_KEY_POOL_V1, 1u8)
    };

    let mut key = [0u8; 24];
    for (i, &b) in key_pool[index..index + 24].iter().enumerate() {
        key[i] = b ^ 0xA5;
    }
    let cipher = Aes192::new_from_slice(&key)?;

    if proto_ver == 2 {
        let _ = client
            .post(&web_fac_entry)
            .body(ecb_encrypt(&cipher, b"SendInfo.gch?info=6|"))
            .send()
            .await;
    }

    let mut authenticated = false;
    for &(user, pwd) in CREDENTIAL_CANDIDATES {
        let payload = format!("CheckLoginAuth.gch?version50&user={user}&pass={pwd}");
        if let Ok(r) = client
            .post(&web_fac_entry)
            .body(ecb_encrypt(&cipher, payload.as_bytes()))
            .send()
            .await
        {
            if r.status().is_success() {
                if let Ok(bytes) = r.bytes().await {
                    if let Some(dec) = ecb_decrypt(&cipher, &bytes) {
                        if dec
                            .windows(b"FactoryMode.gch".len())
                            .any(|w| w == b"FactoryMode.gch")
                        {
                            authenticated = true;
                            break;
                        }
                    }
                }
            }
        }
    }

    if !authenticated {
        bail!("Authentication rejected for all candidate credentials.");
    }

    for m in [2u8, 3, 1, 0] {
        let payload = format!("FactoryMode.gch?mode={m}&user=notused");
        if let Ok(r) = client
            .post(&web_fac_entry)
            .body(ecb_encrypt(&cipher, payload.as_bytes()))
            .send()
            .await
        {
            if r.status().is_success() {
                if let Ok(bytes) = r.bytes().await {
                    if let Some(dec) = ecb_decrypt(&cipher, &bytes) {
                        let text = String::from_utf8_lossy(&dec);
                        if text.contains("user=") && text.contains("pass=") {
                            let full_url = if text.starts_with("http") {
                                text.to_string()
                            } else {
                                format!("http://localhost/{}", text.trim_start_matches('/'))
                            };
                            if let Ok(parsed) = Url::parse(&full_url) {
                                let mut user = None;
                                let mut pass = None;
                                for (k, v) in parsed.query_pairs() {
                                    if k == "user" {
                                        user = Some(v.into_owned());
                                    } else if k == "pass" {
                                        pass = Some(v.into_owned());
                                    }
                                }
                                if let (Some(u), Some(p)) = (user, pass) {
                                    return Ok((u, p));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    bail!("Failed to obtain Telnet credentials from FactoryMode.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes192_ecb_roundtrip() {
        let key = [0x42u8; 24];
        let cipher = Aes192::new_from_slice(&key).unwrap();
        let msg = b"FactoryMode.gch?mode=2&user=notused";
        let enc = ecb_encrypt(&cipher, msg);
        let dec = ecb_decrypt(&cipher, &enc).unwrap();
        assert_eq!(dec, msg);
    }
}
