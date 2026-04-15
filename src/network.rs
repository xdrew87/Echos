use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use std::str::FromStr;
use std::time::Duration;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::*;
use std::error::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};

use crate::runtime::RuntimeOptions;

fn build_headers(profile: &crate::profiles::TrafficProfile) -> Result<HeaderMap, Box<dyn Error>> {
    let mut headers = HeaderMap::new();
    for (k, v) in &profile.custom_headers {
        headers.insert(HeaderName::from_str(k)?, HeaderValue::from_str(v)?);
    }
    Ok(headers)
}

pub async fn send_http(profile: &crate::profiles::TrafficProfile, _opts: &RuntimeOptions) -> Result<(), Box<dyn Error>> {
    let target = profile.get_target();
    let client = reqwest::Client::new();
    let res = client.get(target).headers(build_headers(profile)?).send().await?;
    if !res.status().is_success() {
        return Err(format!("HTTP {}", res.status()).into());
    }
    tracing::debug!(target, status = %res.status(), "HTTP response received");
    Ok(())
}

/// HTTPS beacon. TLS certificate validation is enabled by default; pass `--insecure-tls` to
/// allow self-signed or invalid certificates (e.g. for lab C2 servers).
pub async fn send_https(profile: &crate::profiles::TrafficProfile, opts: &RuntimeOptions) -> Result<(), Box<dyn Error>> {
    let target = profile.get_target();
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(opts.insecure_tls)
        .build()?;
    let res = client.get(target).headers(build_headers(profile)?).send().await?;
    if !res.status().is_success() {
        return Err(format!("HTTPS {}", res.status()).into());
    }
    tracing::debug!(target, status = %res.status(), "HTTPS response received");
    Ok(())
}

pub async fn send_dns(profile: &crate::profiles::TrafficProfile, _opts: &RuntimeOptions) -> Result<(), Box<dyn Error>> {
    let target = profile.get_target();
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())?;
    let response = resolver.lookup_ip(target).await?;
    let ips: Vec<_> = response.iter().collect();
    tracing::debug!(target, ?ips, "DNS lookup result");
    Ok(())
}

pub async fn send_icmp(profile: &crate::profiles::TrafficProfile, _opts: &RuntimeOptions) -> Result<(), Box<dyn Error>> {
    let target = profile.get_target();
    let output = tokio::process::Command::new("ping")
        .arg("-n")
        .arg("1")
        .arg(target)
        .output()
        .await?;
    if !output.status.success() {
        return Err(format!("ICMP ping to {} failed", target).into());
    }
    tracing::debug!(target, "ICMP ping successful");
    Ok(())
}

/// SMB beacon: establishes a TCP connection to port 445 and sends an SMBv1/v2/v3 negotiate
/// request to trigger lateral-movement and SMB-scanning NDR signatures.
pub async fn send_smb(profile: &crate::profiles::TrafficProfile, opts: &RuntimeOptions) -> Result<(), Box<dyn Error>> {
    let target = profile.get_target();
    // Reject targets that already contain a port to prevent a malformed "host:port:445" address.
    if target.contains(':') {
        return Err(format!(
            "SMB target \"{}\" must be a bare hostname or IP (no port); port 445 is fixed",
            target
        )
        .into());
    }
    let addr = format!("{}:445", target);
    let mut stream = tokio::time::timeout(
        Duration::from_secs(opts.timeout_secs),
        TcpStream::connect(&addr),
    )
    .await
    .map_err(|_| format!("SMB connect to {} timed out", addr))??;

    // NetBIOS Session Message wrapping an SMB_COM_NEGOTIATE request advertising
    // NT LM 0.12, SMB 2.002, SMB 2.???, SMB 3.002, and SMB 3.11 dialects.
    #[rustfmt::skip]
    let smb_negotiate: &[u8] = &[
        // NetBIOS Session Message header: type=0x00, length=69 (0x45)
        0x00, 0x00, 0x00, 0x45,
        // SMB1 header (32 bytes)
        0xff, 0x53, 0x4d, 0x42,  // Protocol magic: "\xffSMB"
        0x72,                     // Command: SMB_COM_NEGOTIATE
        0x00, 0x00, 0x00, 0x00,  // NT Status: STATUS_SUCCESS
        0x18,                     // Flags: CASE_INSENSITIVE | CANONICALIZED_PATHS
        0x01, 0x28,              // Flags2: UNICODE | NTLM | EXTENDED_SECURITY
        0x00, 0x00,              // PID High
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Signature
        0x00, 0x00,              // Reserved
        0x00, 0x00,              // Tree ID
        0xff, 0xfe,              // Process ID
        0x00, 0x00,              // User ID
        0x00, 0x00,              // Multiplex ID
        // Parameter block
        0x00,                    // Word Count: 0
        // Data block
        0x22, 0x00,              // Byte Count: 34 (dialect strings below)
        // Dialects: each prefixed with 0x02, NUL-terminated
        0x02, 0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32, 0x00, // "NT LM 0.12"
        0x02, 0x53, 0x4d, 0x42, 0x20, 0x32, 0x2e, 0x30, 0x30, 0x32, 0x00,        // "SMB 2.002"
        0x02, 0x53, 0x4d, 0x42, 0x20, 0x32, 0x2e, 0x3f, 0x3f, 0x3f, 0x00,        // "SMB 2.???"
    ];

    stream.write_all(smb_negotiate).await?;

    let mut buf = [0u8; 512];
    match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => tracing::debug!(target, bytes = n, "SMB server responded"),
        _ => tracing::debug!(target, "SMB probe sent (no response within timeout)"),
    }
    Ok(())
}

/// WebSocket beacon: connects and sends a single "beacon" text frame, simulating
/// persistent WebSocket-based C2 channels used by modern implants.
pub async fn send_websocket(profile: &crate::profiles::TrafficProfile, opts: &RuntimeOptions) -> Result<(), Box<dyn Error>> {
    let target = profile.get_target();
    let (ws_stream, _) = tokio::time::timeout(
        Duration::from_secs(opts.timeout_secs),
        connect_async(target),
    )
    .await
    .map_err(|_| format!("WebSocket connect to {} timed out", target))??;
    let (mut write, mut read) = ws_stream.split();
    write.send(Message::Text("beacon".into())).await?;
    // Send close frame, then drain the read half until the server's close frame arrives or
    // the timeout expires. Without this, the connection stays in CLOSE_WAIT and can exhaust
    // ports over a long-running beacon loop.
    write.close().await?;
    while let Ok(Some(_)) = tokio::time::timeout(Duration::from_secs(2), read.next()).await {}
    tracing::debug!(target, "WebSocket beacon frame sent");
    Ok(())
}

/// SMTP beacon: probes an SMTP server with EHLO to simulate email-based exfiltration
/// or SMTP C2 channel establishment without sending actual mail.
pub async fn send_smtp(profile: &crate::profiles::TrafficProfile, opts: &RuntimeOptions) -> Result<(), Box<dyn Error>> {
    let target = profile.get_target();
    // Determine address: if the target already specifies a port (e.g. "host:587" or "[::1]:25"),
    // use it as-is. A bare hostname/IP without a port gets port 25 appended.
    // IPv6 literals must be bracketed: "[::1]" → "[::1]:25".
    let addr = if target.starts_with('[') || !target.contains(':') {
        // Bracketed IPv6 or plain hostname/IPv4 — append port 25
        format!("{}:25", target)
    } else {
        // Already has a port component (e.g. "mail.host.com:587")
        target.to_string()
    };

    let mut stream = tokio::time::timeout(
        Duration::from_secs(opts.timeout_secs),
        TcpStream::connect(&addr),
    )
    .await
    .map_err(|_| format!("SMTP connect to {} timed out", addr))??;
    let mut buf = [0u8; 1024];

    // Read SMTP banner
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await??;
    let banner = String::from_utf8_lossy(&buf[..n]);
    tracing::debug!(addr, banner = banner.trim(), "SMTP banner received");

    // Send EHLO to elicit capability advertisement
    stream.write_all(b"EHLO beacon.internal\r\n").await?;
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await??;
    tracing::debug!(addr, bytes = n, "SMTP EHLO response received");

    let _ = stream.write_all(b"QUIT\r\n").await;
    Ok(())
}
