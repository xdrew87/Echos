use reqwest::header::HeaderMap;
use trust_dns_resolver::Resolver;
use trust_dns_resolver::config::*;
use std::error::Error;

pub async fn send_http(profile: &crate::profiles::TrafficProfile) -> Result<(), Box<dyn Error>> {
    let client = reqwest::Client::new();
    let mut headers = HeaderMap::new();
    for (k, v) in &profile.custom_headers {
        headers.insert(k, v.parse()?);
    }
    let res = client.get(&profile.target).headers(headers).send().await?;
    if res.status().is_success() {
        println!("[!] HTTP Echo sent successfully to {}", profile.target);
    } else {
        eprintln!("[X] HTTP Echo failed: {} for {}", res.status(), profile.target);
    }
    Ok(())
}

pub async fn send_dns(profile: &crate::profiles::TrafficProfile) -> Result<(), Box<dyn Error>> {
    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default())?;
    let response = resolver.lookup_ip(&profile.target).await?;
    let ips: Vec<_> = response.iter().collect();
    println!("[!] DNS lookup for {}: {:?}", profile.target, ips);
    Ok(())
}

pub async fn send_icmp(profile: &crate::profiles::TrafficProfile) -> Result<(), Box<dyn Error>> {
    // Simple ICMP ping using system ping command
    let output = tokio::process::Command::new("ping")
        .arg("-n")
        .arg("1")
        .arg(&profile.target)
        .output()
        .await?;
    if output.status.success() {
        println!("[!] ICMP ping to {} successful", profile.target);
    } else {
        eprintln!("[X] ICMP ping to {} failed", profile.target);
    }
    Ok(())
}
