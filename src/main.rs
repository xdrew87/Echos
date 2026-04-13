// Echos: Red Team traffic emulation and network security research tool in Rust.
// Goals: Emulate network beacons for EDR/NDR testing, implement protocols (HTTP, HTTPS, DNS, ICMP, SMB, WebSocket, SMTP).
// Focus: Jitter algorithms (Uniform, Gaussian, Sinusoidal), header customization to mimic APT signatures.
// Style: Idiomatic Rust, modular, high performance, low memory.
// Educational tool for defensive testing and security auditing.

mod profiles;
mod network;

use std::time::Duration;
use tokio::time::sleep;
use clap::Parser;
use crate::profiles::Protocol;

#[derive(Parser)]
#[command(name = "echos")]
#[command(about = "Red Team traffic emulation tool")]
struct Args {
    #[arg(short, long, default_value = "Cobalt")]
    profile: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let profiles = profiles::get_profiles();
    let profile = match profiles.iter().find(|p| p.name == args.profile) {
        Some(p) => p,
        None => match profiles.first() {
            Some(p) => {
                eprintln!("[!] Profile \"{}\" not found, falling back to \"{}\"", args.profile, p.name);
                p
            }
            None => {
                eprintln!("[X] No profiles available. Exiting.");
                std::process::exit(1);
            }
        },
    };

    println!("[+] Echos started. Profile: {} | Protocol: {:?} | Jitter: {:?}",
        profile.name, profile.protocol, profile.jitter_algorithm);

    let mut consecutive_failures: u32 = 0;
    const MAX_BACKOFF_SECS: u64 = 300;

    loop {
        let result = match profile.protocol {
            Protocol::Http     => network::send_http(profile).await,
            Protocol::Https    => network::send_https(profile).await,
            Protocol::Dns      => network::send_dns(profile).await,
            Protocol::Icmp     => network::send_icmp(profile).await,
            Protocol::Smb      => network::send_smb(profile).await,
            Protocol::WebSocket => network::send_websocket(profile).await,
            Protocol::Smtp     => network::send_smtp(profile).await,
        };

        match result {
            Ok(_) => {
                consecutive_failures = 0;
            }
            Err(e) => {
                consecutive_failures += 1;
                eprintln!("[X] Beacon error (failure #{}): {}", consecutive_failures, e);

                if consecutive_failures >= 3 {
                    // Exponential backoff: 2^n seconds, capped at MAX_BACKOFF_SECS
                    let backoff_secs = (2u64.pow(consecutive_failures.min(8))).min(MAX_BACKOFF_SECS);
                    eprintln!("[~] Exponential backoff: waiting {}s before retry", backoff_secs);
                    sleep(Duration::from_secs(backoff_secs)).await;
                    continue;
                }
            }
        }

        let delay = profile.calculate_jitter();
        println!("[~] Next beacon in {:.1}s", delay.as_secs_f64());
        sleep(delay).await;
    }
}