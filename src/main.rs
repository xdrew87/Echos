// Echos: Red Team traffic emulation and network security research tool in Rust.
// Goals: Emulate network beacons for EDR/NDR testing, implement protocols (HTTP, DNS, ICMP), use tokio/reqwest.
// Focus: Jitter algorithms, header customization to mimic APT signatures.
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
    let profile = profiles.iter().find(|p| p.name == args.profile).unwrap_or(&profiles[0]);

    println!("[+] Echos started. Emulating: {}", profile.name);

    loop {
        // Simulate Beacon Check-in based on protocol
        match profile.protocol {
            Protocol::Http => network::send_http(profile).await?,
            Protocol::Dns => network::send_dns(profile).await?,
            Protocol::Icmp => network::send_icmp(profile).await?,
        }

        // Add Jitter
        let delay = profile.calculate_jitter();
        sleep(delay).await;
    }
}