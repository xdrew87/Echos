use std::collections::HashMap;
use std::error::Error;
use std::path::Path;
use serde::Deserialize;

use crate::profiles::{JitterAlgorithm, Protocol, TrafficProfile};

#[derive(Debug, Deserialize)]
struct ProfileConfig {
    name: String,
    protocol: String,
    target: String,
    #[serde(default)]
    targets: Vec<String>,
    #[serde(default)]
    headers: HashMap<String, String>,
    base_delay_secs: u64,
    jitter_percent: f64,
    #[serde(default)]
    jitter_algorithm: String,
}

#[derive(Debug, Deserialize)]
struct ConfigFile {
    profiles: Vec<ProfileConfig>,
}

fn parse_protocol(s: &str) -> Result<Protocol, String> {
    match s.to_lowercase().as_str() {
        "http" => Ok(Protocol::Http),
        "https" => Ok(Protocol::Https),
        "dns" => Ok(Protocol::Dns),
        "icmp" => Ok(Protocol::Icmp),
        "smb" => Ok(Protocol::Smb),
        "websocket" | "ws" => Ok(Protocol::WebSocket),
        "smtp" => Ok(Protocol::Smtp),
        other => Err(format!(
            "unknown protocol '{}'. Valid values: http, https, dns, icmp, smb, websocket, smtp",
            other
        )),
    }
}

fn parse_jitter_algorithm(s: &str) -> Result<JitterAlgorithm, String> {
    match s.to_lowercase().as_str() {
        "" | "uniform" => Ok(JitterAlgorithm::Uniform),
        "gaussian" | "gauss" | "normal" => Ok(JitterAlgorithm::Gaussian),
        "sinusoidal" | "sine" => Ok(JitterAlgorithm::Sinusoidal),
        other => Err(format!(
            "unknown jitter algorithm '{}'. Valid values: uniform, gaussian, sinusoidal",
            other
        )),
    }
}

fn convert(pc: ProfileConfig, source_path: &Path) -> Result<TrafficProfile, String> {
    let protocol = parse_protocol(&pc.protocol)
        .map_err(|e| format!("profile '{}' in {:?}: {}", pc.name, source_path, e))?;
    let jitter_algorithm = parse_jitter_algorithm(&pc.jitter_algorithm)
        .map_err(|e| format!("profile '{}' in {:?}: {}", pc.name, source_path, e))?;

    let mut profile = TrafficProfile::new(&pc.name, &pc.target, pc.base_delay_secs, pc.jitter_percent, protocol);
    profile.jitter_algorithm = jitter_algorithm;
    profile.from_config = true;

    for t in pc.targets {
        profile.add_target(&t);
    }
    for (k, v) in pc.headers {
        profile.add_header(&k, &v);
    }

    Ok(profile)
}

pub fn load_from_file(path: &Path) -> Result<Vec<TrafficProfile>, Box<dyn Error>> {
    let content = std::fs::read_to_string(path)?;
    let config: ConfigFile = toml::from_str(&content)?;

    let mut profiles = Vec::new();
    for pc in config.profiles {
        profiles.push(convert(pc, path)?);
    }
    Ok(profiles)
}

pub fn load_from_dir(dir: &Path) -> Result<Vec<TrafficProfile>, Box<dyn Error>> {
    let mut profiles = Vec::new();
    let mut paths: Vec<_> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map_or(false, |ext| ext == "toml"))
        .collect();
    paths.sort();

    for path in paths {
        profiles.extend(load_from_file(&path)?);
    }
    Ok(profiles)
}
