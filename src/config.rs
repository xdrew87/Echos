use serde::Deserialize;
use std::collections::HashMap;
use std::error::Error;
use std::path::Path;

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
struct SequenceConfig {
    name: String,
    profiles: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ConfigFile {
    #[serde(default)]
    profiles: Vec<ProfileConfig>,
    #[serde(default)]
    sequences: Vec<SequenceConfig>,
}

/// Loaded configuration: profiles and named sequences.
pub struct LoadedConfig {
    pub profiles: Vec<TrafficProfile>,
    pub sequences: HashMap<String, Vec<String>>,
}

fn parse_protocol(s: &str) -> Result<Protocol, String> {
    match s.to_lowercase().as_str() {
        "http" => Ok(Protocol::Http),
        "https" => Ok(Protocol::Https),
        "http2" | "h2" => Ok(Protocol::Http2),
        "dns" => Ok(Protocol::Dns),
        "icmp" => Ok(Protocol::Icmp),
        "smb" => Ok(Protocol::Smb),
        "websocket" | "ws" => Ok(Protocol::WebSocket),
        "smtp" => Ok(Protocol::Smtp),
        "ftp" => Ok(Protocol::Ftp),
        "ldap" => Ok(Protocol::Ldap),
        "rdp" => Ok(Protocol::Rdp),
        other => Err(format!(
            "unknown protocol '{}'. Valid values: http, https, http2, dns, icmp, smb, websocket, smtp, ftp, ldap, rdp",
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

    let mut profile = TrafficProfile::new(
        &pc.name,
        &pc.target,
        pc.base_delay_secs,
        pc.jitter_percent,
        protocol,
    );
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

pub fn load_from_file(path: &Path) -> Result<LoadedConfig, Box<dyn Error>> {
    let content = std::fs::read_to_string(path)?;
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let config: ConfigFile = match ext {
        "yaml" | "yml" => serde_yaml::from_str(&content)?,
        _ => toml::from_str(&content)?,
    };

    let mut profiles = Vec::new();
    for pc in config.profiles {
        profiles.push(convert(pc, path)?);
    }

    let sequences = config
        .sequences
        .into_iter()
        .map(|s| (s.name, s.profiles))
        .collect();

    Ok(LoadedConfig {
        profiles,
        sequences,
    })
}

pub fn load_from_dir(dir: &Path) -> Result<LoadedConfig, Box<dyn Error>> {
    let mut profiles = Vec::new();
    let mut sequences = HashMap::new();

    let mut paths: Vec<_> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .is_some_and(|ext| matches!(ext.to_str(), Some("toml" | "yaml" | "yml")))
        })
        .collect();
    paths.sort();

    for path in paths {
        let loaded = load_from_file(&path)?;
        profiles.extend(loaded.profiles);
        // Later files override earlier on name collision.
        sequences.extend(loaded.sequences);
    }

    Ok(LoadedConfig {
        profiles,
        sequences,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_parse_protocol_supports_http2() {
        assert!(matches!(parse_protocol("http2"), Ok(Protocol::Http2)));
        assert!(matches!(parse_protocol("h2"), Ok(Protocol::Http2)));
    }

    #[test]
    fn test_load_yaml_config_file() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_nanos();
        let path = std::env::current_dir()
            .expect("current dir")
            .join(format!("echos-config-test-{unique}.yaml"));
        let yaml = r#"
profiles:
  - name: "YAML Test"
    protocol: "http2"
    target: "https://127.0.0.1:8443"
    base_delay_secs: 30
    jitter_percent: 10.0
sequences:
  - name: "yaml-seq"
    profiles:
      - "YAML Test"
"#;

        fs::write(&path, yaml).expect("write yaml config");
        let loaded = load_from_file(&path).expect("load yaml config");
        fs::remove_file(&path).expect("remove yaml config");

        assert_eq!(loaded.profiles.len(), 1);
        assert_eq!(loaded.profiles[0].name, "YAML Test");
        assert!(matches!(&loaded.profiles[0].protocol, Protocol::Http2));
        assert_eq!(
            loaded.sequences.get("yaml-seq"),
            Some(&vec!["YAML Test".to_string()])
        );
    }
}
