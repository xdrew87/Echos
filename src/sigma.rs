//! Sigma detection rule generator for Echos profiles.
//!
//! Generates experimental Sigma YAML rules from profile definitions.
//! Field names follow common Sigma log source conventions (proxy, network_connection, dns).
//! Review and tune rules before deploying in production.

use crate::profiles::{Protocol, TrafficProfile};

/// Generate a Sigma rule YAML string for the given profile.
pub fn generate(profile: &TrafficProfile) -> String {
    let mut lines: Vec<String> = Vec::new();
    let slug = slugify(&profile.name);

    lines.push(format!("title: Echos - {}", profile.name));
    lines.push(format!("id: echos-{}", slug));
    lines.push("status: experimental".to_string());
    lines.push(format!(
        "description: \"Detects beacon traffic matching the Echos '{}' profile ({} protocol).\"",
        escape_yaml(&profile.name),
        profile.protocol.display_name()
    ));
    lines.push("author: Echos (generated)".to_string());
    lines.push(format!("date: {}", chrono::Local::now().format("%Y-%m-%d")));
    lines.push("references:".to_string());
    lines.push("  - https://github.com/xdrew87/Echos".to_string());

    let tags = build_tags(profile);
    lines.push("tags:".to_string());
    for tag in tags {
        lines.push(format!("  - {}", tag));
    }

    let logsource = build_logsource(profile);
    lines.push("logsource:".to_string());
    for ls in logsource {
        lines.push(format!("  {}", ls));
    }

    let detection = build_detection(profile);
    lines.push("detection:".to_string());
    lines.push("  selection:".to_string());
    for d in detection {
        lines.push(format!("    {}", d));
    }
    lines.push("  condition: selection".to_string());

    let fields = build_fields(profile);
    lines.push("fields:".to_string());
    for f in fields {
        lines.push(format!("  - {}", f));
    }

    lines.push("falsepositives:".to_string());
    lines.push("  - Legitimate traffic using the same user-agent or ports".to_string());
    lines.push("  - Security scanning tools".to_string());
    lines.push("level: medium".to_string());

    lines.join("\n")
}

fn slugify(name: &str) -> String {
    let raw: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    raw.split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

fn escape_yaml(s: &str) -> String {
    s.replace('"', "\\\"")
}

fn build_tags(profile: &TrafficProfile) -> Vec<&'static str> {
    let mut tags = vec!["attack.command_and_control"];
    match &profile.protocol {
        Protocol::Http | Protocol::Https | Protocol::Http2 | Protocol::WebSocket => {
            tags.push("attack.t1071.001");
        }
        Protocol::Dns => {
            tags.push("attack.t1071.004");
        }
        Protocol::Smtp => {
            tags.push("attack.t1071.003");
        }
        Protocol::Icmp => {
            tags.push("attack.t1095");
        }
        Protocol::Smb => {
            tags.push("attack.t1021.002");
            tags.push("attack.lateral_movement");
        }
        Protocol::Ftp => {
            tags.push("attack.t1048");
            tags.push("attack.exfiltration");
        }
        Protocol::Ldap => {
            tags.push("attack.t1018");
            tags.push("attack.discovery");
        }
        Protocol::Rdp => {
            tags.push("attack.t1021.001");
            tags.push("attack.lateral_movement");
        }
    }
    tags
}

fn build_logsource(profile: &TrafficProfile) -> Vec<String> {
    match &profile.protocol {
        Protocol::Http | Protocol::Https | Protocol::Http2 | Protocol::WebSocket => {
            vec!["category: proxy".to_string()]
        }
        Protocol::Dns => {
            vec!["category: dns".to_string()]
        }
        _ => {
            vec!["category: network_connection".to_string()]
        }
    }
}

fn build_detection(profile: &TrafficProfile) -> Vec<String> {
    match &profile.protocol {
        Protocol::Http | Protocol::Https | Protocol::Http2 | Protocol::WebSocket => {
            http_detection(profile)
        }
        Protocol::Dns => dns_detection(profile),
        Protocol::Icmp => icmp_detection(profile),
        Protocol::Smb => port_detection(445),
        Protocol::Smtp => port_detection(25),
        Protocol::Ftp => port_detection(21),
        Protocol::Ldap => port_detection(389),
        Protocol::Rdp => port_detection(3389),
    }
}

fn http_detection(profile: &TrafficProfile) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(ua) = profile.custom_headers.get("User-Agent") {
        lines.push(format!("cs-useragent|contains: \"{}\"", escape_yaml(ua)));
    } else {
        lines.push("cs-method: 'GET'".to_string());
    }
    // Comment non-standard custom headers for analyst reference
    for (k, v) in &profile.custom_headers {
        if !matches!(
            k.as_str(),
            "User-Agent"
                | "Accept"
                | "Accept-Language"
                | "Accept-Encoding"
                | "Connection"
                | "Cache-Control"
        ) {
            lines.push(format!("# custom header {}: {}", k, escape_yaml(v)));
        }
    }
    lines
}

fn dns_detection(profile: &TrafficProfile) -> Vec<String> {
    let mut lines = Vec::new();
    if profile.targets.is_empty() {
        lines.push(format!(
            "QueryName|contains: \"{}\"",
            extract_host(&profile.target)
        ));
    } else {
        lines.push("QueryName|contains:".to_string());
        lines.push(format!("  - \"{}\"", extract_host(&profile.target)));
        for t in &profile.targets {
            lines.push(format!("  - \"{}\"", extract_host(t)));
        }
    }
    lines.push("QueryType: 'A'".to_string());
    lines
}

fn icmp_detection(profile: &TrafficProfile) -> Vec<String> {
    vec![
        "Network.Protocol: 'icmp'".to_string(),
        format!("DestinationIp: \"{}\"", extract_host(&profile.target)),
        "Initiated: 'true'".to_string(),
    ]
}

fn port_detection(port: u16) -> Vec<String> {
    vec![
        format!("DestinationPort: {}", port),
        "Initiated: 'true'".to_string(),
    ]
}

fn build_fields(profile: &TrafficProfile) -> Vec<&'static str> {
    match &profile.protocol {
        Protocol::Http | Protocol::Https | Protocol::Http2 | Protocol::WebSocket => {
            vec![
                "cs-useragent",
                "cs-host",
                "cs-method",
                "cs-uri-stem",
                "sc-status",
                "c-ip",
            ]
        }
        Protocol::Dns => vec!["QueryName", "QueryType", "record_type", "answers"],
        Protocol::Icmp => vec!["DestinationIp", "SourceIp", "Network.Protocol"],
        _ => vec![
            "DestinationIp",
            "DestinationPort",
            "SourceIp",
            "SourcePort",
            "Initiated",
        ],
    }
}

fn extract_host(target: &str) -> &str {
    let s = target
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_start_matches("wss://")
        .trim_start_matches("ws://")
        .trim_start_matches("ftp://")
        .trim_start_matches("ldap://")
        .trim_start_matches("smb://")
        .trim_start_matches("rdp://");
    // Remove port (:xxxx) and path (/...)
    let s = if let Some(idx) = s.find(':') {
        &s[..idx]
    } else {
        s
    };
    if let Some(idx) = s.find('/') {
        &s[..idx]
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profiles::{Protocol, TrafficProfile};

    #[test]
    fn test_slugify() {
        assert_eq!(slugify("CS DNS Beacon"), "cs-dns-beacon");
        assert_eq!(slugify("APT28"), "apt28");
        assert_eq!(slugify("My--Profile"), "my-profile");
    }

    #[test]
    fn test_extract_host() {
        assert_eq!(extract_host("http://example.com/path"), "example.com");
        assert_eq!(extract_host("https://example.com:8443/path"), "example.com");
        assert_eq!(extract_host("example.com"), "example.com");
        assert_eq!(extract_host("ws://127.0.0.1:8080"), "127.0.0.1");
    }

    #[test]
    fn test_generate_contains_title() {
        let p = TrafficProfile::new(
            "Test Profile",
            "http://example.com",
            10,
            20.0,
            Protocol::Http,
        );
        let yaml = generate(&p);
        assert!(yaml.contains("title: Echos - Test Profile"));
        assert!(yaml.contains("status: experimental"));
        assert!(yaml.contains("attack.command_and_control"));
    }

    #[test]
    fn test_generate_dns() {
        let p = TrafficProfile::new("APT28", "example.com", 30, 10.0, Protocol::Dns);
        let yaml = generate(&p);
        assert!(yaml.contains("category: dns"));
        assert!(yaml.contains("attack.t1071.004"));
        assert!(yaml.contains("QueryName|contains"));
    }

    #[test]
    fn test_generate_http_with_ua() {
        let mut p =
            TrafficProfile::new("Cobalt", "http://127.0.0.1:8080", 10, 20.0, Protocol::Http);
        p.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0)");
        let yaml = generate(&p);
        assert!(yaml.contains("cs-useragent|contains"));
        assert!(yaml.contains("Mozilla/5.0"));
    }

    #[test]
    fn test_generate_smb() {
        let p = TrafficProfile::new("SMB Beacon", "127.0.0.1", 120, 10.0, Protocol::Smb);
        let yaml = generate(&p);
        assert!(yaml.contains("DestinationPort: 445"));
        assert!(yaml.contains("attack.t1021.002"));
    }

    #[test]
    fn test_generate_http2_uses_http_tags() {
        let p = TrafficProfile::new("APT41", "https://127.0.0.1:8443", 45, 15.0, Protocol::Http2);
        let yaml = generate(&p);
        assert!(yaml.contains("category: proxy"));
        assert!(yaml.contains("attack.t1071.001"));
    }
}
