//! Suricata IDS rule generator for Echos profiles.
//!
//! Generates experimental Suricata rules from profile definitions.
//! Rules use Suricata's sticky buffer keywords for accurate matching.
//! Review and tune before deploying in production.

use crate::profiles::{Protocol, TrafficProfile};

/// SID base — Echos uses 9_000_000 range to avoid colliding with public rulesets.
const SID_BASE: u64 = 9_000_000;

/// Generate a Suricata rules string for the given profile.
/// May return multiple rules (one per target if rotating targets).
pub fn generate(profile: &TrafficProfile, profile_index: usize) -> String {
    let mut lines: Vec<String> = Vec::new();

    lines.push(format!(
        "# Echos - Suricata Rules for profile: {}",
        profile.name
    ));
    lines.push(format!("# Protocol: {}", profile.protocol.display_name()));
    lines.push(format!(
        "# Generated: {}",
        chrono::Local::now().format("%Y-%m-%d")
    ));
    lines.push("# Status: experimental - review and tune before production use".to_string());
    lines.push("# https://github.com/xdrew87/Echos".to_string());

    for rule in build_rules(profile, profile_index) {
        lines.push(rule);
    }

    lines.join("\n")
}

fn make_sid(profile_index: usize, offset: usize) -> u64 {
    SID_BASE + (profile_index as u64) * 100 + offset as u64
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

fn build_rules(profile: &TrafficProfile, profile_index: usize) -> Vec<String> {
    match &profile.protocol {
        Protocol::Http | Protocol::Https | Protocol::WebSocket => {
            vec![build_http_rule(profile, make_sid(profile_index, 1))]
        }
        Protocol::Dns => {
            let primary = profile.target.clone();
            let extras: Vec<String> = profile.targets.clone();
            let mut rules = vec![build_dns_rule(
                profile,
                &primary,
                make_sid(profile_index, 1),
            )];
            for (i, t) in extras.iter().enumerate() {
                rules.push(build_dns_rule(profile, t, make_sid(profile_index, i + 2)));
            }
            rules
        }
        Protocol::Icmp => vec![build_icmp_rule(profile, make_sid(profile_index, 1))],
        Protocol::Smb => vec![build_tcp_port_rule(
            profile,
            445,
            "SMB",
            make_sid(profile_index, 1),
        )],
        Protocol::Smtp => vec![build_tcp_port_rule(
            profile,
            25,
            "SMTP",
            make_sid(profile_index, 1),
        )],
        Protocol::Ftp => vec![build_tcp_port_rule(
            profile,
            21,
            "FTP",
            make_sid(profile_index, 1),
        )],
        Protocol::Ldap => vec![build_tcp_port_rule(
            profile,
            389,
            "LDAP",
            make_sid(profile_index, 1),
        )],
        Protocol::Rdp => vec![build_tcp_port_rule(
            profile,
            3389,
            "RDP",
            make_sid(profile_index, 1),
        )],
    }
}

fn build_http_rule(profile: &TrafficProfile, sid: u64) -> String {
    let slug = slugify(&profile.name);
    let proto_label = if matches!(&profile.protocol, Protocol::Https) {
        "https"
    } else {
        "http"
    };
    let mut opts: Vec<String> = Vec::new();
    opts.push(format!("msg:\"Echos - {}\";", profile.name));
    opts.push("flow:established,to_server;".to_string());
    if let Some(ua) = profile.custom_headers.get("User-Agent") {
        opts.push("http.user_agent;".to_string());
        opts.push(format!("content:\"{}\"; nocase;", ua));
    } else {
        opts.push("http.method;".to_string());
        opts.push("content:\"GET\";".to_string());
    }
    if let Some(ct) = profile.custom_headers.get("Content-Type") {
        opts.push("http.content_type;".to_string());
        opts.push(format!("content:\"{}\";", ct));
    }
    opts.push("classtype:trojan-activity;".to_string());
    opts.push(format!("sid:{}; rev:1;", sid));
    opts.push(format!(
        "metadata:profile {}, tool Echos, protocol {};",
        slug, proto_label
    ));
    format!(
        "alert http $HOME_NET any -> $EXTERNAL_NET any ({})",
        opts.join(" ")
    )
}

fn build_dns_rule(profile: &TrafficProfile, target: &str, sid: u64) -> String {
    let slug = slugify(&profile.name);
    let host = extract_host(target);
    let mut opts: Vec<String> = Vec::new();
    opts.push(format!("msg:\"Echos - {} DNS Beacon\";", profile.name));
    opts.push("dns.query;".to_string());
    opts.push(format!("content:\"{}\"; nocase;", host));
    opts.push("classtype:trojan-activity;".to_string());
    opts.push(format!("sid:{}; rev:1;", sid));
    opts.push(format!(
        "metadata:profile {}, tool Echos, protocol dns;",
        slug
    ));
    format!("alert dns $HOME_NET any -> any 53 ({})", opts.join(" "))
}

fn build_icmp_rule(profile: &TrafficProfile, sid: u64) -> String {
    let slug = slugify(&profile.name);
    let dst_raw = extract_host(&profile.target);
    let dst_ip = if !dst_raw.is_empty()
        && dst_raw.chars().all(|c| c.is_ascii_digit() || c == '.')
        && dst_raw.contains('.')
    {
        dst_raw
    } else {
        "$EXTERNAL_NET"
    };
    let mut opts: Vec<String> = Vec::new();
    opts.push(format!("msg:\"Echos - {} ICMP Beacon\";", profile.name));
    opts.push("itype:8;".to_string());
    opts.push("classtype:trojan-activity;".to_string());
    opts.push(format!("sid:{}; rev:1;", sid));
    opts.push(format!(
        "metadata:profile {}, tool Echos, protocol icmp;",
        slug
    ));
    format!(
        "alert icmp $HOME_NET any -> {} any ({})",
        dst_ip,
        opts.join(" ")
    )
}

fn build_tcp_port_rule(profile: &TrafficProfile, port: u16, proto_label: &str, sid: u64) -> String {
    let slug = slugify(&profile.name);
    let proto_lower = proto_label.to_lowercase();
    let mut opts: Vec<String> = Vec::new();
    opts.push(format!(
        "msg:\"Echos - {} {} Beacon\";",
        profile.name, proto_label
    ));
    opts.push("flow:established,to_server;".to_string());
    opts.push("classtype:trojan-activity;".to_string());
    opts.push(format!("sid:{}; rev:1;", sid));
    opts.push(format!(
        "metadata:profile {}, tool Echos, protocol {};",
        slug, proto_lower
    ));
    format!(
        "alert tcp $HOME_NET any -> $EXTERNAL_NET {} ({})",
        port,
        opts.join(" ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profiles::{Protocol, TrafficProfile};

    #[test]
    fn test_generate_http_contains_alert_http() {
        let mut p =
            TrafficProfile::new("Cobalt", "http://127.0.0.1:8080", 10, 20.0, Protocol::Http);
        p.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0)");
        let rules = generate(&p, 0);
        assert!(
            rules.contains("alert http"),
            "expected 'alert http' in:\n{}",
            rules
        );
    }

    #[test]
    fn test_generate_dns_contains_alert_dns() {
        let p = TrafficProfile::new("APT28", "example.com", 30, 10.0, Protocol::Dns);
        let rules = generate(&p, 1);
        assert!(
            rules.contains("alert dns"),
            "expected 'alert dns' in:\n{}",
            rules
        );
    }

    #[test]
    fn test_generate_smb_contains_port_445() {
        let p = TrafficProfile::new("SMB Beacon", "127.0.0.1", 120, 10.0, Protocol::Smb);
        let rules = generate(&p, 7);
        assert!(rules.contains("445"), "expected '445' in:\n{}", rules);
    }

    #[test]
    fn test_generate_sid_present() {
        let p = TrafficProfile::new("Test", "http://example.com", 10, 20.0, Protocol::Http);
        let rules = generate(&p, 0);
        assert!(
            rules.contains("sid:9000001"),
            "expected 'sid:9000001' in:\n{}",
            rules
        );
    }

    #[test]
    fn test_generate_rotating_dns_multiple_rules() {
        let mut p = TrafficProfile::new("CS DNS", "beacon.example.com", 20, 30.0, Protocol::Dns);
        p.add_target("stage.example.com");
        p.add_target("cdn.example.com");
        let rules = generate(&p, 0);
        assert!(rules.contains("beacon.example.com"));
        assert!(rules.contains("stage.example.com"));
        assert!(rules.contains("cdn.example.com"));
    }

    #[test]
    fn test_generate_icmp_contains_alert_icmp() {
        let p = TrafficProfile::new("ICMP Beacon", "8.8.8.8", 60, 5.0, Protocol::Icmp);
        let rules = generate(&p, 2);
        assert!(rules.contains("alert icmp"));
        assert!(rules.contains("8.8.8.8"));
        assert!(rules.contains("itype:8"));
    }

    #[test]
    fn test_generate_slugify() {
        assert_eq!(slugify("CS DNS Beacon"), "cs-dns-beacon");
        assert_eq!(slugify("APT28"), "apt28");
    }

    #[test]
    fn test_extract_host() {
        assert_eq!(extract_host("http://example.com/path"), "example.com");
        assert_eq!(extract_host("https://example.com:8443/path"), "example.com");
        assert_eq!(extract_host("example.com"), "example.com");
    }
}
