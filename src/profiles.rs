use std::collections::HashMap;
use std::f64::consts::PI;
use std::time::Duration;
use rand::Rng;
use chrono::Timelike;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JitterAlgorithm {
    /// Uniform random delay within ±jitter_percent of base_delay.
    Uniform,
    /// Gaussian (normal) distribution centered at base_delay via Box-Muller transform.
    Gaussian,
    /// Sinusoidal time-of-day modulation: shorter delays during business hours (09:00–17:00),
    /// longer delays at night to mimic adversaries that blend with business traffic.
    Sinusoidal,
}

impl JitterAlgorithm {
    pub fn display_name(&self) -> &'static str {
        match self {
            JitterAlgorithm::Uniform => "Uniform",
            JitterAlgorithm::Gaussian => "Gaussian",
            JitterAlgorithm::Sinusoidal => "Sinusoidal",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Http,
    Https,
    Dns,
    Icmp,
    Smb,
    WebSocket,
    Smtp,
}

impl Protocol {
    pub fn display_name(&self) -> &'static str {
        match self {
            Protocol::Http => "HTTP",
            Protocol::Https => "HTTPS",
            Protocol::Dns => "DNS",
            Protocol::Icmp => "ICMP",
            Protocol::Smb => "SMB",
            Protocol::WebSocket => "WebSocket",
            Protocol::Smtp => "SMTP",
        }
    }
}

#[derive(Debug, Clone)]
pub struct TrafficProfile {
    pub name: String,
    /// Primary target (URL, hostname, or IP depending on protocol).
    pub target: String,
    /// Optional additional targets; if non-empty, get_target() rotates through them randomly.
    pub targets: Vec<String>,
    pub custom_headers: HashMap<String, String>,
    pub base_delay: Duration,
    pub jitter_percent: f64,
    pub jitter_algorithm: JitterAlgorithm,
    pub protocol: Protocol,
    /// True when loaded from a user-supplied TOML config file.
    pub from_config: bool,
}

impl TrafficProfile {
    pub fn new(
        name: &str,
        target: &str,
        base_delay_secs: u64,
        jitter_percent: f64,
        protocol: Protocol,
    ) -> Self {
        Self {
            name: name.to_string(),
            target: target.to_string(),
            targets: Vec::new(),
            custom_headers: HashMap::new(),
            base_delay: Duration::from_secs(base_delay_secs),
            jitter_percent,
            jitter_algorithm: JitterAlgorithm::Uniform,
            protocol,
            from_config: false,
        }
    }

    /// Builder-style setter for the jitter algorithm.
    pub fn with_jitter_algorithm(mut self, algorithm: JitterAlgorithm) -> Self {
        self.jitter_algorithm = algorithm;
        self
    }

    pub fn add_header(&mut self, key: &str, value: &str) {
        self.custom_headers.insert(key.to_string(), value.to_string());
    }

    pub fn add_target(&mut self, target: &str) {
        self.targets.push(target.to_string());
    }

    /// Returns the active target. When multiple targets are configured, picks one at random
    /// to simulate domain-generation or fast-flux beaconing.
    pub fn get_target(&self) -> &str {
        if self.targets.is_empty() {
            &self.target
        } else {
            let idx = rand::thread_rng().gen_range(0..self.targets.len());
            &self.targets[idx]
        }
    }

    pub fn calculate_jitter(&self) -> Duration {
        let base_secs = self.base_delay.as_secs_f64();
        let jitter_amount = base_secs * (self.jitter_percent / 100.0);
        let mut rng = rand::thread_rng();

        match self.jitter_algorithm {
            JitterAlgorithm::Uniform => {
                let min_delay = base_secs - jitter_amount;
                let max_delay = base_secs + jitter_amount;
                Duration::from_secs_f64(rng.gen_range(min_delay..=max_delay))
            }

            JitterAlgorithm::Gaussian => {
                // Box-Muller transform: produces a standard normal sample z,
                // then scales to mean=base_secs, std_dev=jitter_amount.
                let u1: f64 = rng.gen_range(f64::EPSILON..=1.0);
                let u2: f64 = rng.gen_range(0.0..=1.0);
                let z = (-2.0 * u1.ln()).sqrt() * (2.0 * PI * u2).cos();
                let delay = (base_secs + z * jitter_amount).max(0.1);
                Duration::from_secs_f64(delay)
            }

            JitterAlgorithm::Sinusoidal => {
                // Sinusoidal modifier keyed to local time-of-day.
                // Peaks (3× base) at ~01:00 (off-hours), troughs (1× base) at ~13:00 (business hours).
                let hour = chrono::Local::now().hour() as f64;
                let phase = 2.0 * PI * (hour - 13.0) / 24.0;
                let modifier = 2.0 - f64::sin(phase); // [1.0, 3.0]
                let adjusted_base = base_secs * modifier;
                let adjusted_jitter = jitter_amount * modifier;
                let min_delay = (adjusted_base - adjusted_jitter).max(0.1);
                let max_delay = adjusted_base + adjusted_jitter;
                Duration::from_secs_f64(rng.gen_range(min_delay..=max_delay))
            }
        }
    }
}

pub fn get_profiles() -> Vec<TrafficProfile> {
    // --- Cobalt Strike ---
    let mut cobalt = TrafficProfile::new("Cobalt", "http://127.0.0.1:8080", 10, 20.0, Protocol::Http);
    cobalt.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
    cobalt.add_header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
    cobalt.add_header("Accept-Language", "en-US,en;q=0.5");
    cobalt.add_header("Accept-Encoding", "gzip, deflate");
    cobalt.add_header("Connection", "keep-alive");

    // --- APT28 ---
    let apt28 = TrafficProfile::new("APT28", "example.com", 30, 10.0, Protocol::Dns);

    // --- ICMP Beacon ---
    let icmp_profile = TrafficProfile::new("ICMP Beacon", "8.8.8.8", 60, 5.0, Protocol::Icmp);

    // --- Lazarus Group ---
    // HTTPS C2 with slow, Gaussian-jittered beaconing, mimicking Korean-language browser UA.
    let mut lazarus = TrafficProfile::new("Lazarus", "https://127.0.0.1:8443", 300, 15.0, Protocol::Https)
        .with_jitter_algorithm(JitterAlgorithm::Gaussian);
    lazarus.add_header(
        "User-Agent",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    );
    lazarus.add_header("Accept-Language", "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7");
    lazarus.add_header("Accept-Encoding", "gzip, deflate, br");
    lazarus.add_header("Cache-Control", "no-cache");
    lazarus.add_header("Pragma", "no-cache");

    // --- APT29 / Cozy Bear ---
    // Ultra-slow HTTPS beaconing with sinusoidal (business-hours) jitter to blend with
    // enterprise traffic, mimicking Office 365 authentication flows.
    let mut apt29 = TrafficProfile::new("APT29", "https://127.0.0.1:8443", 600, 10.0, Protocol::Https)
        .with_jitter_algorithm(JitterAlgorithm::Sinusoidal);
    apt29.add_header(
        "User-Agent",
        "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.17328; Pro)",
    );
    apt29.add_header("Accept", "application/json, text/plain, */*");
    apt29.add_header("Accept-Language", "en-US,en;q=0.9");
    apt29.add_header("X-Client-SKU", "ID_NONE");
    apt29.add_header("X-Client-Ver", "7.0.0.0");

    // --- Emotet ---
    // HTTP with rotating target pool (simulates DGA / fast-flux), Gaussian jitter.
    let mut emotet = TrafficProfile::new("Emotet", "http://127.0.0.1:8080", 60, 25.0, Protocol::Http)
        .with_jitter_algorithm(JitterAlgorithm::Gaussian);
    emotet.add_header(
        "User-Agent",
        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/4.0)",
    );
    emotet.add_header("Content-Type", "application/x-www-form-urlencoded");
    emotet.add_header("Cache-Control", "no-cache");
    emotet.add_target("http://127.0.0.1:8081");
    emotet.add_target("http://127.0.0.1:8082");
    emotet.add_target("http://127.0.0.1:8083");

    // --- FIN7 ---
    // HTTPS beaconing with CDN-masquerading headers to evade inspection,
    // uniform jitter at mid-rate intervals.
    let mut fin7 = TrafficProfile::new("FIN7", "https://127.0.0.1:8443", 30, 10.0, Protocol::Https);
    fin7.add_header(
        "User-Agent",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    );
    fin7.add_header("CF-RAY", "7f3d2a1b4c5e6f78-EWR");
    fin7.add_header("CF-Visitor", r#"{"scheme":"https"}"#);
    fin7.add_header("X-Forwarded-For", "203.0.113.42");
    fin7.add_header("X-Real-IP", "203.0.113.42");
    fin7.add_header("CDN-Loop", "cloudflare");

    // --- SMB Beacon ---
    let smb_profile = TrafficProfile::new("SMB Beacon", "127.0.0.1", 120, 10.0, Protocol::Smb);

    // --- WebSocket Beacon ---
    let ws_profile = TrafficProfile::new("WebSocket Beacon", "ws://127.0.0.1:8080", 15, 15.0, Protocol::WebSocket);

    // --- SMTP Beacon ---
    let smtp_profile = TrafficProfile::new("SMTP Beacon", "127.0.0.1:25", 90, 10.0, Protocol::Smtp);

    vec![
        cobalt, apt28, icmp_profile, lazarus, apt29, emotet, fin7,
        smb_profile, ws_profile, smtp_profile,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uniform_jitter_bounds() {
        let p = TrafficProfile::new("T", "http://t", 10, 20.0, Protocol::Http);
        let min = 10.0 * (1.0 - 20.0 / 100.0);
        let max = 10.0 * (1.0 + 20.0 / 100.0);
        for _ in 0..200 {
            let d = p.calculate_jitter().as_secs_f64();
            assert!(
                d >= min - 1e-9 && d <= max + 1e-9,
                "delay {d} out of bounds [{min}, {max}]"
            );
        }
    }

    #[test]
    fn test_gaussian_jitter_positive() {
        let p = TrafficProfile::new("T", "http://t", 10, 20.0, Protocol::Http)
            .with_jitter_algorithm(JitterAlgorithm::Gaussian);
        for _ in 0..200 {
            let d = p.calculate_jitter().as_secs_f64();
            assert!(d > 0.0, "Gaussian delay {d} not positive");
        }
    }

    #[test]
    fn test_sinusoidal_jitter_nonzero() {
        let p = TrafficProfile::new("T", "http://t", 10, 20.0, Protocol::Http)
            .with_jitter_algorithm(JitterAlgorithm::Sinusoidal);
        for _ in 0..200 {
            let d = p.calculate_jitter().as_secs_f64();
            assert!(d > 0.0, "Sinusoidal delay {d} not positive");
        }
    }

    #[test]
    fn test_target_rotation() {
        let mut p = TrafficProfile::new("T", "http://t1", 10, 10.0, Protocol::Http);
        p.add_target("http://t2");
        p.add_target("http://t3");
        p.add_target("http://t4");
        let mut seen = std::collections::HashSet::new();
        for _ in 0..100 {
            seen.insert(p.get_target().to_string());
        }
        // All three added targets should appear across 100 iterations.
        assert!(seen.contains("http://t2"), "t2 never selected");
        assert!(seen.contains("http://t3"), "t3 never selected");
        assert!(seen.contains("http://t4"), "t4 never selected");
    }

    #[test]
    fn test_single_target_deterministic() {
        let p = TrafficProfile::new("T", "http://primary", 10, 10.0, Protocol::Http);
        for _ in 0..100 {
            assert_eq!(p.get_target(), "http://primary");
        }
    }
}
