use std::collections::HashMap;
use std::time::Duration;
use rand::Rng;

#[derive(Debug, Clone)]
pub enum Protocol {
    Http,
    Dns,
    Icmp,
}

#[derive(Debug, Clone)]
pub struct TrafficProfile {
    pub name: String,
    pub target: String, // URL for HTTP, domain/IP for others
    pub custom_headers: HashMap<String, String>,
    pub base_delay: Duration,
    pub jitter_percent: f64,
    pub protocol: Protocol,
}

impl TrafficProfile {
    pub fn new(name: &str, target: &str, base_delay_secs: u64, jitter_percent: f64, protocol: Protocol) -> Self {
        Self {
            name: name.to_string(),
            target: target.to_string(),
            custom_headers: HashMap::new(),
            base_delay: Duration::from_secs(base_delay_secs),
            jitter_percent,
            protocol,
        }
    }

    pub fn add_header(&mut self, key: &str, value: &str) {
        self.custom_headers.insert(key.to_string(), value.to_string());
    }

    pub fn calculate_jitter(&self) -> Duration {
        let base_secs = self.base_delay.as_secs_f64();
        let jitter_amount = base_secs * (self.jitter_percent / 100.0);
        let min_delay = base_secs - jitter_amount;
        let max_delay = base_secs + jitter_amount;
        let mut rng = rand::thread_rng();
        let random_delay = rng.gen_range(min_delay..=max_delay);
        Duration::from_secs_f64(random_delay)
    }
}

pub fn get_profiles() -> Vec<TrafficProfile> {
    let mut cobalt = TrafficProfile::new("Cobalt", "http://127.0.0.1:8080", 10, 20.0, Protocol::Http);
    cobalt.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
    cobalt.add_header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
    cobalt.add_header("Accept-Language", "en-US,en;q=0.5");
    cobalt.add_header("Accept-Encoding", "gzip, deflate");
    cobalt.add_header("Connection", "keep-alive");

    let apt28 = TrafficProfile::new("APT28", "example.com", 30, 10.0, Protocol::Dns);

    let icmp_profile = TrafficProfile::new("ICMP Beacon", "8.8.8.8", 60, 5.0, Protocol::Icmp);

    vec![cobalt, apt28, icmp_profile]
}
