// Echos: Red Team traffic emulation and network security research tool in Rust.
// Goals: Emulate network beacons for EDR/NDR testing, implement protocols (HTTP, HTTPS, DNS, ICMP, SMB, WebSocket, SMTP).
// Focus: Jitter algorithms (Uniform, Gaussian, Sinusoidal), header customization to mimic APT signatures.
// Style: Idiomatic Rust, modular, high performance, low memory.
// Educational tool for defensive testing and security auditing.

mod config;
mod logging;
mod network;
mod profiles;
mod runtime;
mod sigma;
mod snort;
mod suricata;

use crate::profiles::{Protocol, TrafficProfile};
use crate::runtime::RuntimeOptions;
use clap::Parser;
use serde::Serialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::time::sleep;

#[derive(Parser)]
#[command(
    name = "echos",
    version = "0.6.0",
    about = "Network beacon emulator for EDR/NDR detection lab testing"
)]
#[command(
    after_help = "EXAMPLES:\n  echos --list\n  echos --profile Cobalt --count 5\n  echos --profile Lazarus --duration 60 --insecure-tls\n  echos --profile Cobalt --target http://10.0.0.1:8080 --count 3\n  echos --config examples/echos.toml --profile \"My Custom Profile\"\n  echos --config examples/echos.yaml --profile \"YAML HTTP/2 Profile\"\n  echos --profile APT29 --json --log-file run.json\n  echos --profile Cobalt --dry-run\n  echos --profile APT41 --mtls-cert client.crt.pem --mtls-key client.key.pem --count 1\n  echos --profile APT41 --schedule \"*/5 * * * *\"\n  echos --sequence \"Cobalt,APT28\" --count 3\n  echos --config examples/echos.toml --sequence recon-chain\n  echos --export-sigma --profile APT28\n  echos --export-suricata --profile Cobalt > cobalt.rules\n  echos --export-snort --profile \"RDP Beacon\""
)]
struct Args {
    #[arg(
        short,
        long,
        default_value = "Cobalt",
        help = "Name of the beacon profile to run"
    )]
    profile: String,

    #[arg(long, help = "List all available profiles and exit")]
    list: bool,

    #[arg(long, help = "Override the profile target at runtime")]
    target: Option<String>,

    #[arg(long, help = "Send exactly N beacon iterations and exit")]
    count: Option<u32>,

    #[arg(long, help = "Run for this many seconds then exit")]
    duration: Option<u64>,

    #[arg(
        long,
        help = "Load profile definitions from a TOML or YAML config file"
    )]
    config: Option<PathBuf>,

    #[arg(
        long,
        help = "Load profile definitions from all .toml, .yaml, and .yml files in a directory"
    )]
    config_dir: Option<PathBuf>,

    #[arg(long, help = "Emit structured JSON logs")]
    json: bool,

    #[arg(
        long,
        help = "Print additional runtime details",
        conflicts_with = "quiet"
    )]
    verbose: bool,

    #[arg(
        long,
        help = "Suppress routine messages; show only warnings/errors/summary",
        conflicts_with = "verbose"
    )]
    quiet: bool,

    #[arg(long, help = "Write logs to a file")]
    log_file: Option<PathBuf>,

    #[arg(
        long,
        default_value = "10",
        help = "Per-connection/request timeout in seconds"
    )]
    timeout: u64,

    #[arg(
        long,
        help = "Accept invalid/self-signed TLS certificates (HTTPS/HTTP2 only)"
    )]
    insecure_tls: bool,

    #[arg(
        long,
        requires = "mtls_key",
        help = "Client certificate PEM file path for mTLS (HTTPS/HTTP2 only; requires --mtls-key)"
    )]
    mtls_cert: Option<PathBuf>,

    #[arg(
        long,
        requires = "mtls_cert",
        help = "Client private key PEM file path for mTLS (HTTPS/HTTP2 only; requires --mtls-cert)"
    )]
    mtls_key: Option<PathBuf>,

    #[arg(
        long,
        help = "Run the profile on a cron schedule. Accepts 5-field (min hour day month weekday) or 6-field (sec min hour day month weekday). Example: \"*/5 * * * *\" = every 5 min"
    )]
    schedule: Option<String>,

    #[arg(long, help = "Print what would run and exit without sending traffic")]
    dry_run: bool,

    #[arg(
        long,
        help = "Run profiles in sequence. Comma-separated names (\"Cobalt,APT28\") or a named sequence from --config"
    )]
    sequence: Option<String>,

    #[arg(
        long,
        help = "Export a Sigma detection rule for the selected profile and exit"
    )]
    export_sigma: bool,

    #[arg(
        long,
        help = "Export a Suricata rule for the selected profile and exit"
    )]
    export_suricata: bool,

    #[arg(long, help = "Export a Snort 3 rule for the selected profile and exit")]
    export_snort: bool,
}

#[derive(Serialize)]
struct RunSummary {
    profile: String,
    protocol: String,
    target: String,
    attempts: u32,
    successes: u32,
    failures: u32,
    failure_rate_pct: f64,
    avg_delay_secs: f64,
    start: String,
    end: String,
    runtime_secs: f64,
    dry_run: bool,
    insecure_tls: bool,
}

fn merge_profiles(base: Vec<TrafficProfile>, incoming: Vec<TrafficProfile>) -> Vec<TrafficProfile> {
    let mut result = base;
    for p in incoming {
        if let Some(existing) = result.iter_mut().find(|e| e.name == p.name) {
            *existing = p;
        } else {
            result.push(p);
        }
    }
    result
}

fn print_list(profiles: &[TrafficProfile]) {
    let builtin_count = profiles.iter().filter(|p| !p.from_config).count();
    let config_count = profiles.iter().filter(|p| p.from_config).count();

    println!(
        "Available Profiles ({} total — {} built-in, {} from config)\n",
        profiles.len(),
        builtin_count,
        config_count
    );

    println!(
        "  {:<22} {:<13} {:<8} {:<9} {:<14} {:<11} {:<10} SOURCE",
        "NAME", "PROTOCOL", "DELAY", "JITTER", "ALGORITHM", "ROTATING", "HEADERS"
    );
    println!("  {}", "─".repeat(93));

    for p in profiles {
        let delay = format!("{}s", p.base_delay.as_secs());
        let jitter = format!("{:.0}%", p.jitter_percent);
        let rotating = if p.targets.is_empty() { "No" } else { "Yes" };
        let headers = p.custom_headers.len().to_string();
        let source = if p.from_config { "Config" } else { "Built-in" };

        println!(
            "  {:<22} {:<13} {:<8} {:<9} {:<14} {:<11} {:<10} {}",
            p.name,
            p.protocol.display_name(),
            delay,
            jitter,
            p.jitter_algorithm.display_name(),
            rotating,
            headers,
            source
        );
    }

    println!("\nTarget: use --target to override any profile's destination at runtime.");
}

fn print_list_json(profiles: &[TrafficProfile]) {
    #[derive(Serialize)]
    struct ProfileInfo<'a> {
        name: &'a str,
        protocol: &'a str,
        delay_secs: u64,
        jitter_percent: f64,
        jitter_algorithm: &'a str,
        rotating: bool,
        header_count: usize,
        source: &'a str,
    }
    let infos: Vec<_> = profiles
        .iter()
        .map(|p| ProfileInfo {
            name: &p.name,
            protocol: p.protocol.display_name(),
            delay_secs: p.base_delay.as_secs(),
            jitter_percent: p.jitter_percent,
            jitter_algorithm: p.jitter_algorithm.display_name(),
            rotating: !p.targets.is_empty(),
            header_count: p.custom_headers.len(),
            source: if p.from_config { "Config" } else { "Built-in" },
        })
        .collect();
    println!(
        "{}",
        serde_json::to_string_pretty(&infos).unwrap_or_default()
    );
}

fn print_summary_human(summary: &RunSummary) {
    let sep = "─".repeat(41);
    println!("{sep}");
    println!("  Run Summary");
    println!("{sep}");
    println!("  {:<18}: {}", "Profile", summary.profile);
    println!("  {:<18}: {}", "Protocol", summary.protocol);
    println!("  {:<18}: {}", "Target", summary.target);
    println!("  {:<18}: {}", "Attempts", summary.attempts);
    println!("  {:<18}: {}", "Successes", summary.successes);
    println!("  {:<18}: {}", "Failures", summary.failures);
    println!("  {:<18}: {:.1}%", "Failure Rate", summary.failure_rate_pct);
    println!("  {:<18}: {:.2}s", "Avg Delay", summary.avg_delay_secs);
    println!("  {:<18}: {}", "Start", summary.start);
    println!("  {:<18}: {}", "End", summary.end);
    println!("  {:<18}: {:.1}s", "Runtime", summary.runtime_secs);
    println!(
        "  {:<18}: {}",
        "Dry Run",
        if summary.dry_run { "Yes" } else { "No" }
    );
    println!(
        "  {:<18}: {}",
        "Insecure TLS",
        if summary.insecure_tls { "Yes" } else { "No" }
    );
    println!("{sep}");
}

fn normalize_schedule_expression(cron_expr: &str) -> String {
    if cron_expr.split_whitespace().count() == 5 {
        format!("0 {cron_expr}")
    } else {
        cron_expr.to_string()
    }
}

/// Dispatch a single beacon to the appropriate network function.
async fn dispatch(
    profile: &TrafficProfile,
    opts: &RuntimeOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    match &profile.protocol {
        Protocol::Http => network::send_http(profile, opts).await,
        Protocol::Https => network::send_https(profile, opts).await,
        Protocol::Http2 => network::send_http2(profile, opts).await,
        Protocol::Dns => network::send_dns(profile, opts).await,
        Protocol::Icmp => network::send_icmp(profile, opts).await,
        Protocol::Smb => network::send_smb(profile, opts).await,
        Protocol::WebSocket => network::send_websocket(profile, opts).await,
        Protocol::Smtp => network::send_smtp(profile, opts).await,
        Protocol::Ftp => network::send_ftp(profile, opts).await,
        Protocol::Ldap => network::send_ldap(profile, opts).await,
        Protocol::Rdp => network::send_rdp(profile, opts).await,
    }
}

/// Run the beacon loop for a single profile.
/// When both `count` and `duration_secs` are `None`, runs indefinitely (single-profile default).
async fn run_profile(
    active_profile: TrafficProfile,
    count: Option<u32>,
    duration_secs: Option<u64>,
    opts: &RuntimeOptions,
) -> RunSummary {
    let effective_target = active_profile.target.clone();

    tracing::info!(
        profile = %active_profile.name,
        protocol = ?active_profile.protocol,
        target = %effective_target,
        "echos started"
    );

    let mut attempts: u32 = 0;
    let mut successes: u32 = 0;
    let mut failures: u32 = 0;
    let mut delays: Vec<f64> = Vec::new();
    let mut consecutive_failures: u32 = 0;
    let start_inst = Instant::now();
    let start_dt = chrono::Local::now();
    const MAX_BACKOFF_SECS: u64 = 300;

    loop {
        if let Some(c) = count {
            if attempts >= c {
                break;
            }
        }

        if let Some(dur) = duration_secs {
            if start_inst.elapsed().as_secs() >= dur {
                break;
            }
        }

        attempts += 1;
        let attempt_num = attempts;

        let beacon_target = active_profile.get_target().to_string();
        let result = dispatch(&active_profile, opts).await;

        match result {
            Ok(_) => {
                successes += 1;
                consecutive_failures = 0;
                tracing::info!(
                    profile = %active_profile.name,
                    protocol = ?active_profile.protocol,
                    target = %beacon_target,
                    attempt = attempt_num,
                    "beacon sent"
                );
            }
            Err(e) => {
                failures += 1;
                consecutive_failures += 1;
                tracing::error!(
                    profile = %active_profile.name,
                    error = %e,
                    attempt = attempt_num,
                    "beacon failed"
                );

                if consecutive_failures >= 3 {
                    let backoff_secs =
                        (2u64.pow(consecutive_failures.min(8))).min(MAX_BACKOFF_SECS);
                    tracing::warn!(backoff_secs, "exponential backoff");
                    sleep(Duration::from_secs(backoff_secs)).await;
                    continue;
                }
            }
        }

        let delay = active_profile.calculate_jitter();
        let delay_secs = delay.as_secs_f64();
        delays.push(delay_secs);
        tracing::debug!(delay_secs, "sleeping");

        // Clamp sleep to remaining duration when a duration limit is set.
        let sleep_dur = if let Some(dur) = duration_secs {
            let elapsed = start_inst.elapsed().as_secs();
            let remaining = dur.saturating_sub(elapsed);
            if remaining == 0 {
                break;
            }
            delay.min(Duration::from_secs(remaining))
        } else {
            delay
        };

        sleep(sleep_dur).await;

        // Re-check duration after sleeping.
        if let Some(dur) = duration_secs {
            if start_inst.elapsed().as_secs() >= dur {
                break;
            }
        }
    }

    let end_dt = chrono::Local::now();
    let total_runtime = start_inst.elapsed();
    let avg_delay = if delays.is_empty() {
        0.0
    } else {
        delays.iter().sum::<f64>() / delays.len() as f64
    };
    let failure_rate = if attempts > 0 {
        failures as f64 / attempts as f64 * 100.0
    } else {
        0.0
    };

    RunSummary {
        profile: active_profile.name.clone(),
        protocol: active_profile.protocol.display_name().to_string(),
        target: effective_target,
        attempts,
        successes,
        failures,
        failure_rate_pct: failure_rate,
        avg_delay_secs: avg_delay,
        start: start_dt.format("%Y-%m-%d %H:%M:%S").to_string(),
        end: end_dt.format("%Y-%m-%d %H:%M:%S").to_string(),
        runtime_secs: total_runtime.as_secs_f64(),
        dry_run: opts.dry_run,
        insecure_tls: opts.insecure_tls,
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let _log_guard = logging::init(
        args.verbose,
        args.quiet,
        args.json,
        args.log_file.as_deref(),
    );

    let opts = RuntimeOptions {
        insecure_tls: args.insecure_tls,
        timeout_secs: args.timeout,
        dry_run: args.dry_run,
        json_output: args.json,
        target_override: args.target.clone(),
        mtls_cert: args.mtls_cert.clone(),
        mtls_key: args.mtls_key.clone(),
    };

    // Load built-in profiles then merge external ones (later wins on name collision).
    let mut all_profiles = profiles::get_profiles();
    let mut all_sequences: HashMap<String, Vec<String>> = HashMap::new();

    if let Some(ref path) = args.config {
        match config::load_from_file(path) {
            Ok(loaded) => {
                all_profiles = merge_profiles(all_profiles, loaded.profiles);
                all_sequences.extend(loaded.sequences);
            }
            Err(e) => {
                eprintln!("[X] Failed to load config file {:?}: {}", path, e);
                std::process::exit(1);
            }
        }
    }

    if let Some(ref dir) = args.config_dir {
        match config::load_from_dir(dir) {
            Ok(loaded) => {
                all_profiles = merge_profiles(all_profiles, loaded.profiles);
                all_sequences.extend(loaded.sequences);
            }
            Err(e) => {
                eprintln!("[X] Failed to load config dir {:?}: {}", dir, e);
                std::process::exit(1);
            }
        }
    }

    if args.list {
        if args.json {
            print_list_json(&all_profiles);
        } else {
            print_list(&all_profiles);
        }
        return Ok(());
    }

    // Export a Sigma rule and exit.
    if args.export_sigma {
        let profile = match all_profiles.iter().find(|p| p.name == args.profile) {
            Some(p) => p,
            None => {
                eprintln!("[X] Profile '{}' not found for Sigma export.", args.profile);
                std::process::exit(1);
            }
        };
        println!("{}", sigma::generate(profile));
        return Ok(());
    }

    // Export a Suricata rule and exit.
    if args.export_suricata {
        let idx = all_profiles
            .iter()
            .position(|p| p.name == args.profile)
            .unwrap_or(0);
        let profile = match all_profiles.iter().find(|p| p.name == args.profile) {
            Some(p) => p,
            None => {
                eprintln!(
                    "[X] Profile '{}' not found for Suricata export.",
                    args.profile
                );
                std::process::exit(1);
            }
        };
        println!("{}", suricata::generate(profile, idx));
        return Ok(());
    }

    // Export a Snort 3 rule and exit.
    if args.export_snort {
        let idx = all_profiles
            .iter()
            .position(|p| p.name == args.profile)
            .unwrap_or(0);
        let profile = match all_profiles.iter().find(|p| p.name == args.profile) {
            Some(p) => p,
            None => {
                eprintln!("[X] Profile '{}' not found for Snort export.", args.profile);
                std::process::exit(1);
            }
        };
        println!("{}", snort::generate(profile, idx));
        return Ok(());
    }

    // Sequence mode: run multiple profiles in order.
    if let Some(ref seq_arg) = args.sequence {
        let profile_names: Vec<String> = if seq_arg.contains(',') {
            seq_arg.split(',').map(|s| s.trim().to_string()).collect()
        } else {
            match all_sequences.get(seq_arg.as_str()) {
                Some(names) => names.clone(),
                None => {
                    eprintln!("[X] Sequence '{}' not found in config.", seq_arg);
                    std::process::exit(1);
                }
            }
        };

        let global_start = Instant::now();

        for name in &profile_names {
            // Enforce global duration limit.
            if let Some(total_dur) = args.duration {
                let elapsed = global_start.elapsed().as_secs();
                if elapsed >= total_dur {
                    break;
                }
            }

            let base_profile = match all_profiles.iter().find(|p| p.name == *name) {
                Some(p) => p.clone(),
                None => {
                    eprintln!("[X] Profile '{}' not found in sequence, skipping.", name);
                    continue;
                }
            };

            let mut active_profile = base_profile;
            if let Some(ref target) = opts.target_override {
                active_profile.target = target.clone();
                active_profile.targets.clear();
            }

            if opts.dry_run {
                println!(
                    "[DRY RUN] Would run profile \"{}\" ({} → {})",
                    active_profile.name,
                    active_profile.protocol.display_name(),
                    active_profile.target
                );
                continue;
            }

            let per_profile_count = args.count.or(Some(1));
            let per_profile_duration = args.duration.map(|total_dur| {
                let elapsed = global_start.elapsed().as_secs();
                total_dur.saturating_sub(elapsed)
            });

            if per_profile_duration == Some(0) {
                break;
            }

            let summary = run_profile(
                active_profile,
                per_profile_count,
                per_profile_duration,
                &opts,
            )
            .await;

            if opts.json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&summary).unwrap_or_default()
                );
            } else {
                print_summary_human(&summary);
            }
        }

        return Ok(());
    }

    // Single-profile mode.
    let profile = match all_profiles.iter().find(|p| p.name == args.profile) {
        Some(p) => p,
        None => match all_profiles.first() {
            Some(p) => {
                tracing::warn!(
                    requested = %args.profile,
                    fallback = %p.name,
                    "profile not found, falling back"
                );
                p
            }
            None => {
                eprintln!("[X] No profiles available. Exiting.");
                std::process::exit(1);
            }
        },
    };

    let mut active_profile = profile.clone();
    if let Some(ref target) = opts.target_override {
        active_profile.target = target.clone();
        active_profile.targets.clear();
    }

    let effective_target = active_profile.target.clone();

    if opts.dry_run {
        println!(
            "[DRY RUN] Would run profile \"{}\" ({} → {})",
            active_profile.name,
            active_profile.protocol.display_name(),
            effective_target
        );
        println!(
            "  Jitter       : {:.0}% {}",
            active_profile.jitter_percent,
            active_profile.jitter_algorithm.display_name()
        );
        println!("  Timeout      : {}s", opts.timeout_secs);
        println!(
            "  Insecure TLS : {}",
            if opts.insecure_tls { "Yes" } else { "No" }
        );
        println!(
            "  Count limit  : {}",
            args.count.map_or("none".to_string(), |c| c.to_string())
        );
        println!(
            "  Duration     : {}",
            args.duration
                .map_or("none".to_string(), |d| format!("{}s", d))
        );
        return Ok(());
    }

    // Schedule mode: repeat profile execution on a cron schedule.
    if let Some(ref cron_expr) = args.schedule {
        use cron::Schedule;
        use std::str::FromStr;

        let normalized = normalize_schedule_expression(cron_expr);
        let schedule = Schedule::from_str(&normalized)
            .map_err(|e| format!("Invalid cron expression '{}': {}", cron_expr, e))?;

        loop {
            let next = match schedule.upcoming(chrono::Local).next() {
                Some(t) => t,
                None => {
                    tracing::warn!("Cron schedule has no future occurrences, exiting");
                    break;
                }
            };
            let now = chrono::Local::now();
            let wait = (next - now).to_std().unwrap_or_default();
            tracing::info!(
                next = %next.format("%Y-%m-%d %H:%M:%S"),
                wait_secs = wait.as_secs(),
                "next scheduled run"
            );
            sleep(wait).await;

            let summary =
                run_profile(active_profile.clone(), args.count, args.duration, &opts).await;
            if opts.json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&summary).unwrap_or_default()
                );
            } else {
                print_summary_human(&summary);
            }
        }
        return Ok(());
    }

    let summary = run_profile(active_profile, args.count, args.duration, &opts).await;

    if opts.json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        print_summary_human(&summary);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::normalize_schedule_expression;

    #[test]
    fn test_normalize_schedule_expression_adds_seconds_for_five_fields() {
        assert_eq!(
            normalize_schedule_expression("*/5 * * * *"),
            "0 */5 * * * *"
        );
    }

    #[test]
    fn test_normalize_schedule_expression_preserves_six_fields() {
        assert_eq!(
            normalize_schedule_expression("30 */5 * * * *"),
            "30 */5 * * * *"
        );
    }
}
