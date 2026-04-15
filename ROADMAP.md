# Roadmap

This document tracks planned improvements for Echos. Items are not ordered by priority. Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

---

## In Progress / Near-term

### More profiles
Additional threat actor and tool emulation profiles:

- Sandworm — slow ICMP with time-of-day variation
- Turla — HTTP with custom encoding headers
- Carbanak — HTTPS with banking-industry UA strings
- Cobalt Strike DNS Beacon — subdomain-based lookup pattern
- Generic meterpreter-style HTTP POST beacon

### Additional protocols

- **FTP** — passive mode probe for detecting outbound FTP from workstations
- **LDAP** — bind request probe for detecting unauthorized LDAP queries
- **RDP** — TCP connect probe for lateral movement detection testing

### Profile sequencing

Run multiple profiles in sequence or in parallel from a single config file, to simulate multi-stage intrusion traffic chains.

---

## Medium-term

### Detection rule export

Generate Sigma, Suricata, or Snort rules directly from profile definitions. Each profile encodes the exact headers and timing that a detection rule needs to match.

### HTTP/2 support

The current HTTPS implementation uses HTTP/1.1. HTTP/2 changes TLS fingerprint characteristics relevant to some JA3/JA4 detections.

### mTLS support

Mutual TLS for simulating C2 frameworks that authenticate both ends of the connection.

### Schedule-based execution

Cron-style scheduling to run profiles at specific times or intervals, useful for long-running lab tests that need to repeat over hours or days.

### YAML config support

Optional YAML alternative to TOML for users who prefer it. TOML remains the primary and default format.

---

## Longer-term / Research

### PCAP output

Write beacon traffic to a `.pcap` file instead of (or in addition to) sending live traffic. Enables offline testing of detection rules without a live listener.

### Prometheus metrics endpoint

Expose a `/metrics` endpoint during a run so you can observe beacon success rates and timing distributions from your monitoring stack.

### Docker image

Official Docker image for running Echos in containerized lab environments without installing Rust.

### Detection integration testing

Native integration with detection platforms — push a profile run and automatically check whether an expected alert was generated, returning pass/fail. Candidates: Elastic SIEM, Splunk, Chronicle.

### Web UI

A simple local web interface for configuring and launching profiles without using the CLI. Primarily aimed at defenders who are not comfortable with command-line tools.

---

## Completed (v0.2.0)

- ✅ `--list` — formatted profile table with source, algorithm, and target info
- ✅ `--target` — runtime target override without recompiling
- ✅ `--count` and `--duration` — bounded execution with early-stop when either limit is hit
- ✅ `--dry-run` — preview mode, no traffic sent
- ✅ `--json` — structured JSON logs and JSON summary output
- ✅ `--verbose` / `--quiet` — log verbosity control
- ✅ `--log-file` — write logs to disk
- ✅ `--insecure-tls` — explicit opt-in for self-signed cert acceptance (safe default: validate)
- ✅ `--config` / `--config-dir` — external TOML profile loading
- ✅ Structured run summary (human and JSON)
- ✅ Exponential backoff on consecutive failures
- ✅ Gaussian and sinusoidal jitter algorithms
- ✅ Unit tests for jitter bounds, rotation, and target override
- ✅ GitHub Actions CI (fmt, clippy, test, multi-platform matrix)
- ✅ GitHub Actions release workflow (Linux, Windows, macOS binaries on tag push)
