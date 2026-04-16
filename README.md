# Echos

[![CI](https://github.com/xdrew87/Echos/actions/workflows/ci.yml/badge.svg)](https://github.com/xdrew87/Echos/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-0.4.0-blue)](https://github.com/xdrew87/Echos/releases)
[![Language](https://img.shields.io/badge/language-Rust-orange?logo=rust)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Platforms](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)](https://github.com/xdrew87/Echos/releases)

**Modular network beacon emulator for EDR/NDR detection lab validation — written in Rust.**

Echos replays realistic C2-style beacon traffic so defenders can verify that their detection stack — EDR, NDR, IDS/IPS, SIEM — fires the right alerts under controlled, repeatable conditions. It is not a post-exploitation framework. It sends no payloads, executes no code on remote systems, and requires no implant. It is purely a traffic generator designed for authorized lab use.

---

## Why Echos?

Detection engineering requires repeatable, controllable stimulus. Running a real implant in a lab introduces risk, licensing complexity, and noise. Echos gives you a single binary that generates accurately structured beacon traffic — correct headers, correct timing distributions, correct protocol shapes — without any of that baggage.

Use it to answer questions like:

- Does my NDR alert on Cobalt Strike-style HTTP headers hitting an internal listener?
- Does my SIEM correctly correlate 10 DNS beacon queries from the same host in under 5 minutes?
- Does my detection rule fire on SMTP EHLO probes from workstation endpoints?
- Does exponential backoff behavior in a failing beacon evade my anomaly model?

---

## Features

- **7 protocols** — HTTP, HTTPS, DNS, ICMP, SMB, WebSocket, SMTP
- **10 built-in profiles** — Cobalt Strike, APT28, Lazarus, APT29, Emotet, FIN7, ICMP, SMB, WebSocket, SMTP
- **3 jitter algorithms** — Uniform, Gaussian (Box-Muller), Sinusoidal (business-hours modulation)
- **Bounded execution** — `--count N` or `--duration SECS`, stop on whichever hits first
- **Runtime target override** — `--target` points any profile at your listener without recompiling
- **External TOML config** — define custom profiles without touching source code
- **Profile sequencing** — `--sequence "Cobalt,APT28"` or named sequences from config
- **Sigma rule export** — `--export-sigma --profile <name>` prints a ready-to-tune Sigma YAML rule
- **Structured logging** — human-readable or JSON, with optional file output
- **Exponential backoff** — kicks in after 3 consecutive beacon failures, caps at 300 s
- **Rotating target pools** — simulate DGA/fast-flux by specifying multiple targets per profile
- **Safe HTTPS defaults** — certificate validation on by default; `--insecure-tls` only when explicitly passed
- **Dry-run mode** — preview exactly what would happen without sending any traffic

---

## Quick Start

```bash
# Build
git clone https://github.com/xdrew87/echos
cd echos
cargo build --release

# List all profiles
./target/release/echos --list

# Run a single beacon iteration
./target/release/echos --profile Cobalt --count 1 --target http://127.0.0.1:8080

# Preview without sending traffic
./target/release/echos --profile APT29 --dry-run
```

Requires Rust 1.70+.

---

## Install from source

## Install from source

```bash
git clone https://github.com/xdrew87/echos
cd echos
cargo build --release
./target/release/echos --list
```

Requires Rust 1.70+.

---

## Example Output

### `--list`

```
Available Profiles (18 total — 18 built-in, 0 from config)

  NAME                   PROTOCOL      DELAY    JITTER    ALGORITHM       ROTATING     HEADERS    SOURCE
  ─────────────────────────────────────────────────────────────────────────────────────────────────────
  Cobalt                 HTTP          10s      20%       Uniform         No           5          Built-in
  APT28                  DNS           30s      10%       Uniform         No           0          Built-in
  ICMP Beacon            ICMP          60s      5%        Uniform         No           0          Built-in
  Lazarus                HTTPS         300s     15%       Gaussian        No           5          Built-in
  APT29                  HTTPS         600s     10%       Sinusoidal      No           5          Built-in
  Emotet                 HTTP          60s      25%       Gaussian        Yes          3          Built-in
  FIN7                   HTTPS         30s      10%       Uniform         No           6          Built-in
  SMB Beacon             SMB           120s     10%       Uniform         No           0          Built-in
  WebSocket Beacon       WebSocket     15s      15%       Uniform         No           0          Built-in
  SMTP Beacon            SMTP          90s      10%       Uniform         No           0          Built-in
  Sandworm               ICMP          180s     20%       Sinusoidal      No           0          Built-in
  Turla                  HTTP          45s      15%       Gaussian        No           6          Built-in
  Carbanak               HTTPS         120s     10%       Gaussian        No           6          Built-in
  CS DNS Beacon          DNS           20s      30%       Uniform         Yes          0          Built-in
  Meterpreter            HTTP          5s       25%       Gaussian        No           5          Built-in
  FTP Beacon             FTP           90s      10%       Uniform         No           0          Built-in
  LDAP Beacon            LDAP          60s      10%       Uniform         No           0          Built-in
  RDP Beacon             RDP           30s      10%       Uniform         No           0          Built-in

Target: use --target to override any profile's destination at runtime.
```

### `--dry-run`

```
[DRY RUN] Would run profile "Cobalt" (HTTP → http://127.0.0.1:8080)
  Jitter       : 20% Uniform
  Timeout      : 10s
  Insecure TLS : No
  Count limit  : none
  Duration     : none
```

### Running a profile (human log format)

```
2026-04-15T04:02:11Z  INFO echos started profile=Cobalt protocol=Http target=http://10.0.0.1:8080
2026-04-15T04:02:11Z  INFO beacon sent profile=Cobalt protocol=Http target=http://10.0.0.1:8080 attempt=1
2026-04-15T04:02:19Z  INFO beacon sent profile=Cobalt protocol=Http target=http://10.0.0.1:8080 attempt=2
2026-04-15T04:02:30Z  INFO beacon sent profile=Cobalt protocol=Http target=http://10.0.0.1:8080 attempt=3
─────────────────────────────────────
  Run Summary
─────────────────────────────────────
  Profile           : Cobalt
  Protocol          : HTTP
  Target            : http://10.0.0.1:8080
  Attempts          : 3
  Successes         : 3
  Failures          : 0
  Failure Rate      : 0.0%
  Avg Delay         : 9.84s
  Start             : 2026-04-15 04:02:11
  End               : 2026-04-15 04:02:41
  Runtime           : 30.2s
  Dry Run           : No
  Insecure TLS      : No
─────────────────────────────────────
```

### JSON log output (`--json`)

```json
{
  "timestamp": "2026-04-15T04:02:11.112Z",
  "level": "INFO",
  "fields": {
    "message": "beacon sent",
    "profile": "Cobalt",
    "protocol": "Http",
    "target": "http://10.0.0.1:8080",
    "attempt": 1
  },
  "target": "echos"
}
```

JSON summary (end of run):

```json
{
  "profile": "Cobalt",
  "protocol": "HTTP",
  "target": "http://10.0.0.1:8080",
  "attempts": 3,
  "successes": 3,
  "failures": 0,
  "failure_rate_pct": 0.0,
  "avg_delay_secs": 9.84,
  "start": "2026-04-15 04:02:11",
  "end": "2026-04-15 04:02:41",
  "runtime_secs": 30.2,
  "dry_run": false,
  "insecure_tls": false
}
```

---

## CLI Reference

| Flag | Default | Description |
|------|---------|-------------|
| `-p, --profile <NAME>` | `Cobalt` | Beacon profile to use |
| `--list` | — | Print available profiles and exit |
| `--target <URL>` | — | Override the profile destination at runtime |
| `--count <N>` | — | Send exactly N beacon iterations then exit |
| `--duration <SECS>` | — | Run for this many seconds then exit |
| `--config <FILE>` | — | Load additional profiles from a TOML file |
| `--config-dir <DIR>` | — | Load profiles from all `.toml` files in a directory |
| `--sequence <NAMES>` | — | Run profiles in sequence: `"Cobalt,APT28"` or a named sequence from config |
| `--export-sigma` | — | Print a Sigma YAML detection rule for the selected profile and exit |
| `--json` | — | Emit structured JSON logs and output summary as JSON |
| `--verbose` | — | Show debug-level details |
| `--quiet` | — | Show only warnings, errors, and the final summary |
| `--log-file <FILE>` | — | Write logs to a file (always JSON format) |
| `--timeout <SECS>` | `10` | Per-connection/request timeout |
| `--insecure-tls` | — | Accept invalid/self-signed TLS certificates (HTTPS only) |
| `--dry-run` | — | Print what would happen and exit without sending traffic |

When both `--count` and `--duration` are given, echos stops when **either** limit is first reached.

---

## Profile Sequencing

Run multiple profiles back-to-back in a defined order using `--sequence`.

**Inline (comma-separated):**
```bash
echos --sequence "Cobalt,APT28" --count 3
```
Each profile fires 3 beacons in order: Cobalt first, then APT28.

**Named sequence from config:**
```toml
# examples/echos.toml
[[sequences]]
name     = "recon-chain"
profiles = ["APT28", "LDAP Beacon", "RDP Beacon", "SMB Beacon"]
```
```bash
echos --config examples/echos.toml --sequence recon-chain
```

**With a global time budget:**
```bash
echos --config examples/echos.toml --sequence recon-chain --duration 120
```
The 120 s budget is shared across all profiles in the sequence; execution stops when time runs out.

In sequence mode, `--count` sets the per-profile iteration count (default: 1 per profile).

---

## Sigma Rule Export

Generate an experimental Sigma YAML detection rule from any profile definition:

```bash
echos --export-sigma --profile APT28
```

Example output:
```yaml
title: Echos - APT28
id: echos-apt28
status: experimental
description: "Detects beacon traffic matching the Echos 'APT28' profile (DNS protocol)."
author: Echos (generated)
date: 2025-01-15
references:
  - https://github.com/xdrew87/Echos
tags:
  - attack.command_and_control
  - attack.t1071.004
logsource:
  category: dns
detection:
  selection:
    QueryName|contains: "example.com"
    QueryType: 'A'
  condition: selection
fields:
  - QueryName
  - QueryType
  - record_type
  - answers
falsepositives:
  - Legitimate traffic using the same user-agent or ports
  - Security scanning tools
level: medium
```

Rules are experimental — review and tune before deploying in production. Use with `--config` to export rules for custom profiles too:
```bash
echos --config examples/echos.toml --export-sigma --profile "My Custom Profile"
```

---

## Use Cases

### Red team lab testing

Validate that your C2 listener traffic pattern is indistinguishable from the real threat actor profile before running an engagement:

```bash
# Confirm Cobalt Strike HTTP profile reaches your team server
echos --profile Cobalt --count 5 --target http://teamserver.lab.internal:8080

# Test APT29-style slow HTTPS beaconing over 10 minutes
echos --profile APT29 --duration 600 --insecure-tls --target https://192.168.10.5:443
```

### Detection engineering

Trigger specific detection rules on demand, repeatably:

```bash
# Fire Cobalt Strike HTTP User-Agent signature once
echos --profile Cobalt --count 1 --target http://sensor.lab.internal:8080

# Generate 10 DNS beacon queries for correlation testing
echos --profile APT28 --count 10

# Trigger SMB negotiate probe detection
echos --profile "SMB Beacon" --count 3 --target 192.168.1.50
```

### SIEM and pipeline validation

Use structured JSON output to feed results into your validation pipeline:

```bash
# Machine-readable output for CI/CD detection validation
echos --profile Cobalt --count 10 --json --quiet 2>/dev/null

# Write a timestamped run log to disk
echos --profile FIN7 --count 20 --json --log-file /tmp/fin7-run.json

# Validate multiple profiles in a shell loop
for profile in Cobalt APT28 Lazarus; do
  echos --profile "$profile" --count 1 --json --quiet
done
```

---

## Safety and Intended Use

Echos is designed **exclusively for authorized security testing and detection validation** in environments you own or have explicit written permission to test.

- It sends no payloads and executes no code on remote systems
- All traffic is directed at targets you specify via `--target`
- Default targets point to `127.0.0.1` — no external traffic by default
- TLS certificates are validated by default
- Generating unsolicited beacon traffic on networks you do not control may violate computer-fraud laws

See [SECURITY.md](SECURITY.md) for the full responsible-use policy.

---

## Lab Guide

See [docs/lab-guide.md](docs/lab-guide.md) for a step-by-step walkthrough of setting up a detection validation lab with Echos.

---

## Roadmap

See [ROADMAP.md](ROADMAP.md) for planned features and future direction.

---



```bash
# List all available profiles
echos --list

# Dry-run to preview behaviour without sending traffic
echos --profile Cobalt --dry-run

# Override target at runtime
echos --profile Cobalt --target http://10.0.0.1:8080 --count 5

# Run Lazarus profile for 60 s with self-signed cert support
echos --profile Lazarus --duration 60 --insecure-tls

# Emit structured JSON output and save logs to file
echos --profile APT29 --count 3 --json --log-file run.json

# Load a custom profile from TOML, run quietly
echos --config examples/echos.toml --profile "My Custom Profile" --count 10 --quiet

# Load all TOML files from a directory
echos --config-dir ./profiles.d --list
```

---

## HTTPS and TLS Certificate Validation

By default, echos **validates TLS certificates normally**. This is the safe, secure default.

Pass `--insecure-tls` only when your lab server uses a self-signed certificate and you understand the implications:

```bash
echos --profile Lazarus --insecure-tls --count 1
```

This flag affects only HTTPS profiles. HTTP, DNS, ICMP, SMB, WebSocket, and SMTP profiles are unaffected.

---

## Config File Format

Define additional profiles in TOML. Load them at runtime with `--config` or `--config-dir`.

```toml
# examples/echos.toml

[[profiles]]
name             = "My Custom Profile"
protocol         = "https"
target           = "https://192.168.1.100:8443"
base_delay_secs  = 45
jitter_percent   = 15.0
jitter_algorithm = "gaussian"   # uniform | gaussian | sinusoidal (default: uniform)

[profiles.headers]
User-Agent = "Mozilla/5.0 (compatible; LabScanner/1.0)"
X-Lab-ID   = "detection-lab-01"
```

**Required fields:** `name`, `protocol`, `target`, `base_delay_secs`, `jitter_percent`
**Optional fields:** `targets` (rotating list), `headers`, `jitter_algorithm`

External profiles with the same name as a built-in profile silently override the built-in.

---

## Available Profiles

| Profile | Protocol | Delay | Jitter | Algorithm | Notes |
|---------|----------|-------|--------|-----------|-------|
| Cobalt | HTTP | 10 s | 20% | Uniform | Cobalt Strike-style headers |
| APT28 | DNS | 30 s | 10% | Uniform | DNS lookup beacon |
| ICMP Beacon | ICMP | 60 s | 5% | Uniform | Ping-based probe |
| Lazarus | HTTPS | 300 s | 15% | Gaussian | Korean-language UA, slow C2 |
| APT29 | HTTPS | 600 s | 10% | Sinusoidal | Office 365 UA, business-hours blend |
| Emotet | HTTP | 60 s | 25% | Gaussian | Rotating 4-target pool, DGA simulation |
| FIN7 | HTTPS | 30 s | 10% | Uniform | CDN-masquerading headers |
| SMB Beacon | SMB | 120 s | 10% | Uniform | SMB negotiate probe on port 445 |
| WebSocket Beacon | WebSocket | 15 s | 15% | Uniform | Single text frame over WS |
| SMTP Beacon | SMTP | 90 s | 10% | Uniform | EHLO probe without sending mail |
| Sandworm | ICMP | 180 s | 20% | Sinusoidal | GRU-style slow ICMP, time-of-day jitter |
| Turla | HTTP | 45 s | 15% | Gaussian | FSB-style obfuscation headers |
| Carbanak | HTTPS | 120 s | 10% | Gaussian | Banking-industry UA strings |
| CS DNS Beacon | DNS | 20 s | 30% | Uniform | Cobalt Strike DNS, rotating subdomains |
| Meterpreter | HTTP | 5 s | 25% | Gaussian | Meterpreter reverse_http POST pattern |
| FTP Beacon | FTP | 90 s | 10% | Uniform | Outbound FTP banner probe, port 21 |
| LDAP Beacon | LDAP | 60 s | 10% | Uniform | Anonymous LDAP bind probe, port 389 |
| RDP Beacon | RDP | 30 s | 10% | Uniform | RDP connection request probe, port 3389 |

---

## Jitter Algorithms

| Algorithm | Behaviour |
|-----------|-----------|
| `uniform` | Random delay uniformly distributed in `[base × (1−jitter%), base × (1+jitter%)]` |
| `gaussian` | Box-Muller normal distribution centred at `base`, σ = `jitter_amount`; clamped to > 0.1 s |
| `sinusoidal` | Time-of-day modulation: 3× base at 01:00, 1× base at 13:00; mimics business-hours blending |

---

## Download Pre-built Binaries

Pre-built binaries for Linux, Windows, and macOS are published on the [Releases page](https://github.com/xdrew87/echos/releases) for every tagged version.

| Platform | File |
|----------|------|
| Linux x86-64 | `echos-linux-x86_64` |
| Windows x86-64 | `echos-windows-x86_64.exe` |
| macOS x86-64 | `echos-macos-x86_64` |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add profiles, run tests, and open pull requests.

---

## Disclaimer

Echos is intended **exclusively for authorized security testing and defensive research** in environments you own or have explicit written permission to test. Generating unsolicited beacon traffic on networks you do not control may violate computer-fraud laws. The authors assume no liability for misuse.
