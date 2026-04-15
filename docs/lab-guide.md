# Echos Lab Guide

This guide walks through setting up a detection validation lab using Echos, from initial build to verifying that your detection rules fire correctly.

---

## Overview

The basic workflow is:

1. Stand up a listener on a lab host (your "C2 server" stand-in)
2. Run Echos from a separate lab host (your "victim" stand-in)
3. Observe whether your detection stack alerts on the traffic
4. Adjust detection rules and repeat

Everything stays within your lab network. No external traffic is required.

---

## Prerequisites

- Rust 1.70+ installed on the Echos host
- A packet capture or detection tool (Zeek, Suricata, Snort, your EDR/NDR, etc.) monitoring the lab segment
- A listener or simple HTTP server on the target host (e.g. `python3 -m http.server 8080`)

---

## Step 1 — Build Echos

```bash
git clone https://github.com/xdrew87/echos
cd echos
cargo build --release
```

The binary is at `target/release/echos` (or `target\release\echos.exe` on Windows).

---

## Step 2 — List Available Profiles

```bash
./target/release/echos --list
```

Pick a profile that matches the traffic pattern you want to simulate. Each profile emulates a specific threat actor's beaconing style — headers, timing, jitter, and protocol.

---

## Step 3 — Preview Without Sending Traffic

Before running live, confirm the configuration looks correct:

```bash
./target/release/echos --profile Cobalt --target http://192.168.10.50:8080 --count 5 --dry-run
```

Output:

```
[DRY RUN] Would run profile "Cobalt" (HTTP → http://192.168.10.50:8080)
  Jitter       : 20% Uniform
  Timeout      : 10s
  Insecure TLS : No
  Count limit  : 5
  Duration     : none
```

---

## Step 4 — Run a Profile Against Your Listener

Start a listener on your target host:

```bash
# Simple HTTP listener (Python)
python3 -m http.server 8080
```

Run Echos from the source host:

```bash
./target/release/echos --profile Cobalt --target http://192.168.10.50:8080 --count 5
```

Check your detection stack for alerts matching Cobalt Strike HTTP patterns (User-Agent, Accept headers, etc.).

---

## Step 5 — Validate a DNS Beacon

The APT28 profile generates DNS lookup traffic:

```bash
./target/release/echos --profile APT28 --count 10
```

The default target is `example.com`. Your DNS monitoring (Zeek `dns.log`, Suricata, etc.) should log repeated A-record lookups from the same host within a short window. This tests your DNS beacon frequency detection.

---

## Step 6 — Test HTTPS With Self-Signed Certs

Many lab environments use self-signed certificates. Use `--insecure-tls` to allow this:

```bash
./target/release/echos --profile Lazarus --target https://192.168.10.50:8443 --count 3 --insecure-tls
```

Without `--insecure-tls`, Echos validates certificates normally. Use this to confirm your detection logic triggers on the correct TLS fingerprint regardless of cert validity.

---

## Step 7 — Capture Structured Output for Your Pipeline

Use `--json` to emit machine-readable output suitable for feeding into a validation script or CI pipeline:

```bash
./target/release/echos --profile Cobalt --count 5 --json --quiet --target http://192.168.10.50:8080
```

The final summary prints as a single JSON object:

```json
{
  "profile": "Cobalt",
  "protocol": "HTTP",
  "target": "http://192.168.10.50:8080",
  "attempts": 5,
  "successes": 5,
  "failures": 0,
  "failure_rate_pct": 0.0,
  "avg_delay_secs": 9.84,
  "start": "2026-04-15 04:02:11",
  "end": "2026-04-15 04:02:41",
  "runtime_secs": 60.1,
  "dry_run": false,
  "insecure_tls": false
}
```

Pipe this to `jq` or parse it in your automation scripts.

---

## Step 8 — Load a Custom Profile

Define your own profile in a TOML file to match traffic you need to simulate:

```toml
# profiles/custom.toml

[[profiles]]
name             = "Lab HTTPS Beacon"
protocol         = "https"
target           = "https://192.168.10.50:8443"
base_delay_secs  = 30
jitter_percent   = 10.0
jitter_algorithm = "gaussian"

[profiles.headers]
User-Agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
X-Lab-Run  = "detection-test-01"
```

Load it at runtime:

```bash
./target/release/echos --config profiles/custom.toml --profile "Lab HTTPS Beacon" --count 5 --insecure-tls
```

---

## Typical Detection Validation Workflow

```
┌─────────────────────────────────────────────────────┐
│                                                     │
│   1. Write or update detection rule                 │
│   2. Run Echos --dry-run to confirm setup           │
│   3. Run Echos with --count N                       │
│   4. Check detection stack for expected alert       │
│   5. If alert fires → rule is validated ✓           │
│   6. If no alert → tune rule, repeat                │
│                                                     │
└─────────────────────────────────────────────────────┘
```

---

## Tips

- Start with `--count 1` to confirm connectivity before running longer tests
- Use `--verbose` to see delay and timing details during a run
- Use `--log-file run.json` to archive every run for audit trails
- The Emotet profile rotates across 4 targets by default — useful for testing target-rotation detection logic
- The APT29 profile uses sinusoidal jitter tied to time-of-day; delays will be longer at night and shorter during business hours
- Use `--timeout` to shorten per-connection timeouts in environments where listeners are not always up

---

## Notes on Authorized Use

Run Echos only on networks and systems you own or have explicit written permission to test. The default targets (`127.0.0.1`, `example.com`) are intentionally inert. Always point `--target` at infrastructure you control.
