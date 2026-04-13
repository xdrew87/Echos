# Security Policy

## ⚠️ Authorized Use Only

Echos is a **Red Team traffic emulation tool** intended exclusively for:

- Controlled lab environments
- Authorized penetration tests with explicit written permission
- Internal EDR/NDR detection validation by the owning organization

**Unauthorized use against systems you do not own or do not have explicit written permission to test is illegal and unethical. The authors assume zero liability for misuse.**

---

## Reporting a Vulnerability

If you discover a security vulnerability in Echos itself (e.g., a bug that could cause unintended network activity, data leakage, or unsafe behavior on the operator's machine), please report it responsibly:

1. **Do not open a public GitHub issue** for security-sensitive bugs.
2. Email the maintainer directly or use GitHub's [private security advisory](https://github.com/xdrew87/echos/security/advisories/new) feature.
3. Include a clear description, reproduction steps, and any suggested fix.

We aim to respond within **72 hours** and will coordinate a fix and public disclosure together.

---

## Known Intentional Design Decisions

The following behaviors are **by design** for red team simulation fidelity. They are documented here so operators understand the threat model.

### TLS Certificate Validation Disabled (HTTPS Profile)

`send_https` uses `reqwest::ClientBuilder::danger_accept_invalid_certs(true)` to allow connections to C2 servers using self-signed certificates — a realistic adversary pattern. This means:

- The tool **will not detect MITM attacks** between the operator machine and the target.
- This flag is scoped to a per-request `Client` instance and does **not** affect system-wide TLS or any other process.
- **Mitigation**: Only run HTTPS profiles against targets you control. Do not route through untrusted proxies.

### Raw TCP / SMB Probing

`send_smb` opens a raw TCP connection to port 445 and sends a well-formed SMB negotiate packet. This is intentional for triggering NDR signatures. No credentials are sent or stored.

### SMTP Probing Without Authentication

`send_smtp` sends only `EHLO beacon.internal\r\n` and `QUIT`. It does **not** authenticate, send mail, or transmit any user data. The EHLO hostname is hardcoded and does not reflect the operator's real identity.

### ICMP via System `ping`

`send_icmp` spawns the OS `ping` binary with the target as a **separate argument** (not interpolated into a shell string), so **there is no shell injection risk**. The target string is passed directly by the OS.

---

## Security Properties of the Codebase

| Area | Status | Notes |
|------|--------|-------|
| Shell injection | ✅ Safe | `ping` target passed as a distinct argument, no shell involved |
| SMB packet construction | ✅ Safe | Statically defined byte slice; no user input interpolated |
| Connection timeouts | ✅ Fixed | All raw TCP connects (`send_smb`, `send_smtp`) and WebSocket `connect_async` have a 10-second timeout |
| WebSocket close handshake | ✅ Fixed | Read half is drained after `close()` to complete RFC-compliant close handshake and prevent `CLOSE_WAIT` port exhaustion |
| Panic on missing profile | ✅ Fixed | `profiles.first()` used with graceful error message instead of `profiles[0]` index panic |
| SMTP IPv6 address parsing | ✅ Fixed | Bracketed IPv6 literals (`[::1]`) handled correctly when inferring port 25 |
| SMB target port validation | ✅ Fixed | Returns a clear error if target contains `:` to prevent malformed `host:port:445` addresses |
| Hardcoded secrets | ✅ None | No API keys, passwords, or tokens in source |
| Credential storage | ✅ None | No credentials are written to disk or logged |
| Supply chain | ✅ Locked | `Cargo.lock` committed; all dependencies pinned to specific versions |

---

## Dependency Trust

All dependencies are well-established crates in the Rust ecosystem:

| Crate | Purpose | Notes |
|-------|---------|-------|
| `tokio` | Async runtime | Maintained by the Tokio team |
| `reqwest` | HTTP/HTTPS client | Wraps `hyper` + `native-tls` |
| `tokio-tungstenite` | WebSocket client | Maintained by the Tungstenite team |
| `trust-dns-resolver` | Async DNS | Part of the Hickory DNS project |
| `clap` | CLI argument parsing | Widely used, derive-based |
| `rand` | Jitter randomness | Non-cryptographic (intentional — timing jitter does not require CSPRNG) |
| `chrono` | Local time for sinusoidal jitter | No network access |
| `futures-util` | Stream/Sink combinators | Part of the `futures` ecosystem |

To audit dependencies: `cargo audit` (install with `cargo install cargo-audit`).

---

## Safe Usage Checklist

Before running Echos in any environment:

- [ ] You have **written authorization** to generate this traffic on the target network.
- [ ] The target IP/host/URL in your profile points to a system **you own or are authorized to test**.
- [ ] You are running in an **isolated lab or authorized test segment**, not production.
- [ ] You have notified the SOC/Blue Team if this is a coordinated purple-team exercise.
- [ ] You understand that HTTPS profiles **bypass TLS validation** — don't route through untrusted infrastructure.
- [ ] You will terminate Echos immediately if it generates unexpected traffic outside the test scope.
