<div align="center">

# Echos 📡

[![Rust](https://img.shields.io/badge/Rust-1.70%2B-orange)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Build Status](https://img.shields.io/github/actions/workflow/status/xdrew87/echos/ci.yml)](https://github.com/xdrew87/echos/actions)

**A lightweight, high-performance Red Team traffic emulation tool written in Rust**  
*Simulate C2 beacons to test EDR/NDR detection capabilities*

[Installation](#-installation) • [Usage](#-usage) • [Contributing](#-contributing)

</div>

---

## 🚀 Features

- ✅ **Multi-Protocol Support**: HTTP, HTTPS, DNS, ICMP, SMB, WebSocket, and SMTP beacon emulation
- 🎭 **Threat Actor Profiles**: Pre-built profiles for Cobalt Strike, APT28, Lazarus Group, APT29, Emotet, and FIN7
- ⏱️ **Jitter Algorithms**: Uniform, Gaussian (Box-Muller), and Sinusoidal (business-hours aware) delays
- 🔄 **Domain Rotation**: Multi-target support for DGA / fast-flux beacon simulation (Emotet)
- 🛡️ **Exponential Backoff**: Automatic retry with capped exponential backoff on consecutive failures
- 🛠️ **Custom Headers**: Fine-tune HTTP/S requests for signature evasion (CDN masquerading, browser UA)
- 🖥️ **CLI Interface**: Simple, intuitive command-line usage
- ⚡ **Asynchronous Networking**: Tokio-powered for high performance
- 🧩 **Modular Architecture**: Easy to extend with new protocols and profiles

## 📋 Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Profiles](#profiles)
- [Building from Source](#building-from-source)
- [Contributing](#contributing)
- [License](#license)
- [Disclaimer](#disclaimer)

## 🛠️ Installation

### Pre-built Binaries (Coming Soon)

Download the latest release from the [Releases](https://github.com/xdrew87/echos/releases) page.

### From Source

Ensure you have [Rust](https://rustup.rs/) installed (version 1.70 or later).

```bash
git clone https://github.com/xdrew87/echos.git
cd echos
cargo build --release
```

The binary will be available at `target/release/echos`.

## 📖 Usage

Run Echos with a specific profile:

```bash
./echos --profile Cobalt
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-p, --profile <PROFILE>` | Select a traffic profile | Cobalt |
| `-h, --help` | Display help information | - |
| `-V, --version` | Display version information | - |

### Examples

```bash
# Emulate Cobalt Strike HTTP beacon
./echos --profile Cobalt

# Emulate APT28 DNS queries
./echos --profile APT28

# Emulate Lazarus Group HTTPS C2 (Gaussian jitter)
./echos --profile Lazarus

# Emulate APT29 slow HTTPS beaconing (sinusoidal / business-hours jitter)
./echos --profile APT29

# Emulate Emotet HTTP with rotating targets
./echos --profile Emotet

# Emulate FIN7 CDN-masqueraded HTTPS
./echos --profile FIN7

# SMB lateral-movement probe
./echos --profile "SMB Beacon"

# WebSocket C2 channel
./echos --profile "WebSocket Beacon"

# SMTP exfil simulation
./echos --profile "SMTP Beacon"

# ICMP beacons
./echos --profile "ICMP Beacon"
```

Echos will run indefinitely, sending beacons at randomized intervals based on the profile's jitter settings.

## 🎭 Profiles

Echos includes several pre-configured profiles:

| Profile | Protocol | Jitter | Description | Base Delay | Jitter % |
|---------|----------|--------|-------------|------------|--------|
| **Cobalt** | HTTP | Uniform | Mimics Cobalt Strike C2 traffic | 10s | 20% |
| **APT28** | DNS | Uniform | Simulates APT28 DNS beaconing | 30s | 10% |
| **Lazarus** | HTTPS | Gaussian | Lazarus Group slow C2, Korean-locale UA | 300s | 15% |
| **APT29** | HTTPS | Sinusoidal | Cozy Bear business-hours-aware beaconing | 600s | 10% |
| **Emotet** | HTTP | Gaussian | Rotating target pool (DGA/fast-flux sim) | 60s | 25% |
| **FIN7** | HTTPS | Uniform | CDN-masquerading headers (Cloudflare) | 30s | 10% |
| **SMB Beacon** | SMB | Uniform | SMB negotiate probe on port 445 | 120s | 10% |
| **WebSocket Beacon** | WebSocket | Uniform | WebSocket frame-based C2 channel | 15s | 15% |
| **SMTP Beacon** | SMTP | Uniform | SMTP EHLO exfil-channel probe | 90s | 10% |
| **ICMP Beacon** | ICMP | Uniform | Basic ICMP ping-based beacon | 60s | 5% |

### Jitter Algorithms

| Algorithm | Description |
|-----------|-------------|
| **Uniform** | Random delay sampled uniformly from `[base - jitter, base + jitter]` |
| **Gaussian** | Normal distribution (Box-Muller transform) centred at `base_delay` with `std_dev = jitter_amount` |
| **Sinusoidal** | Time-of-day modulation: 1× delay at ~13:00, up to 3× delay at ~01:00, mimicking daytime-only adversaries |

> 💡 **Tip**: Profiles can be extended or customized in `src/profiles.rs`.

## 🔨 Building from Source

### Prerequisites

- Rust 1.70+
- Cargo

### Build Steps

```bash
cargo build --release
```

### Development

For development builds with debug symbols:

```bash
cargo build
```

Run tests:

```bash
cargo test
```

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository 🍴
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request 📝

### Adding New Profiles

1. Add a new `TrafficProfile` in `src/profiles.rs`
2. Implement the protocol handler in `src/network.rs` if needed
3. Update this README

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

**Echos is an educational tool for defensive security research and testing. It should only be used in controlled environments with explicit permission. The authors are not responsible for any misuse or illegal activities.**

---

<div align="center">

**Made with ❤️ for the security community**

[⭐ Star us on GitHub](https://github.com/xdrew87/echos) • [🐛 Report Issues](https://github.com/xdrew87/echos/issues)

</div>