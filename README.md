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

- ✅ **Multi-Protocol Support**: HTTP, DNS, and ICMP beacon emulation
- 🎭 **Threat Actor Profiles**: Pre-built profiles for Cobalt Strike, APT28, and more
- ⏱️ **Jitter Algorithms**: Randomized delays to mimic real-world C2 traffic
- 🛠️ **Custom Headers**: Fine-tune HTTP requests for signature evasion
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
# Emulate Cobalt Strike beacon
./echos --profile Cobalt

# Emulate APT28 DNS queries
./echos --profile APT28

# Emulate ICMP beacons
./echos --profile "ICMP Beacon"
```

Echos will run indefinitely, sending beacons at randomized intervals based on the profile's jitter settings.

## 🎭 Profiles

Echos includes several pre-configured profiles:

| Profile | Protocol | Description | Base Delay | Jitter |
|---------|----------|-------------|------------|--------|
| **Cobalt** | HTTP | Mimics Cobalt Strike C2 traffic | 10s | 20% |
| **APT28** | DNS | Simulates APT28 DNS beaconing | 30s | 10% |
| **ICMP Beacon** | ICMP | Basic ICMP ping-based beacon | 60s | 5% |

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