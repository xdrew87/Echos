# Contributing to Echos

Thank you for your interest in contributing. Echos is a defensive tool built for authorized security testing labs. Contributions that improve usability, add well-documented profiles, or strengthen test coverage are welcome.

---

## Getting Started

### Build the project

```bash
git clone https://github.com/xdrew87/echos
cd echos
cargo build
```

### Run the tests

```bash
cargo test
```

Tests live in `#[cfg(test)]` modules inside each source file (not in a separate `tests/` directory, since this is a binary crate).

### Check formatting and lints

```bash
cargo fmt --check
cargo clippy -- -D warnings
```

Fix any warnings before opening a pull request. The CI pipeline enforces both.

---

## Project Structure

```
echos/
├── src/
│   ├── main.rs       — CLI parsing, beacon loop, run summary
│   ├── profiles.rs   — TrafficProfile, JitterAlgorithm, Protocol, built-in profiles
│   ├── network.rs    — Protocol implementations (HTTP, HTTPS, DNS, ICMP, SMB, WS, SMTP)
│   ├── config.rs     — TOML config loading and profile parsing
│   ├── runtime.rs    — RuntimeOptions struct (threaded through all network calls)
│   └── logging.rs    — tracing subscriber setup (console + file, human + JSON)
├── examples/
│   └── echos.toml    — Sample custom profile config
├── docs/
│   └── lab-guide.md  — Detection validation lab walkthrough
├── .github/
│   └── workflows/
│       ├── ci.yml      — fmt, clippy, test, multi-platform build
│       └── release.yml — Binary release on tag push
├── SECURITY.md
├── ROADMAP.md
└── CONTRIBUTING.md   — This file
```

---

## How to Add a New Built-in Profile

Built-in profiles live in `src/profiles.rs` inside `get_profiles()`.

1. Create a `TrafficProfile` with the appropriate protocol and timing:

```rust
let mut my_profile = TrafficProfile::new(
    "MyProfile",           // display name
    "http://127.0.0.1:8080", // default target
    60,                    // base delay in seconds
    15.0,                  // jitter percent
    Protocol::Http,
);
```

2. Add any headers that define this profile's fingerprint:

```rust
my_profile.add_header("User-Agent", "...");
my_profile.add_header("Accept", "...");
```

3. Optionally set a jitter algorithm:

```rust
let my_profile = my_profile.with_jitter_algorithm(JitterAlgorithm::Gaussian);
```

4. Add rotating targets if the threat actor uses fast-flux or DGA:

```rust
my_profile.add_target("http://127.0.0.1:8081");
my_profile.add_target("http://127.0.0.1:8082");
```

5. Add the profile to the return `vec![]` at the bottom of `get_profiles()`.

6. Add a comment block above the profile explaining what threat actor or tool it emulates and what makes it distinctive.

---

## How to Add a Custom Profile via Config

You do not need to modify source code to add custom profiles. Create a TOML file:

```toml
[[profiles]]
name             = "My Lab Profile"
protocol         = "https"
target           = "https://192.168.10.50:8443"
base_delay_secs  = 45
jitter_percent   = 10.0
jitter_algorithm = "uniform"    # uniform | gaussian | sinusoidal

[profiles.headers]
User-Agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
```

Load it at runtime:

```bash
echos --config my-profile.toml --profile "My Lab Profile" --count 5
```

---

## How to Add a New Protocol

1. Add the variant to the `Protocol` enum in `src/profiles.rs` and implement `display_name()` for it.
2. Implement a `send_<protocol>(profile: &TrafficProfile, opts: &RuntimeOptions) -> Result<(), Box<dyn Error>>` function in `src/network.rs`.
3. Add the match arm in the beacon loop in `src/main.rs`.
4. Update `src/config.rs` to recognize the new protocol string in `parse_protocol()`.
5. Add at least one unit test validating the function compiles and runs without panicking against a known-safe target.

---

## Pull Request Guidelines

- **One logical change per PR.** Keep PRs focused — a new profile, a new flag, a bug fix, etc.
- **Run `cargo fmt` before pushing.** CI will reject unformatted code.
- **Fix all clippy warnings.** CI runs `cargo clippy -- -D warnings`.
- **Add or update tests.** New profiles should include at least a round of jitter bound tests. New network functions should have at least a smoke test.
- **Do not add profiles that claim to bypass detection.** Echos emulates traffic patterns — it does not claim to evade any specific product. Profiles should be documented as "emulating X's known TTP" not "bypassing Y's detection."
- **Do not add outbound connections to third-party infrastructure.** All default targets must be loopback or RFC 1918 addresses.
- **Update the relevant documentation** if your change affects CLI flags, config format, or profile behavior.

---

## Reporting Issues

Open a GitHub issue with:

- Echos version (`echos --version`)
- OS and Rust version (`rustc --version`)
- The exact command you ran
- The output you got vs. what you expected

For security issues, see [SECURITY.md](SECURITY.md) for the responsible disclosure process.
