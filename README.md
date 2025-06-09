# Netstat Exporter for Prometheus (Rust)

##  A simple, configurable Prometheus exporter written in Rust that exposes TCP connection metrics from /proc/net/tcp, similar to netstat.
### Features

    Exposes TCP connections in the Prometheus exposition format.

    Allows filtering for connections in ESTABLISHED and/or LISTEN states.

    Supports filtering by a list of ports or specific IP:Port endpoints via a configuration file.

    Includes a cardinality reduction feature to prevent Prometheus performance issues from high-numbered ephemeral ports.

### Prerequisites

    Rust and Cargo: You need to have the Rust toolchain installed. You can get it from rustup.rs.

### Configuration

The exporter is configured using a TOML file (e.g., config.toml). The path to this file can be specified with the --config-path command-line argument.

The configuration file allows you to specify which ports or endpoints are considered "known". This is used for the cardinality reduction feature.

### Example config.toml:
```toml
# A list of ports to consider "known".
# When aggregation is on, any port in this list will be reported with its number.
# If this list is commented out or empty, this filter is ignored.
ports = [443, 8080, 9100]

# A list of specific IP:Port combinations to consider "known".
# When aggregation is on, the port from any endpoint in this list will be reported with its number.
# If this list is commented out or empty, this filter is ignored.
endpoints = ["127.0.0.1:9090"]
```
### Building

    Clone the repository or save the main.rs file.

    Make sure you have a Cargo.toml file with the required dependencies:
```toml
    [dependencies]
    tokio = { version = "1", features = ["full"] }
    hyper = { version = "0.14", features = ["full"] }
    config = "0.13"
    serde = { version = "1.0", features = ["derive"] }
    clap = { version = "4.0", features = ["derive"] }
```

    Build the project from the root directory:
```bash
    cargo build --release
```
    The binary will be located at ./target/release/netstat_exporter_rust.




#### README is written with AI, too lazy to write docs.. will update it later.
