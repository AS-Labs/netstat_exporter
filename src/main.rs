use hyper::{
    service::{make_service_fn, service_fn},
    Body, Request, Response, Server, StatusCode,
};
use std::collections::HashSet;
use std::convert::Infallible;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use serde::Deserialize;
use clap::Parser;

/// A simple netstat exporter for Prometheus
#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Port for the exporter to listen on
    #[arg(short, long, default_value_t = 9102)]
    port: u16,

    /// Path to the configuration file
    #[arg(short, long, default_value = "config.toml")]
    config_path: String,

    /// Only show connections in ESTABLISHED or LISTEN state
    #[arg(long)]
    show_established_listening: bool,

    /// Aggregate all non-configured ports into a single 'ephemeral' label to reduce cardinality
    #[arg(long)]
    aggregate_ports: bool,
}


#[derive(Debug, Deserialize, Clone, Default)]
struct ExporterConfig {
    /// A list of specific IP:Port combinations to filter for.
    /// The connection's source OR destination must match one of these.
    endpoints: Option<Vec<String>>,
    /// A list of ports to filter for.
    /// The connection's source OR destination port must match one of these.
    ports: Option<Vec<u16>>,
}

#[derive(Debug)]
struct Connection {
    local_addr: IpAddr,
    local_port: u16,
    remote_addr: IpAddr,
    remote_port: u16,
    state: String,
}

fn get_tcp_state(state_hex: &str) -> &'static str {
    let state = u8::from_str_radix(state_hex, 16).unwrap_or(0);
    match state {
        0x01 => "ESTABLISHED",
        0x02 => "SYN_SENT",
        0x03 => "SYN_RECV",
        0x04 => "FIN_WAIT1",
        0x05 => "FIN_WAIT2",
        0x06 => "TIME_WAIT",
        0x07 => "CLOSE",
        0x08 => "CLOSE_WAIT",
        0x09 => "LAST_ACK",
        0x0A => "LISTEN",
        0x0B => "CLOSING",
        _ => "UNKNOWN",
    }
}

fn parse_proc_address(hex_addr: &str) -> (IpAddr, u16) {
    let parts: Vec<&str> = hex_addr.split(':').collect();
    if parts.len() != 2 {
        return (IpAddr::V4(Ipv4Addr::new(0,0,0,0)), 0);
    }
    let ip_hex = u32::from_str_radix(parts[0], 16).unwrap_or(0);
    let port = u16::from_str_radix(parts[1], 16).unwrap_or(0);

    // The IP address in /proc/net/tcp is in little-endian format, so we need to reverse the bytes.
    let ip = Ipv4Addr::new(
        (ip_hex & 0xFF) as u8,
        ((ip_hex >> 8) & 0xFF) as u8,
        ((ip_hex >> 16) & 0xFF) as u8,
        ((ip_hex >> 24) & 0xFF) as u8,
    );

    (IpAddr::V4(ip), port)
}

async fn generate_metrics(config: &ExporterConfig, args: &Args) -> String {
    let mut metrics = String::new();
    metrics.push_str("# HELP netstat_connections_total Total number of connections.\n");
    metrics.push_str("# TYPE netstat_connections_total gauge\n");

    let has_port_filter = config.ports.as_ref().map_or(false, |p| !p.is_empty());
    let has_endpoint_filter = config.endpoints.as_ref().map_or(false, |e| !e.is_empty());
    let has_ip_port_filters = has_port_filter || has_endpoint_filter;

    // Build a set of all explicitly configured ports for aggregation logic
    let mut known_ports = HashSet::new();
    if args.aggregate_ports {
        if let Some(ports) = &config.ports {
            for port in ports {
                known_ports.insert(*port);
            }
        }
        if let Some(endpoints) = &config.endpoints {
            for endpoint in endpoints {
                if let Some(pos) = endpoint.rfind(':') {
                    if let Ok(port) = endpoint[pos+1..].parse::<u16>() {
                        known_ports.insert(port);
                    }
                }
            }
        }
    }


    if let Ok(content) = fs::read_to_string("/proc/net/tcp") {
        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 4 {
                continue;
            }
            
            let state = get_tcp_state(fields[3]);
            
            // Filter by connection state if the flag is enabled
            if args.show_established_listening && (state != "ESTABLISHED" && state != "LISTEN") {
                continue;
            }

            let (local_addr, local_port) = parse_proc_address(fields[1]);
            let (remote_addr, remote_port) = parse_proc_address(fields[2]);
            
            let conn = Connection {
                local_addr,
                local_port,
                remote_addr,
                remote_port,
                state: state.to_string(),
            };

            // If IP/port filters are active, check if the connection matches.
            if has_ip_port_filters {
                let mut matched = false;
                if has_port_filter {
                    if let Some(ports) = &config.ports {
                        if ports.contains(&conn.local_port) || ports.contains(&conn.remote_port) {
                            matched = true;
                        }
                    }
                }
                if !matched && has_endpoint_filter {
                    if let Some(endpoints) = &config.endpoints {
                        let local_endpoint = format!("{}:{}", conn.local_addr, conn.local_port);
                        let remote_endpoint = format!("{}:{}", conn.remote_addr, conn.remote_port);
                        if endpoints.contains(&local_endpoint) || endpoints.contains(&remote_endpoint) {
                            matched = true;
                        }
                    }
                }
                // If filters are on and no match was found, skip this connection
                if !matched {
                    continue;
                }
            }

            // Determine port labels based on aggregation flag
            let local_port_label = if args.aggregate_ports && !known_ports.contains(&conn.local_port) {
                "ephemeral".to_string()
            } else {
                conn.local_port.to_string()
            };

            let remote_port_label = if args.aggregate_ports && !known_ports.contains(&conn.remote_port) {
                "ephemeral".to_string()
            } else {
                conn.remote_port.to_string()
            };
            
            metrics.push_str(&format!(
                "netstat_connections_total{{state=\"{}\",src_ip=\"{}\",src_port=\"{}\",dst_ip=\"{}\",dst_port=\"{}\"}} 1\n",
                conn.state, conn.local_addr, local_port_label, conn.remote_addr, remote_port_label
            ));
        }
    }

    metrics
}

async fn handle_request(req: Request<Body>, config: ExporterConfig, args: Args) -> Result<Response<Body>, Infallible> {
    if req.uri().path() == "/metrics" {
        let metrics = generate_metrics(&config, &args).await;
        Ok(Response::new(Body::from(metrics)))
    } else {
        let mut not_found = Response::default();
        *not_found.status_mut() = StatusCode::NOT_FOUND;
        Ok(not_found)
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let settings = config::Config::builder()
        .add_source(config::File::with_name(&args.config_path).required(false))
        .build()
        .unwrap_or_else(|e| {
            eprintln!("Failed to build configuration from '{}': {}", args.config_path, e);
            std::process::exit(1);
        });

    let config: ExporterConfig = settings.try_deserialize().unwrap_or_else(|e| {
        eprintln!("Failed to deserialize config: {}. Continuing without filters.", e);
        ExporterConfig::default()
    });
    
    let addr = SocketAddr::from(([0, 0, 0, 0], args.port));

    let make_svc = make_service_fn(move |_conn| {
        let config = config.clone();
        let args = args.clone();
        async {
            Ok::<_, Infallible>(service_fn(move |req| {
                handle_request(req, config.clone(), args.clone())
            }))
        }
    });

    let server = Server::bind(&addr).serve(make_svc);
    
    println!("Rust netstat exporter listening on http://{}", addr);

    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}


