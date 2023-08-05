use clap::Parser;
use std::error::Error;
use std::fmt;

mod flood;
mod ping;
mod scan;

pub const NULL_VALUE: &str = "null";

/// Simple nmap-like program with 100% rust
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Scan (port scanning)
    #[arg(short, long, action)]
    scan: bool,
    /// Ping (host discovery)
    #[arg(short, long, action)]
    ping: bool,
    /// Flood (flood attack)
    #[arg(short, long, action)]
    flood: bool,

    /// Target host
    #[arg(long, default_value = NULL_VALUE)]
    host: String,
    /// Target subnet
    #[arg(long, default_value = NULL_VALUE)]
    subnet: String,
    /// Target port (like 80 or 80-8000)
    #[arg(long, default_value = NULL_VALUE)]
    port: String,

    /// Source host
    #[arg(long, default_value = NULL_VALUE)]
    source_host: String,
    /// Source port
    #[arg(long, default_value_t = 0)]
    source_port: u16,
    /// System interface (like ens33)
    #[arg(short, long, default_value = NULL_VALUE)]
    interface: String,

    /// Zombie host (Idle scan)
    #[arg(long, default_value = NULL_VALUE)]
    zombie_host: String,
    /// Zombie port (Idle scan)
    #[arg(long, default_value_t = 0)]
    zombie_port: u16,

    /// Syn flag
    #[arg(long, action)]
    syn: bool,
    /// Ack flag
    #[arg(long, action)]
    ack: bool,
    /// Connect flag
    #[arg(long, action)]
    connect: bool,
    /// Fin flag
    #[arg(long, action)]
    fin: bool,
    /// Null flag
    #[arg(long, action)]
    null: bool,
    /// Xmas flag
    #[arg(long, action)]
    xmas: bool,
    /// Window flag
    #[arg(long, action)]
    window: bool,
    /// Maimon flag
    #[arg(long, action)]
    maimon: bool,
    /// Idle flag
    #[arg(long, action)]
    idle: bool,
    /// Udp flag
    #[arg(long, action)]
    udp: bool,
    /// Ip flag
    #[arg(long, action)]
    ip: bool,
    /// Icmp flag
    #[arg(long, action)]
    icmp: bool,
    /// Arp flag
    #[arg(long, action)]
    arp: bool,
}

/* GetTargetPortFailed */
#[derive(Debug, Clone)]
pub struct GetTargetPortFailed {}

impl fmt::Display for GetTargetPortFailed {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "please set target port")
    }
}

impl GetTargetPortFailed {
    pub fn new() -> GetTargetPortFailed {
        GetTargetPortFailed {}
    }
}

impl Error for GetTargetPortFailed {}

/* SplitPortError */
#[derive(Debug, Clone)]
pub struct SplitPortError {
    portstr: String,
}

impl fmt::Display for SplitPortError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "can not split range port {}", self.portstr)
    }
}

impl SplitPortError {
    pub fn new(portstr: String) -> SplitPortError {
        SplitPortError { portstr }
    }
}

impl Error for SplitPortError {}

/* AutoInferScanTypeError */
#[derive(Debug, Clone)]
pub struct AutoInferScanTypeError {}

impl fmt::Display for AutoInferScanTypeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "can not auto infer scan type, please set host, port or interface at least one"
        )
    }
}

impl AutoInferScanTypeError {
    pub fn new() -> AutoInferScanTypeError {
        AutoInferScanTypeError {}
    }
}

impl Error for AutoInferScanTypeError {}

/* IdleScanValueError */
#[derive(Debug, Clone)]
pub struct IdleScanValueError {}

impl fmt::Display for IdleScanValueError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "can not find the zombie host or port")
    }
}

impl IdleScanValueError {
    pub fn new() -> IdleScanValueError {
        IdleScanValueError {}
    }
}

impl Error for IdleScanValueError {}

fn main() {
    let args = Args::parse();
    if args.scan {
        // start scan
        match scan::start_scan(args) {
            Err(e) => println!("{}", e),
            _ => (),
        }
    } else if args.ping {
        // start ping
        match ping::start_ping(args) {
            Err(e) => println!("{}", e),
            _ => (),
        }
    } else if args.flood {
        // start flood attack
        match flood::start_flood(args) {
            Err(e) => println!("{}", e),
            _ => (),
        }
    }
}
