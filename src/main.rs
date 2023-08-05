use clap::Parser;

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

    /// Syn flag
    #[arg(long, action)]
    syn: bool,
    /// Ack flag
    #[arg(long, action)]
    ack: bool,
}

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
    } else if args.flood {
        // start flood attack
    }
}
