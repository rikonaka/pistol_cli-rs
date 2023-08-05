use crate::Args;
use crate::AutoInferScanTypeError;
use crate::NULL_VALUE;
use anyhow::Result;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::time::Duration;
use subnetwork::Ipv4Pool;

#[derive(PartialEq)]
enum InferScanType {
    Host,
    Subnet,
    Unknown,
}

struct Parameters {
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    dst_ipv4: Option<Ipv4Addr>,
    dst_port: Option<u16>,
    start_port: Option<u16>,
    end_port: Option<u16>,
    subnet: Option<Ipv4Pool>,
    interface: Option<String>,
    inter_scan_type: InferScanType,
}

impl Parameters {
    fn new_empty() -> Parameters {
        Parameters {
            src_ipv4: None,
            src_port: None,
            dst_ipv4: None,
            dst_port: None,
            start_port: None,
            end_port: None,
            subnet: None,
            interface: None,
            inter_scan_type: InferScanType::Unknown,
        }
    }
}

pub fn start_ping(args: Args) -> Result<()> {
    let mut parameters = Parameters::new_empty();

    let src_ipv4 = if args.source_host != NULL_VALUE {
        Some(Ipv4Addr::from_str(&args.source_host)?)
    } else {
        None
    };
    parameters.src_ipv4 = src_ipv4;

    let src_port = if args.source_port != 0 {
        Some(args.source_port)
    } else {
        None
    };
    parameters.src_port = src_port;

    if args.host != NULL_VALUE {
        let dst_ipv4 = Ipv4Addr::from_str(&args.host)?;
        parameters.dst_ipv4 = Some(dst_ipv4);
    }

    if args.subnet != NULL_VALUE {
        let subnet = Ipv4Pool::new(&args.subnet)?;
        parameters.subnet = Some(subnet);
        parameters.inter_scan_type = InferScanType::Subnet;
    }

    if args.port != NULL_VALUE {
        let dst_port: u16 = args.port.parse()?;
        parameters.dst_port = Some(dst_port);
        if parameters.inter_scan_type == InferScanType::Subnet {
            parameters.start_port = Some(dst_port);
            parameters.end_port = Some(dst_port);
        } else {
            parameters.inter_scan_type = InferScanType::Host;
        }
    } else {
        parameters.inter_scan_type = InferScanType::Host;
        parameters.dst_port = None;
    };

    let interface = if args.interface != NULL_VALUE {
        Some(args.interface)
    } else {
        None
    };
    parameters.interface = interface;

    let print_result = false;
    let timeout = Some(Duration::from_secs_f32(0.1));
    let max_loop = Some(64);
    let threads_num = 0; // auto detect

    match parameters.inter_scan_type {
        InferScanType::Unknown => return Err(AutoInferScanTypeError::new().into()),
        InferScanType::Host => {
            let func = if args.syn {
                pistol::tcp_syn_ping_host
            } else if args.ack {
                pistol::tcp_ack_ping_host
            } else if args.udp {
                let ret = pistol::udp_ping_host(
                    src_ipv4,
                    src_port,
                    parameters.dst_ipv4.unwrap(),
                    parameters.dst_port,
                    parameters.interface.as_deref(),
                    print_result,
                    timeout,
                    max_loop,
                )?;
                println!("{}", ret);
                return Ok(());
            } else if args.icmp {
                let ret = pistol::icmp_ping_host(
                    src_ipv4,
                    src_port,
                    parameters.dst_ipv4.unwrap(),
                    parameters.dst_port,
                    parameters.interface.as_deref(),
                    print_result,
                    timeout,
                    max_loop,
                )?;
                println!("{}", ret);
                return Ok(());
            } else {
                pistol::tcp_syn_ping_host
            };
            let ret = func(
                src_ipv4,
                src_port,
                parameters.dst_ipv4.unwrap(),
                parameters.dst_port,
                parameters.interface.as_deref(),
                print_result,
                timeout,
                max_loop,
            )?;
            println!("{}", ret);
        }
        InferScanType::Subnet => {
            let func = if args.syn {
                pistol::tcp_syn_ping_subnet
            } else if args.ack {
                pistol::tcp_ack_ping_subnet
            } else if args.udp {
                let ret = pistol::udp_ping_subnet(
                    src_ipv4,
                    src_port,
                    parameters.dst_port,
                    parameters.subnet.unwrap(),
                    parameters.interface.as_deref(),
                    threads_num,
                    print_result,
                    timeout,
                    max_loop,
                )?;
                for k in ret.keys() {
                    println!("{}", ret.get(k).unwrap());
                }
                return Ok(());
            } else if args.icmp {
                let ret = pistol::icmp_ping_subnet(
                    src_ipv4,
                    src_port,
                    parameters.dst_port,
                    parameters.subnet.unwrap(),
                    parameters.interface.as_deref(),
                    threads_num,
                    print_result,
                    timeout,
                    max_loop,
                )?;
                for k in ret.keys() {
                    println!("{}", ret.get(k).unwrap());
                }
                return Ok(());
            } else {
                pistol::tcp_syn_ping_subnet
            };
            let ret = func(
                src_ipv4,
                src_port,
                parameters.dst_port,
                parameters.subnet.unwrap(),
                parameters.interface.as_deref(),
                threads_num,
                print_result,
                timeout,
                max_loop,
            )?;
            for k in ret.keys() {
                println!("{}", ret.get(k).unwrap());
            }
        }
    }

    Ok(())
}
