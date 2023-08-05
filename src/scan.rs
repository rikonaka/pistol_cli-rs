use crate::Args;
use crate::AutoInferScanTypeError;
use crate::GetTargetPortFailed;
use crate::IdleScanValueError;
use crate::SplitPortError;
use crate::NULL_VALUE;
use anyhow::Result;
use pistol;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::time::Duration;
use subnetwork::Ipv4Pool;

#[derive(PartialEq)]
enum InferScanType {
    SinglePort,
    RangePort,
    Subnet,
    Unknown,
}

struct Parameters {
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    dst_ipv4: Option<Ipv4Addr>,
    dst_port: Option<u16>,
    zombie_ipv4: Option<Ipv4Addr>,
    zombie_port: Option<u16>,
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
            zombie_ipv4: None,
            zombie_port: None,
            start_port: None,
            end_port: None,
            subnet: None,
            interface: None,
            inter_scan_type: InferScanType::Unknown,
        }
    }
}

pub fn start_scan(args: Args) -> Result<()> {
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

    let zombie_ipv4 = if args.zombie_host != NULL_VALUE {
        Some(Ipv4Addr::from_str(&args.zombie_host)?)
    } else {
        None
    };
    parameters.zombie_ipv4 = zombie_ipv4;

    let zombie_port = if args.zombie_port != 0 {
        Some(args.zombie_port)
    } else {
        None
    };
    parameters.zombie_port = zombie_port;

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
        if args.port.contains("-") {
            let port_split_vec: Vec<&str> = args.port.split("-").collect();
            if port_split_vec.len() == 2 {
                let start_port: u16 = port_split_vec[0].parse()?;
                let end_port: u16 = port_split_vec[1].parse()?;
                parameters.start_port = Some(start_port);
                parameters.end_port = Some(end_port);
                parameters.inter_scan_type = InferScanType::RangePort;
            } else {
                return Err(SplitPortError::new(args.port).into());
            }
        } else {
            let dst_port: u16 = args.port.parse()?;
            parameters.dst_port = Some(dst_port);
            if parameters.inter_scan_type == InferScanType::Subnet {
                parameters.start_port = Some(dst_port);
                parameters.end_port = Some(dst_port);
            } else {
                parameters.inter_scan_type = InferScanType::SinglePort;
            }
        }
    } else {
        return Err(GetTargetPortFailed::new().into());
    };

    let interface = if args.interface != NULL_VALUE {
        Some(args.interface)
    } else {
        None
    };
    parameters.interface = interface;

    let print_result = true;
    let timeout = Some(Duration::from_secs_f32(0.1));
    let max_loop = Some(64);
    let threads_num = 0; // auto detect

    match parameters.inter_scan_type {
        InferScanType::Unknown => return Err(AutoInferScanTypeError::new().into()),
        InferScanType::SinglePort => {
            // scan single port
            let func = if args.syn {
                // start syn scan
                pistol::tcp_syn_scan_single_port
            } else if args.ack {
                // start ack scan
                pistol::tcp_ack_scan_single_port
            } else if args.connect {
                pistol::tcp_connect_scan_single_port
            } else if args.fin {
                pistol::tcp_fin_scan_single_port
            } else if args.null {
                pistol::tcp_null_scan_single_port
            } else if args.xmas {
                pistol::tcp_xmas_scan_single_port
            } else if args.window {
                pistol::tcp_window_scan_single_port
            } else if args.maimon {
                pistol::tcp_maimon_scan_single_port
            } else if args.idle {
                if parameters.zombie_ipv4.is_none() || parameters.zombie_port.is_none() {
                    return Err(IdleScanValueError::new().into());
                }
                let _ = pistol::tcp_idle_scan_single_port(
                    src_ipv4,
                    src_port,
                    parameters.dst_ipv4.unwrap(),
                    parameters.dst_port.unwrap(),
                    parameters.zombie_ipv4,
                    parameters.zombie_port,
                    parameters.interface.as_deref(),
                    print_result,
                    timeout,
                    max_loop,
                )?;
                return Ok(());
            } else if args.udp {
                let _ = pistol::udp_scan_single_port(
                    src_ipv4,
                    src_port,
                    parameters.dst_ipv4.unwrap(),
                    parameters.dst_port.unwrap(),
                    parameters.interface.as_deref(),
                    print_result,
                    timeout,
                    max_loop,
                )?;
                return Ok(());
            } else if args.ip {
                // let _ = pistol::ip_protocol_scan_host(
                //     src_ipv4,
                //     parameters.dst_ipv4.unwrap(),
                //     parameters.interface.as_deref(),
                //     print_result,
                //     timeout,
                //     max_loop,
                // )?;
                return Ok(());
            } else if args.arp {
                let _ = pistol::arp_scan_subnet(
                    parameters.subnet.unwrap(),
                    None,
                    parameters.interface.as_deref(),
                    threads_num,
                    print_result,
                    max_loop,
                )?;
                return Ok(());
            } else {
                pistol::tcp_syn_scan_single_port
            };
            let _ = func(
                src_ipv4,
                src_port,
                parameters.dst_ipv4.unwrap(),
                parameters.dst_port.unwrap(),
                parameters.interface.as_deref(),
                print_result,
                timeout,
                max_loop,
            )?;
        }
        InferScanType::RangePort => {
            // scan range port
            let func = if args.syn {
                pistol::tcp_syn_scan_range_port
            } else if args.ack {
                pistol::tcp_ack_scan_range_port
            } else if args.connect {
                pistol::tcp_connect_scan_range_port
            } else if args.fin {
                pistol::tcp_fin_scan_range_port
            } else if args.null {
                pistol::tcp_null_scan_range_port
            } else if args.xmas {
                pistol::tcp_xmas_scan_range_port
            } else if args.window {
                pistol::tcp_window_scan_range_port
            } else if args.maimon {
                pistol::tcp_maimon_scan_range_port
            } else if args.idle {
                if parameters.zombie_ipv4.is_none() || parameters.zombie_port.is_none() {
                    return Err(IdleScanValueError::new().into());
                }
                let _ = pistol::tcp_idle_scan_range_port(
                    src_ipv4,
                    src_port,
                    parameters.dst_ipv4.unwrap(),
                    parameters.zombie_ipv4,
                    parameters.zombie_port,
                    parameters.start_port.unwrap(),
                    parameters.end_port.unwrap(),
                    parameters.interface.as_deref(),
                    threads_num,
                    print_result,
                    timeout,
                    max_loop,
                )?;
                return Ok(());
            } else if args.udp {
                let _ = pistol::udp_scan_range_port(
                    src_ipv4,
                    src_port,
                    parameters.dst_ipv4.unwrap(),
                    parameters.start_port.unwrap(),
                    parameters.end_port.unwrap(),
                    parameters.interface.as_deref(),
                    threads_num,
                    print_result,
                    timeout,
                    max_loop,
                )?;
                return Ok(());
            } else if args.ip {
                return Ok(());
            } else if args.arp {
                let _ = pistol::arp_scan_subnet(
                    parameters.subnet.unwrap(),
                    None,
                    parameters.interface.as_deref(),
                    threads_num,
                    print_result,
                    max_loop,
                )?;
                return Ok(());
            } else {
                pistol::tcp_syn_scan_range_port
            };
            let _ = func(
                src_ipv4,
                src_port,
                parameters.dst_ipv4.unwrap(),
                parameters.start_port.unwrap(),
                parameters.end_port.unwrap(),
                parameters.interface.as_deref(),
                threads_num,
                print_result,
                timeout,
                max_loop,
            )?;
        }
        InferScanType::Subnet => {
            // scan a subnet
            let func = if args.syn {
                pistol::tcp_syn_scan_subnet
            } else if args.ack {
                pistol::tcp_ack_scan_subnet
            } else if args.connect {
                pistol::tcp_connect_scan_subnet
            } else if args.fin {
                pistol::tcp_fin_scan_subnet
            } else if args.null {
                pistol::tcp_null_scan_subnet
            } else if args.xmas {
                pistol::tcp_xmas_scan_subnet
            } else if args.window {
                pistol::tcp_window_scan_subnet
            } else if args.maimon {
                pistol::tcp_maimon_scan_subnet
            } else if args.idle {
                if parameters.zombie_ipv4.is_none() || parameters.zombie_port.is_none() {
                    return Err(IdleScanValueError::new().into());
                }
                let _ = pistol::tcp_idle_scan_subnet(
                    src_ipv4,
                    src_port,
                    parameters.zombie_ipv4,
                    parameters.zombie_port,
                    parameters.subnet.unwrap(),
                    parameters.start_port.unwrap(),
                    parameters.end_port.unwrap(),
                    parameters.interface.as_deref(),
                    threads_num,
                    print_result,
                    timeout,
                    max_loop,
                )?;
                return Ok(());
            } else if args.udp {
                let _ = pistol::udp_scan_subnet(
                    src_ipv4,
                    src_port,
                    parameters.subnet.unwrap(),
                    parameters.start_port.unwrap(),
                    parameters.end_port.unwrap(),
                    parameters.interface.as_deref(),
                    threads_num,
                    print_result,
                    timeout,
                    max_loop,
                )?;
                return Ok(());
            } else if args.ip {
                return Ok(());
            } else {
                pistol::tcp_syn_scan_subnet
            };
            let _ = func(
                src_ipv4,
                src_port,
                parameters.subnet.unwrap(),
                parameters.start_port.unwrap(),
                parameters.end_port.unwrap(),
                parameters.interface.as_deref(),
                threads_num,
                print_result,
                timeout,
                max_loop,
            )?;
        }
    }
    Ok(())
}
