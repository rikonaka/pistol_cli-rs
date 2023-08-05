use crate::Args;
use crate::AutoInferScanTypeError;
use crate::GetTargetPortFailed;
use crate::SplitPortError;
use crate::NULL_VALUE;
use anyhow::Result;
use std::net::Ipv4Addr;
use std::str::FromStr;

#[derive(PartialEq)]
enum InferScanType {
    Host,
    Unknown,
}

struct Parameters {
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    dst_ipv4: Option<Ipv4Addr>,
    dst_port: Option<u16>,
    start_port: Option<u16>,
    end_port: Option<u16>,
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
            interface: None,
            inter_scan_type: InferScanType::Unknown,
        }
    }
}

pub fn start_flood(args: Args) -> Result<()> {
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

    if args.port != NULL_VALUE {
        if args.port.contains("-") {
            let port_split_vec: Vec<&str> = args.port.split("-").collect();
            if port_split_vec.len() == 2 {
                let start_port: u16 = port_split_vec[0].parse()?;
                let end_port: u16 = port_split_vec[1].parse()?;
                parameters.start_port = Some(start_port);
                parameters.end_port = Some(end_port);
                parameters.inter_scan_type = InferScanType::Host;
            } else {
                return Err(SplitPortError::new(args.port).into());
            }
        } else {
            let dst_port: u16 = args.port.parse()?;
            parameters.dst_port = Some(dst_port);
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
    let threads_num = 0; // auto detect
    let max_same_packet = 1024;
    let max_flood_packet = 1024;

    match parameters.inter_scan_type {
        InferScanType::Unknown => return Err(AutoInferScanTypeError::new().into()),
        InferScanType::Host => {
            let func = if args.syn {
                pistol::tcp_syn_flood_host
            } else if args.ack {
                pistol::tcp_ack_flood_host
            } else if args.icmp {
                let _ = pistol::icmp_flood_host(
                    src_ipv4,
                    parameters.dst_ipv4.unwrap(),
                    parameters.interface.as_deref(),
                    threads_num,
                    print_result,
                    max_same_packet,
                    max_flood_packet,
                )?;
                return Ok(());
            } else if args.udp {
                pistol::udp_flood_host
            } else {
                pistol::tcp_syn_flood_host
            };

            let _ = func(
                src_ipv4,
                src_port,
                parameters.dst_ipv4.unwrap(),
                parameters.dst_port,
                parameters.interface.as_deref(),
                threads_num,
                print_result,
                max_same_packet,
                max_flood_packet,
            )?;
        }
    }
    Ok(())
}
