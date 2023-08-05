use crate::Args;
use crate::NULL_VALUE;
use anyhow::Result;
use pistol;
use std::error::Error;
use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::time::Duration;
use subnetwork::Ipv4Pool;

/* GetTargetPortFailed */
#[derive(Debug, Clone)]
struct GetTargetPortFailed {}

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
struct SplitPortError {
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
struct AutoInferScanTypeError {}

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
            if args.syn {
                // start syn scan
                let _ = pistol::tcp_syn_scan_single_port(
                    src_ipv4,
                    src_port,
                    parameters.dst_ipv4.unwrap(),
                    parameters.dst_port.unwrap(),
                    parameters.interface.as_deref(),
                    print_result,
                    timeout,
                    max_loop,
                )?;
                // println!("{}", scan_ret);
            } else if args.ack {
                // start ack scan
                let _ = pistol::tcp_ack_scan_single_port(
                    src_ipv4,
                    src_port,
                    parameters.dst_ipv4.unwrap(),
                    parameters.dst_port.unwrap(),
                    parameters.interface.as_deref(),
                    print_result,
                    timeout,
                    max_loop,
                )?;
                // println!("{}", scan_ret);
            }
        }
        InferScanType::RangePort => {
            // scan range port
            if args.syn {
                let _ = pistol::tcp_syn_scan_range_port(
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
            } else if args.ack {
                let _ = pistol::tcp_ack_scan_range_port(
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
        }
        InferScanType::Subnet => {
            // scan a subnet
            if args.syn {
                let _ = pistol::tcp_syn_scan_subnet(
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
            } else if args.ack {
                let _ = pistol::tcp_ack_scan_subnet(
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
    }
    Ok(())
}
