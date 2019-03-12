extern crate get_if_addrs;
extern crate failure;

use std::str;
use std::process::Command;
use failure::Fail;
use jsonrpc_http_server::jsonrpc_core::types::error::Error;
use jsonrpc_http_server::jsonrpc_core::*;
use jsonrpc_http_server::*;
use serde::Deserialize;

// define the Iface struct for interface parameter
#[derive(Debug, Deserialize)]
struct Iface {
    iface: String,
}

#[derive(Debug, Fail)]
pub enum CallError {
    #[fail(display = "missing expected parameters")]
    MissingParams { e: Error },

    #[fail(display = "no ip found for given interface")]
    NoIpFound,
}

impl From<CallError> for Error {
    fn from(err: CallError) -> Self {
        match &err {
            CallError::MissingParams { e } => Error {
                code: ErrorCode::ServerError(-32602),
                message: "invalid params".into(),
                data: Some(format!("{}", e.message).into()),
            },
            CallError::NoIpFound => Error {
                code: ErrorCode::ServerError(-32000),
                message: "no ip found for given interface".into(),
                data: None,
            },
            err => Error {
                code: ErrorCode::InternalError,
                message: "internal error".into(),
                data: Some(format!("{:?}", err).into()),
            },
        }
    }
}

// retrieve ip address for specified interface
fn get_ip(iface: String) -> Option<String> {
    let ifaces = get_if_addrs::get_if_addrs().unwrap();
    ifaces
        .iter()
        .find(|&i| i.name == iface)
        .map(|iface| iface.ip().to_string())
}

// retrieve ssid of connected network
fn get_ssid() -> Option<String> {
    let ssid = Command::new("iwgetid")
        .arg("-r")
        .output()
        .expect("Failed to execute iwgetif command");

    if ssid.status.success() {
        let ssid_name = match str::from_utf8(&*ssid.stdout) {
            Ok(s) => s,
            Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
        };
        let mut ssid_name = ssid_name.to_string();
        let len = ssid_name.len();
        // remove trailing newline character from string
        ssid_name.truncate(len - 1);
        Some(ssid_name)
    } else {
        None
    }
}

fn main() {
    let mut io = IoHandler::default();

    io.add_method("get_ip", move |params: Params| {
        // parse parameters and match on result
        let i: Result<Iface> = params.parse();
        match i {
            // if result contains parameters, unwrap
            Ok(_) => {
                let i: Iface = i.unwrap();
                let ip = get_ip(i.iface.to_string());
                match ip {
                    Some(ip) => Ok(Value::String(ip.to_string())),
                    None => Err(Error::from(CallError::NoIpFound)),
                }
            }
            Err(e) => Err(Error::from(CallError::MissingParams { e })),
        }
    });

    io.add_method("get_ssid", move |_| {
        let ssid = get_ssid();
        match ssid {
            Some(ssid) => Ok(Value::String(ssid)),
            None => Ok(Value::String("not currently connected".to_string())),
        }
    });

    let server = ServerBuilder::new(io)
        .cors(DomainsValidation::AllowOnly(vec![
            AccessControlAllowOrigin::Null,
        ]))
        .start_http(&"127.0.0.1:3030".parse().unwrap())
        .expect("Unable to start RPC server");

    server.wait();
}
