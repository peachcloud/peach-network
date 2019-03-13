extern crate failure;
extern crate get_if_addrs;

use failure::Fail;
use jsonrpc_http_server::jsonrpc_core::types::error::Error;
use jsonrpc_http_server::jsonrpc_core::*;
use jsonrpc_http_server::*;
use serde::Deserialize;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::process::{Command, Stdio};
use std::str;

// define the Iface struct for interface parameter
#[derive(Debug, Deserialize)]
struct Iface {
    iface: String,
}

// define the WiFi struct
#[derive(Debug, Deserialize)]
struct WiFi {
    ssid: String,
    pass: String,
}

#[derive(Debug, Fail)]
pub enum CallError {
    #[fail(display = "missing expected parameters")]
    MissingParams { e: Error },

    #[fail(display = "no ip found for given interface")]
    NoIpFound,

    #[fail(display = "ifdown command failed for given interface")]
    IfDownFailed,

    #[fail(display = "ifup command failed for given interface")]
    IfUpFailed,

    #[fail(display = "failed to add config for given wifi creds")]
    AddWifiFailed,

    #[fail(display = "failed to generate wpa_passphrase")]
    WpaPassGenFailed,

    #[fail(display = "failed to open file for writing")]
    FileOpenFailed,

    #[fail(display = "failed to run interface_checker script")]
    IfaceCheckerFailed,
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
            CallError::IfDownFailed => Error {
                code: ErrorCode::ServerError(-32001),
                message: "ifdown command failed for given interface".into(),
                data: None,
            },
            CallError::IfUpFailed => Error {
                code: ErrorCode::ServerError(-32002),
                message: "ifup command failed for given interface".into(),
                data: None,
            },
            CallError::AddWifiFailed => Error {
                code: ErrorCode::ServerError(-32003),
                message: "failed to add config for given wifi creds".into(),
                data: None,
            },
            CallError::WpaPassGenFailed => Error {
                code: ErrorCode::InternalError,
                message: "failed to generate wpa_passphrase".into(),
                data: None,
            },
            CallError::FileOpenFailed => Error {
                code: ErrorCode::InternalError,
                message: "failed to open wpa_supplicant.conf for write".into(),
                data: None,
            },
            CallError::IfaceCheckerFailed => Error {
                code: ErrorCode::InternalError,
                message: "failed to run interface_checker script".into(),
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

// generate wpa configuration for given ssid and password
fn gen_wifi_creds(wifi: WiFi) -> Result<String> {
    // run wpa_passphrase command and capture stdout
    let output = Command::new("wpa_passphrase")
        .arg(&wifi.ssid)
        .arg(&wifi.pass)
        .stdout(Stdio::piped())
        .output()
        .unwrap_or_else(|e| panic!("Failed to execute wpa_passphrase command: {}", e));

    let wpa_details = &*(output.stdout);

    // append wpa_passphrase output to wpa_supplicant.conf if successful
    if output.status.success() {
        // open file in append mode
        let file = OpenOptions::new()
            .append(true)
            .open("/etc/wpa_supplicant/wpa_supplicant.conf");

        match file {
            // if file exists and open succeeds, write wifi configuration
            Ok(mut f) => {
                f.write(wpa_details);
                Ok("success".to_string())
            }
            // need to handle this better: create file if not found
            //  and seed with 'ctrl_interface' and 'update_config' settings
            Err(_) => Err(Error::from(CallError::FileOpenFailed)),
        }
    } else {
        Err(Error::from(CallError::WpaPassGenFailed))
    }
}

fn main() {
    let mut io = IoHandler::default();

    io.add_method("add_wifi", move |params: Params| {
        // parse parameters and match on result
        let w: Result<WiFi> = params.parse();
        match w {
            // if result contains parameters, unwrap
            Ok(_) => {
                let w: WiFi = w.unwrap();
                let add = gen_wifi_creds(w);
                match add {
                    Ok(_) => Ok(Value::String("success".to_string())),
                    //Err(_) => Err(Error::from(CallError::AddWifiFailed))
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(Error::from(CallError::MissingParams { e })),
        }
    });

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

    io.add_method("if_checker", move |_| {
        let iface_checker = Command::new("sudo")
            .arg("/bin/bash")
            .arg("/home/glyph/interface_checker.sh")
            .output().unwrap_or_else(|e| {
                panic!("Failed to run interface_checker script: {}", e)
            });

        if iface_checker.status.success() {
            Ok(Value::String("success".to_string()))
        } else { Err(Error::from(CallError::IfaceCheckerFailed)) }
    });

    io.add_method("if_down", move |params: Params| {
        let i: Result<Iface> = params.parse();
        match i {
            // if result contains parameters, unwrap
            Ok(_) => {
                let i: Iface = i.unwrap();
                let iface = i.iface.to_string();
                let if_down = Command::new("sudo")
                    .arg("/sbin/ifdown")
                    .arg(iface)
                    .output()
                    .unwrap_or_else(|e| panic!("Failed to execute ifdown command: {}", e));

                if if_down.status.success() {
                    Ok(Value::String("success".to_string()))
                } else {
                    Err(Error::from(CallError::IfDownFailed))
                }
            }
            Err(e) => Err(Error::from(CallError::MissingParams { e })),
        }
    });

    io.add_method("if_up", move |params: Params| {
        let i: Result<Iface> = params.parse();
        match i {
            // if result contains parameters, unwrap
            Ok(_) => {
                let i: Iface = i.unwrap();
                let iface = i.iface.to_string();
                let if_up = Command::new("sudo")
                    .arg("/sbin/ifup")
                    .arg(iface)
                    .output()
                    .unwrap_or_else(|e| panic!("Failed to execute ifup command: {}", e));

                if if_up.status.success() {
                    Ok(Value::String("success".to_string()))
                } else {
                    Err(Error::from(CallError::IfUpFailed))
                }
            }
            Err(e) => Err(Error::from(CallError::MissingParams { e })),
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
