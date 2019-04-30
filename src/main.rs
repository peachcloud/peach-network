extern crate failure;
extern crate get_if_addrs;
extern crate wpactrl;
extern crate regex;

use std::process::Command;
use std::str;

use failure::Fail;

use jsonrpc_http_server::jsonrpc_core::types::error::Error;
use jsonrpc_http_server::jsonrpc_core::*;
use jsonrpc_http_server::*;

use serde::Deserialize;

use regex::Regex;

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

    #[fail(display = "failed to add config for given wifi creds")]
    AddWifiFailed,

    #[fail(display = "failed to generate wpa_passphrase")]
    WpaPassGenFailed,

    #[fail(display = "failed to open file for writing")]
    FileOpenFailed,

    #[fail(display = "failed to run interface_checker script")]
    IfaceCheckerFailed,

    #[fail(display = "wpa request failed")]
    WpaRequestFailed,
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
            CallError::WpaRequestFailed => Error {
                code: ErrorCode::InternalError,
                message: "failed to execute wpa supplicant request".into(),
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
    let mut wpa = wpactrl::WpaCtrl::new().open()
        .expect("failed to open connection to wpasupplicant");
    wpa.request("INTERFACE wlan0").unwrap();
    let status = wpa.request("STATUS").unwrap();
    let re = Regex::new(r"\nssid=(.*)\n").unwrap();
    let caps = re.captures(&status);
    match caps {
        Some(caps) => {
            let ssid_name = &mut caps[0].to_string();
            let mut ssid = ssid_name.split_off(6);
            let len = ssid.len();
            ssid.truncate(len - 1);
            Some(ssid)
        },
        None => None
    }
}

// generate wpa configuration for given ssid and password
fn gen_wifi_creds(wifi: WiFi) -> Result<()> {
    let mut wpa = wpactrl::WpaCtrl::new().open()
        .expect("failed to open connection to wpasupplicant");
    wpa.request("INTERFACE wlan0").unwrap();
    let mut net_id = wpa.request("ADD_NETWORK").unwrap();
    let len = net_id.len();
    // remove newline character
    net_id.truncate(len - 1);
    let ssid_cmd = format!("SET_NETWORK {} ssid \"{}\"", net_id, &wifi.ssid);
    wpa.request(&ssid_cmd).unwrap();
    let psk_cmd = format!("SET_NETWORK {} psk \"{}\"", net_id, &wifi.pass);
    wpa.request(&psk_cmd).unwrap();
    let en_cmd = format!("ENABLE_NETWORK {}", net_id);
    wpa.request(&en_cmd).unwrap();
    wpa.request("SET update_config 1").unwrap();
    wpa.request("SAVE_CONFIG").unwrap();
    Ok(())
}

// disconnect and reconnect the wireless interface
fn reconnect_wifi(iface: String) -> Result<()> {
    let mut wpa = wpactrl::WpaCtrl::new().open()
        .expect("failed to open connection to wpasupplicant");
    let select_iface = format!("INTERFACE {}", &iface);
    wpa.request(&select_iface).unwrap();
    wpa.request("DISCONNECT").unwrap();
    wpa.request("RECONNECT").unwrap();
    Ok(())
}

// reassociate the wireless interface
fn reassociate_wifi(iface: String) -> Result<()> {
    let mut wpa = wpactrl::WpaCtrl::new().open()
        .expect("failed to open connection to wpasupplicant");
    let select_iface = format!("INTERFACE {}", &iface);
    wpa.request(&select_iface).unwrap();
    wpa.request("REASSOCIATE").unwrap();
    Ok(())
}

/*
 * Further functions to be implemented:
 *  - list_networks
 *  - remove_network
 */

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

    io.add_method("reassociate_wifi", move |params: Params| {
        let i: Result<Iface> = params.parse();
        match i {
            // if result contains parameters, unwrap
            Ok(_) => {
                let i: Iface = i.unwrap();
                match reassociate_wifi(i.iface) {
                    Ok(_) => Ok(Value::String("success".to_string())),
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(Error::from(CallError::MissingParams { e })),
        }
    });

    io.add_method("reconnect_wifi", move |params: Params| {
        let i: Result<Iface> = params.parse();
        match i {
            // if result contains parameters, unwrap
            Ok(_) => {
                let i: Iface = i.unwrap();
                match reconnect_wifi(i.iface) {
                    Ok(_) => Ok(Value::String("success".to_string())),
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

    let server = ServerBuilder::new(io)
        .cors(DomainsValidation::AllowOnly(vec![
            AccessControlAllowOrigin::Null,
        ]))
        .start_http(&"127.0.0.1:5000".parse().unwrap())
        .expect("Unable to start RPC server");

    server.wait();
}
