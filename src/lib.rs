#[macro_use]
extern crate log;
extern crate get_if_addrs;
extern crate wpactrl;
extern crate regex;

use std::{process::Command, result::Result, error, str, io};

use snafu::{Snafu, ResultExt};

use jsonrpc_core::{*, types::error::Error};
use jsonrpc_http_server::*;

#[allow(unused_imports)]
use jsonrpc_test as test;

use serde::Deserialize;
use serde_json::json;

use regex::Regex;

pub type BoxError = Box<dyn error::Error>;

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

#[derive(Debug, Snafu)]
pub enum NetworkError {
    #[snafu(display("missing expected parameters"))]
    MissingParams { e: Error },

    #[snafu(display("No IP found for given interface: {}", iface))]
    NoIpFound {
        iface: String,
    },

    #[snafu(display("Could not access IP address for {}: {}", iface, source))]
    GetIp {
        iface: String,
        source: io::Error,
    },

    #[snafu(display("Request to wpasupplicant via wpactrl failed"))]
    WpaCtrlRequest { source: BoxError },

    #[snafu(display("Failed to open control interface for wpasupplicant"))]
    WpaCtrlOpen { source: BoxError },

    #[snafu(display("No networks found for given interface: {}", iface))]
    NoNetworksFound {
        iface: String,
    },

    #[snafu(display("failed to add config for given wifi creds"))]
    AddWifiFailed,

    #[snafu(display("failed to generate wpa_passphrase"))]
    WpaPassGenFailed,

    #[snafu(display("failed to open file for writing"))]
    FileOpenFailed,

    #[snafu(display("Failed to run interface_checker script: {}", source))]
    RunApClientScript {
        source: io::Error,
    },

    #[snafu(display("failed to reassociate with wifi connection"))]
    ReassociateFailed,

    #[snafu(display("failed to reconnect with wifi connection"))]
    ReconnectFailed,

    #[snafu(display("Regex command failed"))]
    RegexFailed {
        source: regex::Error,
    },
}

impl From<NetworkError> for Error {
    fn from(err: NetworkError) -> Self {
        match &err {
            NetworkError::MissingParams { e } => e.clone(),
            NetworkError::GetIp { iface, source }  => Error {
                code: ErrorCode::ServerError(-32000),
                message: format!("Failed to retrieve IP address for {}", iface),
                data: None,
            },
            NetworkError::WpaCtrlRequest { source } => Error {
                code: ErrorCode::ServerError(-32000),
                message: "WPA supplicant request failed".into(),
                data: None,
            },
            NetworkError::WpaCtrlOpen { source } => Error {
                code: ErrorCode::ServerError(-32000),
                message: "Failed to open control interface for wpasupplicant".into(),
                data: None,
            },
            NetworkError::RegexFailed { source } => Error {
                code: ErrorCode::ServerError(-32000),
                message: "Regex command error".into(),
                data: None,
            },
            NetworkError::NoIpFound { iface } => Error {
                code: ErrorCode::ServerError(-32000),
                message: format!("No IP address found for {}", iface),
                data: None,
            },
            NetworkError::NoNetworksFound { iface } => Error {
                code: ErrorCode::ServerError(-32000),
                message: format!("No networks found for {}", iface),
                data: None,
            },
            NetworkError::AddWifiFailed => Error {
                code: ErrorCode::ServerError(-32003),
                message: "failed to add config for given wifi creds".into(),
                data: None,
            },
            NetworkError::WpaPassGenFailed => Error {
                code: ErrorCode::InternalError,
                message: "failed to generate wpa_passphrase".into(),
                data: None,
            },
            NetworkError::FileOpenFailed => Error {
                code: ErrorCode::InternalError,
                message: "failed to open wpa_supplicant.conf for write".into(),
                data: None,
            },
            NetworkError::RunApClientScript { source } => Error {
                code: ErrorCode::InternalError,
                message: "Failed to run interface_checker script".into(),
                data: None,
            },
            NetworkError::ReassociateFailed => Error {
                code: ErrorCode::InternalError,
                message: "failed to reassociate with wifi network".into(),
                data: None,
            },
            NetworkError::ReconnectFailed => Error {
                code: ErrorCode::InternalError,
                message: "failed to reconnect with wifi network".into(),
                data: None,
            },
        }
    }
}

// retrieve ip address for specified interface
fn get_ip(iface: String) -> Result<Option<String>, NetworkError> {
    let net_if: String = iface.clone();
    let ifaces = get_if_addrs::get_if_addrs()
        .context(GetIp { iface: net_if })?;
    let ip = ifaces
        .iter()
        .find(|&i| i.name == iface)
        .map(|iface| iface.ip().to_string());

    Ok(ip)
}

// retrieve ssid of connected network
fn get_ssid() -> Result<Option<String>, NetworkError> {
    let mut wpa = wpactrl::WpaCtrl::new()
        .open()
        .map_err(|e| e.into())
        .context(WpaCtrlOpen)?;
    wpa.request("INTERFACE wlan0")
        .map_err(|e| e.into())
        .context(WpaCtrlRequest)?;
    let mut status = wpa
        .request("STATUS")
        .map_err(|e| e.into())
        .context(WpaCtrlRequest)?;
    let re = Regex::new(r"\nssid=(.*)\n").context(RegexFailed)?;
    let caps = re.captures(&status);
    let ssid = match caps {
        Some(caps) => {
            let ssid_name = &mut caps[0].to_string();
            let mut ssid = ssid_name.split_off(6);
            let len = ssid.len();
            ssid.truncate(len - 1);
            Some(ssid)
        },
        None => None
    };

    Ok(ssid)
}

// generate wpa configuration for given ssid and password
fn gen_wifi_creds(wifi: WiFi) -> Result<(), NetworkError> {
    let mut wpa = wpactrl::WpaCtrl::new()
        .open()
        .map_err(|e| e.into())
        .context(WpaCtrlOpen)?;
    wpa.request("INTERFACE wlan0")
        .map_err(|e| e.into())
        .context(WpaCtrlRequest)?;
    let mut net_id = wpa
        .request("ADD_NETWORK")
        .map_err(|e| e.into())
        .context(WpaCtrlRequest)?;
    let len = net_id.len();
    // remove newline character
    net_id.truncate(len - 1);
    let ssid_cmd = format!("SET_NETWORK {} ssid \"{}\"", net_id, &wifi.ssid);
    wpa.request(&ssid_cmd)
        .map_err(|e| e.into())
        .context(WpaCtrlRequest)?;
    let psk_cmd = format!("SET_NETWORK {} psk \"{}\"", net_id, &wifi.pass);
    wpa.request(&psk_cmd)
        .map_err(|e| e.into())
        .context(WpaCtrlRequest)?;
    let en_cmd = format!("ENABLE_NETWORK {}", net_id);
    wpa.request(&en_cmd)
        .map_err(|e| e.into())
        .context(WpaCtrlRequest)?;
    wpa.request("SET update_config 1")
        .map_err(|e| e.into())
        .context(WpaCtrlRequest)?;
    wpa.request("SAVE_CONFIG")
        .map_err(|e| e.into())
        .context(WpaCtrlRequest)?;
    Ok(())
}

// disconnect and reconnect the wireless interface
fn reconnect_wifi(iface: String) -> Result<(), NetworkError> {
    let mut wpa = wpactrl::WpaCtrl::new()
        .open()
        .map_err(|e| e.into())
        .context(WpaCtrlOpen)?;
    let select_iface = format!("INTERFACE {}", &iface);
    wpa.request(&select_iface)
        .map_err(|e| e.into())
        .context(WpaCtrlRequest)?;
    wpa.request("DISCONNECT")
        .map_err(|e| e.into())
        .context(WpaCtrlRequest)?;
    wpa.request("RECONNECT")
        .map_err(|e| e.into())
        .context(WpaCtrlRequest)?;
    Ok(())
}

// reassociate the wireless interface
fn reassociate_wifi(iface: String) -> Result<(), NetworkError> {
    let mut wpa = wpactrl::WpaCtrl::new()
        .open()
        .map_err(|e| e.into())
        .context(WpaCtrlOpen)?;
    let select_iface = format!("INTERFACE {}", &iface);
    wpa.request(&select_iface)
        .map_err(|e| e.into())
        .context(WpaCtrlRequest)?;
    wpa.request("REASSOCIATE")
        .map_err(|e| e.into())
        .context(WpaCtrlRequest)?;
    Ok(())
}

// run the interface checker script for ap-client mode switching
fn run_iface_script() -> Result<(), NetworkError> {
    let iface_checker = Command::new("sudo")
        .arg("/bin/bash")
        .arg("/home/glyph/interface_checker.sh")
        .output()
        .context(RunApClientScript)?;
    Ok(())
}

// list all wireless networks available to given interface
fn list_networks(iface: String) -> Result<Option<Vec<String>>, NetworkError> {
    let mut wpa = wpactrl::WpaCtrl::new()
        .open()
        .map_err(|e| e.into())
        .context(WpaCtrlOpen)?;
    let select_iface = format!("INTERFACE {}", &iface);
    // i have a sneaky suspicion this INTERFACE request is not doing anything
    wpa.request(&select_iface)
        .map_err(|e| e.into())
        .context(WpaCtrlRequest)?;
    let networks = wpa
        .request("LIST_NETWORKS")
        .map_err(|e| e.into())
        .context(WpaCtrlRequest)?;
    let mut ssids = Vec::new();
    for network in networks.lines() {
        let v : Vec<&str> = network.split('\t').collect();
        let len = v.len();
        if len > 1 {
            ssids.push(v[1].to_string());
        }
    }
    Ok(Some(ssids))
}
/*
 * Further functions to be implemented:
 *  - remove_network
 */

pub fn run() -> Result<(), BoxError> {
    info!("Starting up.");

    info!("Creating JSON-RPC I/O handler.");
    let mut io = IoHandler::default();

    io.add_method("add_wifi", move |params: Params| {
        let w: Result<WiFi, Error> = params.parse()?;
        let w: WiFi = w?;
        let add = gen_wifi_creds(w)?;
        Ok(Value::String("success".to_string()))
    });

    io.add_method("reassociate_wifi", move |params: Params| {
        let i: Result<Iface, Error> = params.parse();
        match i {
            // if result contains parameters, unwrap
            Ok(_) => {
                let i: Iface = i?;
                match reassociate_wifi(i.iface) {
                    Ok(_) => Ok(Value::String("success".to_string())),
                    Err(_) => Err(Error::from(NetworkError::ReassociateFailed))
                }
            }
            Err(e) => Err(Error::from(NetworkError::MissingParams { e })),
        }
    });

    io.add_method("reconnect_wifi", move |params: Params| {
        let i: Result<Iface, Error> = params.parse();
        match i {
            // if result contains parameters, unwrap
            Ok(_) => {
                let i: Iface = i?;
                match reconnect_wifi(i.iface) {
                    Ok(_) => Ok(Value::String("success".to_string())),
                    Err(_) => Err(Error::from(NetworkError::ReconnectFailed))
                }
            }
            Err(e) => Err(Error::from(NetworkError::MissingParams { e })),
        }
    });

    io.add_method("list_networks", move |params: Params| {
        let i: Result<Iface, Error> = params.parse();
        match i {
            // if result contains parameters, unwrap
            Ok(_) => {
                let i: Iface = i?;
                let iface = i.iface.to_string();
                let list = list_networks(iface)?;
                match list {
                    Some(list) => {
                        let json_ssids = json!(list);
                        Ok(Value::String(json_ssids.to_string()))
                    },
                    None => Err(Error::from(NetworkError::NoNetworksFound { iface }))
                }
            }
            Err(e) => Err(Error::from(NetworkError::MissingParams { e })),
        }
    });

    io.add_method("get_ip", move |params: Params| {
        // parse parameters and match on result
        let i: Result<Iface, Error> = params.parse();
        match i {
            Ok(_) => {
                let i: Iface = i?;
                let iface = i.iface.to_string();
                let ip = get_ip(iface)?;
                match ip {
                    Some(ip) => Ok(Value::String(ip)),
                    None => Err(Error::from(NetworkError::NoIpFound { iface })),
                }
            }
            Err(e) => Err(Error::from(NetworkError::MissingParams { e })),
        }
    });

    io.add_method("get_ssid", move |_| {
        let ssid = get_ssid()?;
        match ssid {
            Some(ssid) => Ok(Value::String(ssid)),
            None => Ok(Value::String("not currently connected".to_string())),
        }
    });

    io.add_method("if_checker", move |_| {
        let run_script = run_iface_script()?;

        Ok(Value::String("success".to_string()))
    });

    info!("Creating JSON-RPC server.");
    let server = ServerBuilder::new(io)
        .cors(DomainsValidation::AllowOnly(vec![
            AccessControlAllowOrigin::Null,
        ]))
        .start_http(&"127.0.0.1:5000".parse().unwrap())
        .expect("Unable to start RPC server");

    server.wait();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // test to ensure correct success response
    #[test]
    fn rpc_success() {
        let rpc = {
            let mut io = IoHandler::new();
            io.add_method("rpc_success_response", |_| {
                Ok(Value::String("success".into()))
            });
            test::Rpc::from(io)
        };

        assert_eq!(rpc.request("rpc_success_response", &()), r#""success""#);
    }
}
