#[macro_use]
extern crate log;
extern crate get_if_addrs;
extern crate regex;
extern crate wpactrl;

use std::{error, io, process::Command, result::Result, str};

use snafu::{ResultExt, Snafu};

use jsonrpc_core::{types::error::Error, *};
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
    #[snafu(display("Failed to add network for {}", ssid))]
    AddWifi { ssid: String },

    #[snafu(display("Missing expected parameters: {}", e))]
    MissingParams { e: Error },

    #[snafu(display("No IP found for interface: {}", iface))]
    NoIpFound { iface: String },

    #[snafu(display("Could not access IP address for interface: {}", iface))]
    GetIp { iface: String, source: io::Error },

    #[snafu(display("Request to wpasupplicant via wpactrl failed"))]
    WpaCtrlRequest {
        #[snafu(source(from(failure::Error, std::convert::Into::into)))]
        source: BoxError,
    },

    #[snafu(display("Failed to open control interface for wpasupplicant"))]
    WpaCtrlOpen {
        #[snafu(source(from(failure::Error, std::convert::Into::into)))]
        source: BoxError,
    },

    #[snafu(display("No saved networks found for default interface"))]
    ListSavedNetworks,

    #[snafu(display("Failed to run interface_checker script: {}", source))]
    RunApClientScript { source: io::Error },

    #[snafu(display("Failed to reassociate with WiFi network"))]
    ReassociateFailed,

    #[snafu(display("Failed to reconnect with WiFi network"))]
    ReconnectFailed,

    #[snafu(display("Regex command failed"))]
    RegexFailed { source: regex::Error },
}

impl From<NetworkError> for Error {
    fn from(err: NetworkError) -> Self {
        match &err {
            NetworkError::MissingParams { e } => e.clone(),
            NetworkError::AddWifi { ssid } => Error {
                code: ErrorCode::ServerError(-32000),
                message: format!("Failed to add network for {}", ssid),
                data: None,
            },
            NetworkError::GetIp { iface, source } => Error {
                code: ErrorCode::ServerError(-32000),
                message: format!("Failed to retrieve IP address for {}: {}", iface, source),
                data: None,
            },
            NetworkError::WpaCtrlRequest { source } => Error {
                code: ErrorCode::ServerError(-32000),
                message: format!("WPA supplicant request failed: {}", source),
                data: None,
            },
            NetworkError::WpaCtrlOpen { source } => Error {
                code: ErrorCode::ServerError(-32000),
                message: format!(
                    "Failed to open control interface for wpasupplicant: {}",
                    source
                ),
                data: None,
            },
            NetworkError::RegexFailed { source } => Error {
                code: ErrorCode::ServerError(-32000),
                message: format!("Regex command error: {}", source),
                data: None,
            },
            NetworkError::NoIpFound { iface } => Error {
                code: ErrorCode::ServerError(-32000),
                message: format!("No IP address found for {}", iface),
                data: None,
            },
            NetworkError::ListSavedNetworks => Error {
                code: ErrorCode::ServerError(-32000),
                message: format!("No saved networks found"),
                data: None,
            },
            NetworkError::RunApClientScript { source } => Error {
                code: ErrorCode::InternalError,
                message: format!("Failed to run interface_checker script: {}", source),
                data: None,
            },
            NetworkError::ReassociateFailed => Error {
                code: ErrorCode::InternalError,
                message: format!("Failed to reassociate with WiFi network"),
                data: None,
            },
            NetworkError::ReconnectFailed => Error {
                code: ErrorCode::InternalError,
                message: format!("Failed to reconnect with WiFi network"),
                data: None,
            },
        }
    }
}

// retrieve ip address for specified interface
fn get_ip(iface: &str) -> Result<Option<String>, NetworkError> {
    let net_if: String = iface.to_string();
    let ifaces = get_if_addrs::get_if_addrs().context(GetIp { iface: net_if })?;
    let ip = ifaces
        .iter()
        .find(|&i| i.name == iface)
        .map(|iface| iface.ip().to_string());

    Ok(ip)
}

// retrieve ssid of connected network
fn get_ssid() -> Result<Option<String>, NetworkError> {
    let mut wpa = wpactrl::WpaCtrl::new().open().context(WpaCtrlOpen)?;
    let status = wpa.request("STATUS").context(WpaCtrlRequest)?;
    let re = Regex::new(r"\nssid=(.*)\n").context(RegexFailed)?;
    let caps = re.captures(&status);
    let ssid = match caps {
        Some(caps) => {
            let ssid_name = &mut caps[0].to_string();
            let mut ssid = ssid_name.split_off(6);
            let len = ssid.len();
            ssid.truncate(len - 1);
            Some(ssid)
        }
        None => None,
    };

    Ok(ssid)
}

// add network and save configuration for given ssid and password
fn add_wifi(wifi: &WiFi) -> Result<(), NetworkError> {
    let mut wpa = wpactrl::WpaCtrl::new().open().context(WpaCtrlOpen)?;
    let mut net_id = wpa.request("ADD_NETWORK").context(WpaCtrlRequest)?;
    let len = net_id.len();
    // remove newline character
    net_id.truncate(len - 1);
    let ssid_cmd = format!("SET_NETWORK {} ssid \"{}\"", net_id, &wifi.ssid);
    wpa.request(&ssid_cmd).context(WpaCtrlRequest)?;
    let psk_cmd = format!("SET_NETWORK {} psk \"{}\"", net_id, &wifi.pass);
    wpa.request(&psk_cmd).context(WpaCtrlRequest)?;
    let en_cmd = format!("ENABLE_NETWORK {}", net_id);
    wpa.request(&en_cmd).context(WpaCtrlRequest)?;
    wpa.request("SET update_config 1").context(WpaCtrlRequest)?;
    wpa.request("SAVE_CONFIG").context(WpaCtrlRequest)?;
    Ok(())
}

// disconnect and reconnect the wireless interface
fn reconnect_wifi() -> Result<(), NetworkError> {
    let mut wpa = wpactrl::WpaCtrl::new().open().context(WpaCtrlOpen)?;
    wpa.request("DISCONNECT").context(WpaCtrlRequest)?;
    wpa.request("RECONNECT").context(WpaCtrlRequest)?;
    Ok(())
}

// reassociate the wireless interface
fn reassociate_wifi() -> Result<(), NetworkError> {
    let mut wpa = wpactrl::WpaCtrl::new().open().context(WpaCtrlOpen)?;
    wpa.request("REASSOCIATE").context(WpaCtrlRequest)?;
    Ok(())
}

// run the interface checker script for ap-client mode switching
fn run_iface_script() -> Result<(), NetworkError> {
    Command::new("sudo")
        .arg("/bin/bash")
        .arg("/home/glyph/interface_checker.sh")
        .output()
        .context(RunApClientScript)?;
    Ok(())
}

// list all wireless networks saved to the wpasupplicant config
fn list_networks() -> Result<Option<Vec<String>>, NetworkError> {
    let mut wpa = wpactrl::WpaCtrl::new().open().context(WpaCtrlOpen)?;
    let networks = wpa.request("LIST_NETWORKS").context(WpaCtrlRequest)?;
    let mut ssids = Vec::new();
    for network in networks.lines() {
        let v: Vec<&str> = network.split('\t').collect();
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
 *  - scan_networks
 */

pub fn run() -> Result<(), BoxError> {
    info!("Starting up.");

    info!("Creating JSON-RPC I/O handler.");
    let mut io = IoHandler::default();

    io.add_method("add_wifi", move |params: Params| {
        let w: Result<WiFi, Error> = params.parse();
        match w {
            Ok(_) => {
                let w: WiFi = w?;
                match add_wifi(&w) {
                    Ok(_) => Ok(Value::String("success".to_string())),
                    Err(_) => Err(Error::from(NetworkError::AddWifi { ssid: w.ssid })),
                }
            }
            Err(e) => Err(Error::from(NetworkError::MissingParams { e })),
        }
    });

    io.add_method("reassociate_wifi", move |_| match reassociate_wifi() {
        Ok(_) => Ok(Value::String("success".to_string())),
        Err(_) => Err(Error::from(NetworkError::ReassociateFailed)),
    });

    io.add_method("reconnect_wifi", move |_| match reconnect_wifi() {
        Ok(_) => Ok(Value::String("success".to_string())),
        Err(_) => Err(Error::from(NetworkError::ReconnectFailed)),
    });

    io.add_method("list_networks", move |_| {
        let list = list_networks()?;
        match list {
            Some(list) => {
                let json_ssids = json!(list);
                Ok(Value::String(json_ssids.to_string()))
            }
            None => Err(Error::from(NetworkError::ListSavedNetworks)),
        }
    });

    io.add_method("get_ip", move |params: Params| {
        // parse parameters and match on result
        let i: Result<Iface, Error> = params.parse();
        match i {
            Ok(_) => {
                let i: Iface = i?;
                let iface = i.iface.to_string();
                let ip = get_ip(&iface)?;
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
        run_iface_script()?;

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
