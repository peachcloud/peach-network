#[macro_use]
extern crate log;
extern crate get_if_addrs;
extern crate wpactrl;

mod error;
mod network;

use std::result::Result;

use jsonrpc_core::{types::error::Error, *};
use jsonrpc_http_server::*;
#[allow(unused_imports)]
use jsonrpc_test as test;
use serde_json::json;

use crate::error::{BoxError, NetworkError};
use crate::network::{Iface, WiFi};

pub fn run() -> Result<(), BoxError> {
    info!("Starting up.");

    info!("Creating JSON-RPC I/O handler.");
    let mut io = IoHandler::default();

    io.add_method("add_wifi", move |params: Params| {
        let w: Result<WiFi, Error> = params.parse();
        match w {
            Ok(_) => {
                let w: WiFi = w?;
                match network::add_wifi(&w) {
                    Ok(_) => Ok(Value::String("success".to_string())),
                    Err(_) => Err(Error::from(NetworkError::AddWifi { ssid: w.ssid })),
                }
            }
            Err(e) => Err(Error::from(NetworkError::MissingParams { e })),
        }
    });

    io.add_method("get_ip", move |params: Params| {
        let i: Result<Iface, Error> = params.parse();
        match i {
            Ok(_) => {
                let i: Iface = i?;
                let iface = i.iface.to_string();
                let ip = network::get_ip(&iface)?;
                match ip {
                    Some(ip) => Ok(Value::String(ip)),
                    None => Err(Error::from(NetworkError::NoIpFound { iface })),
                }
            }
            Err(e) => Err(Error::from(NetworkError::MissingParams { e })),
        }
    });

    io.add_method("get_ssid", move |params: Params| {
        let i: Result<Iface, Error> = params.parse();
        match i {
            Ok(_) => {
                let i: Iface = i?;
                let iface = i.iface.to_string();
                let ip = network::get_ssid(&iface)?;
                match ip {
                    Some(ip) => Ok(Value::String(ip)),
                    None => Err(Error::from(NetworkError::GetSsid { iface })),
                }
            }
            Err(e) => Err(Error::from(NetworkError::MissingParams { e })),
        }
    });

    io.add_method("if_checker", move |_| {
        network::run_iface_script()?;

        Ok(Value::String("success".to_string()))
    });

    io.add_method("list_networks", move |_| {
        let list = network::list_networks()?;
        match list {
            Some(list) => {
                let json_ssids = json!(list);
                Ok(Value::String(json_ssids.to_string()))
            }
            None => Err(Error::from(NetworkError::ListSavedNetworks)),
        }
    });

    io.add_method("scan_networks", move |params: Params| {
        let i: Result<Iface, Error> = params.parse();
        match i {
            Ok(_) => {
                let i: Iface = i?;
                let iface = i.iface.to_string();
                let list = network::scan_networks(&iface)?;
                match list {
                    Some(list) => {
                        let json_ssids = json!(list);
                        Ok(Value::String(json_ssids.to_string()))
                    }
                    None => Err(Error::from(NetworkError::ListScanResults { iface })),
                }
            }
            Err(e) => Err(Error::from(NetworkError::MissingParams { e })),
        }
    });

    io.add_method("reassociate_wifi", move |params: Params| {
        let i: Result<Iface, Error> = params.parse();
        match i {
            Ok(_) => {
                let i: Iface = i?;
                let iface = i.iface.to_string();
                match network::reassociate_wifi(&iface) {
                    Ok(_) => Ok(Value::String("success".to_string())),
                    Err(_) => Err(Error::from(NetworkError::Reassociate { iface })),
                }
            }
            Err(e) => Err(Error::from(NetworkError::MissingParams { e })),
        }
    });

    io.add_method("reconnect_wifi", move |params: Params| {
        let i: Result<Iface, Error> = params.parse();
        match i {
            Ok(_) => {
                let i: Iface = i?;
                let iface = i.iface.to_string();
                match network::reconnect_wifi(&iface) {
                    Ok(_) => Ok(Value::String("success".to_string())),
                    Err(_) => Err(Error::from(NetworkError::Reconnect { iface })),
                }
            }
            Err(e) => Err(Error::from(NetworkError::MissingParams { e })),
        }
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

    use jsonrpc_core::ErrorCode;
    use std::io::Error as IoError;
    use std::io::ErrorKind;

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

    // test to ensure correct parse error response for rpc parameters
    #[test]
    fn rpc_parse_error() {
        let rpc = {
            let mut io = IoHandler::new();
            io.add_method("rpc_parse_error", |_| {
                let e = Error {
                    code: ErrorCode::ParseError,
                    message: String::from("Parse error"),
                    data: None,
                };
                Err(Error::from(NetworkError::MissingParams { e }))
            });
            test::Rpc::from(io)
        };

        assert_eq!(
            rpc.request("rpc_parse_error", &()),
            r#"{
  "code": -32700,
  "message": "Parse error"
}"#
        );
    }

    // test to ensure correct addwifi error response
    #[test]
    fn rpc_addwifi_error() {
        let rpc = {
            let mut io = IoHandler::new();
            io.add_method("rpc_addwifi_error", |_| {
                Err(Error::from(NetworkError::AddWifi {
                    ssid: "Home".to_string(),
                }))
            });
            test::Rpc::from(io)
        };

        assert_eq!(
            rpc.request("rpc_addwifi_error", &()),
            r#"{
  "code": -32000,
  "message": "Failed to add network for Home"
}"#
        );
    }

    // test to ensure correct getip error response
    #[test]
    fn rpc_getip_error() {
        let rpc = {
            let mut io = IoHandler::new();
            io.add_method("rpc_getip_error", |_| {
                Err(Error::from(NetworkError::GetIp {
                    iface: "wlan7".to_string(),
                    source: IoError::new(ErrorKind::AddrNotAvailable, "oh no!"),
                }))
            });
            test::Rpc::from(io)
        };

        assert_eq!(
            rpc.request("rpc_getip_error", &()),
            r#"{
  "code": -32000,
  "message": "Failed to retrieve IP address for wlan7: oh no!"
}"#
        );
    }

    // test to ensure correct getssid error response
    #[test]
    fn rpc_getssid_error() {
        let rpc = {
            let mut io = IoHandler::new();
            io.add_method("rpc_getssid_error", |_| {
                Err(Error::from(NetworkError::GetSsid {
                    iface: "wlan0".to_string(),
                }))
            });
            test::Rpc::from(io)
        };

        assert_eq!(
            rpc.request("rpc_getssid_error", &()),
            r#"{
  "code": -32000,
  "message": "Failed to retrieve SSID for wlan0. Interface may not be connected"
}"#
        );
    }

    // test to ensure correct listsavednetworks error response
    #[test]
    fn rpc_listsavednetworks_error() {
        let rpc = {
            let mut io = IoHandler::new();
            io.add_method("rpc_listsavednetworks_error", |_| {
                Err(Error::from(NetworkError::ListSavedNetworks))
            });
            test::Rpc::from(io)
        };

        assert_eq!(
            rpc.request("rpc_listsavednetworks_error", &()),
            r#"{
  "code": -32000,
  "message": "No saved networks found"
}"#
        );
    }

    // test to ensure correct listscanresults error response
    #[test]
    fn rpc_listscanresults_error() {
        let rpc = {
            let mut io = IoHandler::new();
            io.add_method("rpc_listscanresults_error", |_| {
                Err(Error::from(NetworkError::ListScanResults {
                    iface: "wlan0".to_string(),
                }))
            });
            test::Rpc::from(io)
        };

        assert_eq!(
            rpc.request("rpc_listscanresults_error", &()),
            r#"{
  "code": -32000,
  "message": "No networks found in range of interface wlan0"
}"#
        );
    }

}
