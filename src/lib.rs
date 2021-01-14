//! # peach-network
//!
//! `peach-network` is a networking microservice module for PeachCloud. It
//! exposes a JSON-RPC API over HTTP which allows querying of network interface
//! data and modification of interface state.
//!
//! The `src/network.rs` module contains the core networking logic and data
//! types for interacting with the `wpa_supplicant` process and related parts of
//! the operating system, while the `src/error.rs` module contains
//! error-handling data types and methods.
//!
//! `src/main.rs` initializes the logger, starts the application and catches
//! application errors, while `src/lib.rs` contains the JSON-RPC server, RPC
//! methods, HTTP server and tests.
//!
mod error;
pub mod network;
mod utils;

use std::env;
use std::result::Result;

use jsonrpc_core::{types::error::Error, IoHandler, Params, Value};
use jsonrpc_http_server::{AccessControlAllowOrigin, DomainsValidation, ServerBuilder};
#[allow(unused_imports)]
use jsonrpc_test as test;
use log::info;
use serde_json::json;

use crate::error::{BoxError, NetworkError};
use crate::network::{Iface, IfaceId, IfaceIdPass, IfaceSsid, WiFi};

/// Create JSON-RPC I/O handler, add RPC methods and launch HTTP server.
pub fn run() -> Result<(), BoxError> {
    info!("Starting up.");

    info!("Creating JSON-RPC I/O handler.");
    let mut io = IoHandler::default();

    /* GET - All RPC methods for retrieving data */

    io.add_method("available_networks", move |params: Params| {
        let i: Result<Iface, Error> = params.parse();
        match i {
            Ok(i) => {
                let iface = i.iface;
                match network::available_networks(&iface)? {
                    Some(list) => Ok(Value::String(list)),
                    None => Err(Error::from(NetworkError::AvailableNetworks { iface })),
                }
            }
            Err(e) => Err(Error::from(NetworkError::MissingParams { e })),
        }
    });

    io.add_method("id", move |params: Params| {
        let i: Result<IfaceSsid, Error> = params.parse();
        match i {
            Ok(i) => {
                let iface = i.iface;
                let ssid = i.ssid;
                match network::id(&iface, &ssid)? {
                    Some(id) => Ok(Value::String(id)),
                    None => Err(Error::from(NetworkError::Id { iface, ssid })),
                }
            }
            Err(e) => Err(Error::from(NetworkError::MissingParams { e })),
        }
    });

    io.add_method("ip", move |params: Params| {
        let i: Result<Iface, Error> = params.parse();
        match i {
            Ok(i) => {
                let iface = i.iface;
                match network::ip(&iface)? {
                    Some(ip) => Ok(Value::String(ip)),
                    None => Err(Error::from(NetworkError::Ip { iface })),
                }
            }
            Err(e) => Err(Error::from(NetworkError::MissingParams { e })),
        }
    });

    io.add_method("ping", |_| Ok(Value::String("success".to_string())));

    io.add_method("rssi", move |params: Params| {
        let i: Result<Iface, Error> = params.parse();
        match i {
            Ok(i) => {
                let iface = i.iface;
                match network::rssi(&iface)? {
                    Some(rssi) => Ok(Value::String(rssi)),
                    None => Err(Error::from(NetworkError::Rssi { iface })),
                }
            }
            Err(e) => Err(Error::from(NetworkError::MissingParams { e })),
        }
    });

    io.add_method("rssi_percent", move |params: Params| {
        let i: Result<Iface, Error> = params.parse();
        match i {
            Ok(i) => {
                let iface = i.iface;
                match network::rssi_percent(&iface)? {
                    Some(rssi) => Ok(Value::String(rssi)),
                    None => Err(Error::from(NetworkError::RssiPercent { iface })),
                }
            }
            Err(e) => Err(Error::from(NetworkError::MissingParams { e })),
        }
    });

    io.add_method("saved_networks", move |_| {
        let list = network::saved_networks()?;
        match list {
            Some(list) => Ok(Value::String(list)),
            None => Err(Error::from(NetworkError::SavedNetworks)),
        }
    });

    io.add_method("ssid", move |params: Params| {
        let i: Result<Iface, Error> = params.parse();
        match i {
            Ok(i) => {
                let iface = i.iface;
                match network::ssid(&iface)? {
                    Some(ip) => Ok(Value::String(ip)),
                    None => Err(Error::from(NetworkError::Ssid { iface })),
                }
            }
            Err(e) => Err(Error::from(NetworkError::MissingParams { e })),
        }
    });

    io.add_method("state", move |params: Params| {
        let i: Result<Iface, Error> = params.parse();
        match i {
            Ok(i) => {
                let iface = i.iface;
                match network::state(&iface)? {
                    Some(state) => Ok(Value::String(state)),
                    None => Err(Error::from(NetworkError::State { iface })),
                }
            }
            Err(e) => Err(Error::from(NetworkError::MissingParams { e })),
        }
    });

    io.add_method("status", move |params: Params| {
        let i: Result<Iface, Error> = params.parse();
        match i {
            Ok(i) => {
                let iface = i.iface;
                match network::status(&iface)? {
                    Some(status) => {
                        let json_status = json!(status);
                        Ok(Value::String(json_status.to_string()))
                    }
                    None => Err(Error::from(NetworkError::Status { iface })),
                }
            }
            Err(e) => Err(Error::from(NetworkError::MissingParams { e })),
        }
    });

    io.add_method("traffic", move |params: Params| {
        let i: Result<Iface, Error> = params.parse();
        match i {
            Ok(i) => {
                let iface = i.iface;
                match network::traffic(&iface)? {
                    Some(traffic) => Ok(Value::String(traffic)),
                    None => Err(Error::from(NetworkError::Traffic { iface })),
                }
            }
            Err(e) => Err(Error::from(NetworkError::MissingParams { e })),
        }
    });

    /* SET - All RPC methods for modifying state */

    io.add_method("activate_ap", move |_| {
        network::activate_ap()?;

        Ok(Value::String("success".to_string()))
    });

    io.add_method("activate_client", move |_| {
        network::activate_client()?;

        Ok(Value::String("success".to_string()))
    });

    io.add_method("add", move |params: Params| {
        let w: Result<WiFi, Error> = params.parse();
        match w {
            Ok(w) => match network::add(&w) {
                Ok(_) => Ok(Value::String("success".to_string())),
                Err(_) => Err(Error::from(NetworkError::Add { ssid: w.ssid })),
            },
            Err(e) => Err(Error::from(NetworkError::MissingParams { e })),
        }
    });

    io.add_method("check_iface", move |_| {
        network::check_iface()?;

        Ok(Value::String("success".to_string()))
    });

    io.add_method("delete", move |params: Params| {
        let i: Result<IfaceId, Error> = params.parse();
        match i {
            Ok(i) => {
                let id = i.id;
                let iface = i.iface;
                match network::delete(&id, &iface) {
                    Ok(_) => Ok(Value::String("success".to_string())),
                    Err(_) => Err(Error::from(NetworkError::Delete { id, iface })),
                }
            }
            Err(e) => Err(Error::from(NetworkError::MissingParams { e })),
        }
    });

    io.add_method("disable", move |params: Params| {
        let i: Result<IfaceId, Error> = params.parse();
        match i {
            Ok(i) => {
                let id = i.id;
                let iface = i.iface;
                match network::disable(&id, &iface) {
                    Ok(_) => Ok(Value::String("success".to_string())),
                    Err(_) => Err(Error::from(NetworkError::Disable { id, iface })),
                }
            }
            Err(e) => Err(Error::from(NetworkError::MissingParams { e })),
        }
    });

    io.add_method("disconnect", move |params: Params| {
        let i: Result<Iface, Error> = params.parse();
        match i {
            Ok(i) => {
                let iface = i.iface;
                match network::disconnect(&iface) {
                    Ok(_) => Ok(Value::String("success".to_string())),
                    Err(_) => Err(Error::from(NetworkError::Disconnect { iface })),
                }
            }
            Err(e) => Err(Error::from(NetworkError::MissingParams { e })),
        }
    });

    io.add_method("modify", move |params: Params| {
        let i: Result<IfaceIdPass, Error> = params.parse();
        match i {
            Ok(i) => {
                let iface = i.iface;
                let id = i.id;
                let pass = i.pass;
                match network::modify(&iface, &id, &pass) {
                    Ok(_) => Ok(Value::String("success".to_string())),
                    Err(_) => Err(Error::from(NetworkError::Modify { iface, id })),
                }
            }
            Err(e) => Err(Error::from(NetworkError::MissingParams { e })),
        }
    });

    io.add_method("reassociate", move |params: Params| {
        let i: Result<Iface, Error> = params.parse();
        match i {
            Ok(i) => {
                let iface = i.iface;
                match network::reassociate(&iface) {
                    Ok(_) => Ok(Value::String("success".to_string())),
                    Err(_) => Err(Error::from(NetworkError::Reassociate { iface })),
                }
            }
            Err(e) => Err(Error::from(NetworkError::MissingParams { e })),
        }
    });

    io.add_method("reconfigure", move |_| match network::reconfigure() {
        Ok(_) => Ok(Value::String("success".to_string())),
        Err(_) => Err(Error::from(NetworkError::Reconfigure)),
    });

    io.add_method("reconnect", move |params: Params| {
        let i: Result<Iface, Error> = params.parse();
        match i {
            Ok(i) => {
                let iface = i.iface;
                match network::reconnect(&iface) {
                    Ok(_) => Ok(Value::String("success".to_string())),
                    Err(_) => Err(Error::from(NetworkError::Reconnect { iface })),
                }
            }
            Err(e) => Err(Error::from(NetworkError::MissingParams { e })),
        }
    });

    io.add_method("save", move |_| match network::save() {
        Ok(_) => Ok(Value::String("success".to_string())),
        Err(_) => Err(Error::from(NetworkError::Save)),
    });

    io.add_method("connect", move |params: Params| {
        let i: Result<IfaceId, Error> = params.parse();
        match i {
            Ok(i) => {
                let id = i.id;
                let iface = i.iface;
                match network::connect(&id, &iface) {
                    Ok(_) => Ok(Value::String("success".to_string())),
                    Err(_) => Err(Error::from(NetworkError::Connect { id, iface })),
                }
            }
            Err(e) => Err(Error::from(NetworkError::MissingParams { e })),
        }
    });

    let http_server =
        env::var("PEACH_NETWORK_SERVER").unwrap_or_else(|_| "127.0.0.1:5110".to_string());

    info!("Starting JSON-RPC server on {}.", http_server);
    let server = ServerBuilder::new(io)
        .cors(DomainsValidation::AllowOnly(vec![
            AccessControlAllowOrigin::Null,
        ]))
        .start_http(
            &http_server
                .parse()
                .expect("Invalid HTTP address and port combination"),
        )
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

    // test to ensure correct MissingParams parse error
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

    // test to ensure correct Add error response
    #[test]
    fn rpc_add_error() {
        let rpc = {
            let mut io = IoHandler::new();
            io.add_method("rpc_add_error", |_| {
                Err(Error::from(NetworkError::Add {
                    ssid: "Home".to_string(),
                }))
            });
            test::Rpc::from(io)
        };

        assert_eq!(
            rpc.request("rpc_add_error", &()),
            r#"{
  "code": -32000,
  "message": "Failed to add network for Home"
}"#
        );
    }

    // test to ensure correct Disable error response
    #[test]
    fn rpc_disable_error() {
        let rpc = {
            let mut io = IoHandler::new();
            io.add_method("rpc_disable_error", |_| {
                Err(Error::from(NetworkError::Disable {
                    id: "0".to_string(),
                    iface: "wlan0".to_string(),
                }))
            });
            test::Rpc::from(io)
        };

        assert_eq!(
            rpc.request("rpc_disable_error", &()),
            r#"{
  "code": -32029,
  "message": "Failed to disable network 0 for wlan0"
}"#
        );
    }

    // test to ensure correct Disconnect error response
    #[test]
    fn rpc_disconnect_error() {
        let rpc = {
            let mut io = IoHandler::new();
            io.add_method("rpc_disconnect_error", |_| {
                Err(Error::from(NetworkError::Disconnect {
                    iface: "wlan0".to_string(),
                }))
            });
            test::Rpc::from(io)
        };

        assert_eq!(
            rpc.request("rpc_disconnect_error", &()),
            r#"{
  "code": -32032,
  "message": "Failed to disconnect wlan0"
}"#
        );
    }

    // test to ensure correct GenWpaPassphrase error response
    #[test]
    fn rpc_genwpapassphrase_error() {
        let rpc = {
            let mut io = IoHandler::new();
            io.add_method("rpc_genwpapassphrase_error", |_| {
                Err(Error::from(NetworkError::GenWpaPassphrase {
                    ssid: "HomeWifi".to_string(),
                    source: IoError::new(ErrorKind::NotFound, "oh no!"),
                }))
            });
            test::Rpc::from(io)
        };

        assert_eq!(
            rpc.request("rpc_genwpapassphrase_error", &()),
            r#"{
  "code": -32025,
  "message": "Failed to generate wpa passphrase for HomeWifi: oh no!"
}"#
        );
    }

    // test to ensure correct Id error response
    #[test]
    fn rpc_id_error() {
        let rpc = {
            let mut io = IoHandler::new();
            io.add_method("rpc_id_error", |_| {
                Err(Error::from(NetworkError::Id {
                    iface: "wlan0".to_string(),
                    ssid: "Home".to_string(),
                }))
            });
            test::Rpc::from(io)
        };

        assert_eq!(
            rpc.request("rpc_id_error", &()),
            r#"{
  "code": -32026,
  "message": "No ID found for Home on interface wlan0"
}"#
        );
    }

    // test to ensure correct NoIp error response
    #[test]
    fn rpc_noip_error() {
        let rpc = {
            let mut io = IoHandler::new();
            io.add_method("rpc_noip_error", |_| {
                Err(Error::from(NetworkError::NoIp {
                    iface: "wlan7".to_string(),
                    source: IoError::new(ErrorKind::AddrNotAvailable, "oh no!"),
                }))
            });
            test::Rpc::from(io)
        };

        assert_eq!(
            rpc.request("rpc_noip_error", &()),
            r#"{
  "code": -32001,
  "message": "Failed to retrieve IP address for wlan7: oh no!"
}"#
        );
    }

    // test to ensure correct Rssi error response
    #[test]
    fn rpc_rssi_error() {
        let rpc = {
            let mut io = IoHandler::new();
            io.add_method("rpc_rssi_error", |_| {
                Err(Error::from(NetworkError::Rssi {
                    iface: "wlan0".to_string(),
                }))
            });
            test::Rpc::from(io)
        };

        assert_eq!(
            rpc.request("rpc_rssi_error", &()),
            r#"{
  "code": -32002,
  "message": "Failed to retrieve RSSI for wlan0. Interface may not be connected"
}"#
        );
    }

    // test to ensure correct RssiPercent error response
    #[test]
    fn rpc_rssipercent_error() {
        let rpc = {
            let mut io = IoHandler::new();
            io.add_method("rpc_rssipercent_error", |_| {
                Err(Error::from(NetworkError::RssiPercent {
                    iface: "wlan0".to_string(),
                }))
            });
            test::Rpc::from(io)
        };

        assert_eq!(
            rpc.request("rpc_rssipercent_error", &()),
            r#"{
  "code": -32034,
  "message": "Failed to retrieve signal quality (%) for wlan0. Interface may not be connected"
}"#
        );
    }

    // test to ensure correct Ssid error response
    #[test]
    fn rpc_ssid_error() {
        let rpc = {
            let mut io = IoHandler::new();
            io.add_method("rpc_ssid_error", |_| {
                Err(Error::from(NetworkError::Ssid {
                    iface: "wlan0".to_string(),
                }))
            });
            test::Rpc::from(io)
        };

        assert_eq!(
            rpc.request("rpc_ssid_error", &()),
            r#"{
  "code": -32003,
  "message": "Failed to retrieve SSID for wlan0. Interface may not be connected"
}"#
        );
    }

    // test to ensure correct State error response
    #[test]
    fn rpc_state_error() {
        let rpc = {
            let mut io = IoHandler::new();
            io.add_method("rpc_state_error", |_| {
                Err(Error::from(NetworkError::State {
                    iface: "wlan1".to_string(),
                }))
            });
            test::Rpc::from(io)
        };

        assert_eq!(
            rpc.request("rpc_state_error", &()),
            r#"{
  "code": -32023,
  "message": "No state found for wlan1. Interface may not exist"
}"#
        );
    }

    // test to ensure correct Traffic error response
    #[test]
    fn rpc_traffic_error() {
        let rpc = {
            let mut io = IoHandler::new();
            io.add_method("rpc_traffic_error", |_| {
                Err(Error::from(NetworkError::Traffic {
                    iface: "wlan0".to_string(),
                }))
            });
            test::Rpc::from(io)
        };

        assert_eq!(
            rpc.request("rpc_traffic_error", &()),
            r#"{
  "code": -32004,
  "message": "No network traffic statistics found for wlan0. Interface may not exist"
}"#
        );
    }

    // test to ensure correct SavedNetworks error response
    #[test]
    fn rpc_savednetworks_error() {
        let rpc = {
            let mut io = IoHandler::new();
            io.add_method("rpc_savednetworks_error", |_| {
                Err(Error::from(NetworkError::SavedNetworks))
            });
            test::Rpc::from(io)
        };

        assert_eq!(
            rpc.request("rpc_savednetworks_error", &()),
            r#"{
  "code": -32005,
  "message": "No saved networks found"
}"#
        );
    }

    // test to ensure correct AvailableNetworks error response
    #[test]
    fn rpc_availablenetworks_error() {
        let rpc = {
            let mut io = IoHandler::new();
            io.add_method("rpc_availablenetworks_error", |_| {
                Err(Error::from(NetworkError::AvailableNetworks {
                    iface: "wlan0".to_string(),
                }))
            });
            test::Rpc::from(io)
        };

        assert_eq!(
            rpc.request("rpc_availablenetworks_error", &()),
            r#"{
  "code": -32006,
  "message": "No networks found in range of wlan0"
}"#
        );
    }

    // test to ensure correct MissingParams error response
    #[test]
    fn rpc_missingparams_error() {
        let rpc = {
            let mut io = IoHandler::new();
            io.add_method("rpc_missingparams_error", |_| {
                let e = Error {
                    code: ErrorCode::InvalidParams,
                    message: String::from(
                        "Invalid params: invalid type: null, expected struct Iface.",
                    ),
                    data: None,
                };
                Err(Error::from(NetworkError::MissingParams { e }))
            });
            test::Rpc::from(io)
        };

        assert_eq!(
            rpc.request("rpc_missingparams_error", &()),
            r#"{
  "code": -32602,
  "message": "Invalid params: invalid type: null, expected struct Iface."
}"#
        );
    }

    // test to ensure correct Modify error response
    #[test]
    fn rpc_modify_error() {
        let rpc = {
            let mut io = IoHandler::new();
            io.add_method("rpc_modify_error", |_| {
                Err(Error::from(NetworkError::Modify {
                    id: "1".to_string(),
                    iface: "wlan0".to_string(),
                }))
            });
            test::Rpc::from(io)
        };

        assert_eq!(
            rpc.request("rpc_modify_error", &()),
            r#"{
  "code": -32033,
  "message": "Failed to set new password for network 1 on wlan0"
}"#
        );
    }

    // test to ensure correct Ip error response
    #[test]
    fn rpc_ip_error() {
        let rpc = {
            let mut io = IoHandler::new();
            io.add_method("rpc_ip_error", |_| {
                Err(Error::from(NetworkError::Ip {
                    iface: "wlan0".to_string(),
                }))
            });
            test::Rpc::from(io)
        };

        assert_eq!(
            rpc.request("rpc_ip_error", &()),
            r#"{
  "code": -32007,
  "message": "No IP address found for wlan0"
}"#
        );
    }

    // test to ensure correct Reassociate error response
    #[test]
    fn rpc_reassociate_error() {
        let rpc = {
            let mut io = IoHandler::new();
            io.add_method("rpc_reassociate_error", |_| {
                Err(Error::from(NetworkError::Reassociate {
                    iface: "wlan0".to_string(),
                }))
            });
            test::Rpc::from(io)
        };

        assert_eq!(
            rpc.request("rpc_reassociate_error", &()),
            r#"{
  "code": -32008,
  "message": "Failed to reassociate with WiFi network for wlan0"
}"#
        );
    }

    // test to ensure correct Reconfigure error response
    #[test]
    fn rpc_reconfigure_error() {
        let rpc = {
            let mut io = IoHandler::new();
            io.add_method("rpc_reconfigure_error", |_| {
                Err(Error::from(NetworkError::Reconfigure))
            });
            test::Rpc::from(io)
        };

        assert_eq!(
            rpc.request("rpc_reconfigure_error", &()),
            r#"{
  "code": -32030,
  "message": "Failed to force reread of wpa_supplicant configuration file"
}"#
        );
    }

    // test to ensure correct Connect error response
    #[test]
    fn rpc_connect_error() {
        let rpc = {
            let mut io = IoHandler::new();
            io.add_method("rpc_connect_error", |_| {
                Err(Error::from(NetworkError::Connect {
                    id: "0".to_string(),
                    iface: "wlan0".to_string(),
                }))
            });
            test::Rpc::from(io)
        };

        assert_eq!(
            rpc.request("rpc_connect_error", &()),
            r#"{
  "code": -32027,
  "message": "Failed to connect to network 0 for wlan0"
}"#
        );
    }

    // test to ensure correct Reconnect error response
    #[test]
    fn rpc_reconnect_error() {
        let rpc = {
            let mut io = IoHandler::new();
            io.add_method("rpc_reconnect_error", |_| {
                Err(Error::from(NetworkError::Reconnect {
                    iface: "wlan0".to_string(),
                }))
            });
            test::Rpc::from(io)
        };

        assert_eq!(
            rpc.request("rpc_reconnect_error", &()),
            r#"{
  "code": -32009,
  "message": "Failed to reconnect with WiFi network for wlan0"
}"#
        );
    }

    // test to ensure correct Regex error response
    #[test]
    fn rpc_regex_error() {
        let rpc = {
            let mut io = IoHandler::new();
            io.add_method("rpc_regex_error", |_| {
                let source = regex::Error::Syntax("oh no!".to_string());
                Err(Error::from(NetworkError::Regex { source }))
            });
            test::Rpc::from(io)
        };

        assert_eq!(
            rpc.request("rpc_regex_error", &()),
            r#"{
  "code": -32010,
  "message": "Regex command error: oh no!"
}"#
        );
    }

    // test to ensure correct Delete error response
    #[test]
    fn rpc_delete_error() {
        let rpc = {
            let mut io = IoHandler::new();
            io.add_method("rpc_delete_error", |_| {
                Err(Error::from(NetworkError::Delete {
                    id: "0".to_string(),
                    iface: "wlan0".to_string(),
                }))
            });
            test::Rpc::from(io)
        };

        assert_eq!(
            rpc.request("rpc_delete_error", &()),
            r#"{
  "code": -32028,
  "message": "Failed to delete network 0 for wlan0"
}"#
        );
    }

    // test to ensure correct CheckIface error response
    #[test]
    fn rpc_checkiface_error() {
        let rpc = {
            let mut io = IoHandler::new();
            io.add_method("rpc_checkiface_error", |_| {
                let source = IoError::new(ErrorKind::PermissionDenied, "oh no!");
                Err(Error::from(NetworkError::CheckIface { source }))
            });
            test::Rpc::from(io)
        };

        assert_eq!(
            rpc.request("rpc_checkiface_error", &()),
            r#"{
  "code": -32011,
  "message": "Failed to run interface_checker script: oh no!"
}"#
        );
    }

    // test to ensure correct Save error response
    #[test]
    fn rpc_save_error() {
        let rpc = {
            let mut io = IoHandler::new();
            io.add_method("rpc_save_error", |_| Err(Error::from(NetworkError::Save)));
            test::Rpc::from(io)
        };

        assert_eq!(
            rpc.request("rpc_save_error", &()),
            r#"{
  "code": -32031,
  "message": "Failed to save configuration changes to file"
}"#
        );
    }

    // test to ensure correct WpaCtrlOpen error response
    #[test]
    fn rpc_wpactrlopen_error() {
        let rpc = {
            let mut io = IoHandler::new();
            io.add_method("rpc_wpactrlopen_error", |_| {
                let fail_err = failure::err_msg("Permission denied (os error 13)").compat();
                let source = Box::new(fail_err);
                Err(Error::from(NetworkError::WpaCtrlOpen { source }))
            });
            test::Rpc::from(io)
        };

        assert_eq!(
            rpc.request("rpc_wpactrlopen_error", &()),
            r#"{
  "code": -32013,
  "message": "Failed to open control interface for wpasupplicant: Permission denied (os error 13)"
}"#
        );
    }

    // test to ensure correct WpaCtrlRequest error response
    #[test]
    fn rpc_wpactrlrequest_error() {
        let rpc = {
            let mut io = IoHandler::new();
            io.add_method("rpc_wpactrlrequest_error", |_| {
                let fail_err = failure::err_msg("oh no!").compat();
                let source = Box::new(fail_err);
                Err(Error::from(NetworkError::WpaCtrlRequest { source }))
            });
            test::Rpc::from(io)
        };

        assert_eq!(
            rpc.request("rpc_wpactrlrequest_error", &()),
            r#"{
  "code": -32014,
  "message": "WPA supplicant request failed: oh no!"
}"#
        );
    }
}
