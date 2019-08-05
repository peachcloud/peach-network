#[macro_use]
extern crate log;
extern crate get_if_addrs;
extern crate wpactrl;

mod error;
mod network;

use std::env;
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

    io.add_method("activate_ap", move |_| {
        network::activate_ap()?;

        Ok(Value::String("success".to_string()))
    });

    io.add_method("add_wifi", move |params: Params| {
        let w: Result<WiFi, Error> = params.parse();
        match w {
            Ok(w) => match network::add_wifi(&w) {
                Ok(_) => Ok(Value::String("success".to_string())),
                Err(_) => Err(Error::from(NetworkError::AddWifi { ssid: w.ssid })),
            },
            Err(e) => Err(Error::from(NetworkError::MissingParams { e })),
        }
    });

    io.add_method("get_ip", move |params: Params| {
        let i: Result<Iface, Error> = params.parse();
        match i {
            Ok(i) => {
                let iface = i.iface;
                match network::get_ip(&iface)? {
                    Some(ip) => Ok(Value::String(ip)),
                    None => Err(Error::from(NetworkError::NoIpFound { iface })),
                }
            }
            Err(e) => Err(Error::from(NetworkError::MissingParams { e })),
        }
    });

    io.add_method("get_rssi", move |params: Params| {
        let i: Result<Iface, Error> = params.parse();
        match i {
            Ok(i) => {
                let iface = i.iface;
                match network::get_rssi(&iface)? {
                    Some(rssi) => Ok(Value::String(rssi)),
                    None => Err(Error::from(NetworkError::GetRssi { iface })),
                }
            }
            Err(e) => Err(Error::from(NetworkError::MissingParams { e })),
        }
    });

    io.add_method("get_ssid", move |params: Params| {
        let i: Result<Iface, Error> = params.parse();
        match i {
            Ok(i) => {
                let iface = i.iface;
                match network::get_ssid(&iface)? {
                    Some(ip) => Ok(Value::String(ip)),
                    None => Err(Error::from(NetworkError::GetSsid { iface })),
                }
            }
            Err(e) => Err(Error::from(NetworkError::MissingParams { e })),
        }
    });

    io.add_method("get_traffic", move |params: Params| {
        let i: Result<Iface, Error> = params.parse();
        match i {
            Ok(i) => {
                let iface = i.iface;
                match network::get_traffic(&iface)? {
                    Some(traffic) => Ok(Value::String(traffic)),
                    None => Err(Error::from(NetworkError::GetTraffic { iface })),
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

    io.add_method("ping", |_: Params| Ok(Value::String("success".to_string())));

    io.add_method("scan_networks", move |params: Params| {
        let i: Result<Iface, Error> = params.parse();
        match i {
            Ok(i) => {
                let iface = i.iface;
                match network::scan_networks(&iface)? {
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
            Ok(i) => {
                let iface = i.iface;
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
            Ok(i) => {
                let iface = i.iface;
                match network::reconnect_wifi(&iface) {
                    Ok(_) => Ok(Value::String("success".to_string())),
                    Err(_) => Err(Error::from(NetworkError::Reconnect { iface })),
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
  "code": -32001,
  "message": "Failed to retrieve IP address for wlan7: oh no!"
}"#
        );
    }

    // test to ensure correct getrssi error response
    #[test]
    fn rpc_getrssi_error() {
        let rpc = {
            let mut io = IoHandler::new();
            io.add_method("rpc_getrssi_error", |_| {
                Err(Error::from(NetworkError::GetRssi {
                    iface: "wlan0".to_string(),
                }))
            });
            test::Rpc::from(io)
        };

        assert_eq!(
            rpc.request("rpc_getrssi_error", &()),
            r#"{
  "code": -32002,
  "message": "Failed to retrieve RSSI for wlan0. Interface may not be connected"
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
  "code": -32003,
  "message": "Failed to retrieve SSID for wlan0. Interface may not be connected"
}"#
        );
    }

    // test to ensure correct gettraffic error response
    #[test]
    fn rpc_gettraffic_error() {
        let rpc = {
            let mut io = IoHandler::new();
            io.add_method("rpc_gettraffic_error", |_| {
                Err(Error::from(NetworkError::GetTraffic {
                    iface: "wlan0".to_string(),
                }))
            });
            test::Rpc::from(io)
        };

        assert_eq!(
            rpc.request("rpc_gettraffic_error", &()),
            r#"{
  "code": -32004,
  "message": "No network traffic statistics found for wlan0. Interface may not exist"
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
  "code": -32005,
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
  "code": -32006,
  "message": "No networks found in range of wlan0"
}"#
        );
    }

    // test to ensure correct missingparams error response
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

    // test to ensure correct noipfound error response
    #[test]
    fn rpc_noipfound_error() {
        let rpc = {
            let mut io = IoHandler::new();
            io.add_method("rpc_noipfound_error", |_| {
                Err(Error::from(NetworkError::NoIpFound {
                    iface: "wlan0".to_string(),
                }))
            });
            test::Rpc::from(io)
        };

        assert_eq!(
            rpc.request("rpc_noipfound_error", &()),
            r#"{
  "code": -32007,
  "message": "No IP address found for wlan0"
}"#
        );
    }

    // test to ensure correct reassociate error response
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

    // test to ensure correct reconnect error response
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

    // test to ensure correct regex error response
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

    // test to ensure correct runapclientscript error response
    #[test]
    fn rpc_rrunapclientscript_error() {
        let rpc = {
            let mut io = IoHandler::new();
            io.add_method("rpc_runapclientscript_error", |_| {
                let source = IoError::new(ErrorKind::PermissionDenied, "oh no!");
                Err(Error::from(NetworkError::RunApClientScript { source }))
            });
            test::Rpc::from(io)
        };

        assert_eq!(
            rpc.request("rpc_runapclientscript_error", &()),
            r#"{
  "code": -32011,
  "message": "Failed to run interface_checker script: oh no!"
}"#
        );
    }

    // test to ensure correct SetWlanInterfaceDown error response
    #[test]
    fn rpc_setwlaninterfacedown_error() {
        let rpc = {
            let mut io = IoHandler::new();
            io.add_method("rpc_setwlaninterfacedown_error", |_| {
                let source = IoError::new(ErrorKind::PermissionDenied, "oh no!");
                Err(Error::from(NetworkError::SetWlanInterfaceDown { source }))
            });
            test::Rpc::from(io)
        };

        assert_eq!(
            rpc.request("rpc_setwlaninterfacedown_error", &()),
            r#"{
  "code": -32016,
  "message": "Failed to take wlan0 interface down: oh no!"
}"#
        );
    }

    // test to ensure correct StartDnsmasq error response
    #[test]
    fn rpc_startdnsmasq_error() {
        let rpc = {
            let mut io = IoHandler::new();
            io.add_method("rpc_startdnsmasq_error", |_| {
                let source = IoError::new(ErrorKind::PermissionDenied, "oh no!");
                Err(Error::from(NetworkError::StartDnsmasq { source }))
            });
            test::Rpc::from(io)
        };

        assert_eq!(
            rpc.request("rpc_startdnsmasq_error", &()),
            r#"{
  "code": -32018,
  "message": "Failed to start dnsmasq process: oh no!"
}"#
        );
    }

    // test to ensure correct StartHostapd error response
    #[test]
    fn rpc_starthostapd_error() {
        let rpc = {
            let mut io = IoHandler::new();
            io.add_method("rpc_starthostapd_error", |_| {
                let source = IoError::new(ErrorKind::PermissionDenied, "oh no!");
                Err(Error::from(NetworkError::StartHostapd { source }))
            });
            test::Rpc::from(io)
        };

        assert_eq!(
            rpc.request("rpc_starthostapd_error", &()),
            r#"{
  "code": -32017,
  "message": "Failed to start hostapd process: oh no!"
}"#
        );
    }

    // test to ensure correct StopWpaSupplicant error response
    #[test]
    fn rpc_stopwpasupplicant_error() {
        let rpc = {
            let mut io = IoHandler::new();
            io.add_method("rpc_stopwpasupplicant_error", |_| {
                let source = IoError::new(ErrorKind::PermissionDenied, "oh no!");
                Err(Error::from(NetworkError::StopWpaSupplicant { source }))
            });
            test::Rpc::from(io)
        };

        assert_eq!(
            rpc.request("rpc_stopwpasupplicant_error", &()),
            r#"{
  "code": -32015,
  "message": "Failed to stop wpasupplicant process: oh no!"
}"#
        );
    }

    // test to ensure correct wpactrlopen error response
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

    // test to ensure correct wpactrlrequest error response
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
