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
use crate::network::{Iface, WiFi}; //*

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

    io.add_method(
        "reassociate_wifi",
        move |_| match network::reassociate_wifi() {
            Ok(_) => Ok(Value::String("success".to_string())),
            Err(_) => Err(Error::from(NetworkError::ReassociateFailed)),
        },
    );

    io.add_method("reconnect_wifi", move |_| match network::reconnect_wifi() {
        Ok(_) => Ok(Value::String("success".to_string())),
        Err(_) => Err(Error::from(NetworkError::ReconnectFailed)),
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

    io.add_method("get_ip", move |params: Params| {
        // parse parameters and match on result
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

    io.add_method("get_ssid", move |_| {
        let ssid = network::get_ssid()?;
        match ssid {
            Some(ssid) => Ok(Value::String(ssid)),
            None => Ok(Value::String("not currently connected".to_string())),
        }
    });

    io.add_method("if_checker", move |_| {
        network::run_iface_script()?;

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
