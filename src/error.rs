use std::{error, io, str};

use jsonrpc_core::{types::error::Error, ErrorCode};
use probes::ProbeError;
use serde_json::error::Error as SerdeError;
use snafu::Snafu;

pub type BoxError = Box<dyn error::Error>;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum NetworkError {
    #[snafu(display("Failed to add network for {}", ssid))]
    AddWifi { ssid: String },

    #[snafu(display("Could not access IP address for interface: {}", iface))]
    GetIp { iface: String, source: io::Error },

    #[snafu(display("Could not find RSSI for interface: {}", iface))]
    GetRssi { iface: String },

    #[snafu(display("Could not find SSID for interface: {}", iface))]
    GetSsid { iface: String },

    #[snafu(display("Could not find network traffic for interface: {}", iface))]
    GetTraffic { iface: String },

    #[snafu(display("No saved networks found for default interface"))]
    ListSavedNetworks,

    #[snafu(display("No networks found in range of interface: {}", iface))]
    ListScanResults { iface: String },

    #[snafu(display("Missing expected parameters: {}", e))]
    MissingParams { e: Error },

    #[snafu(display("No IP found for interface: {}", iface))]
    NoIpFound { iface: String },

    #[snafu(display(
        "Failed to retrieve network traffic measurement for {}: {}",
        iface,
        source
    ))]
    ReadTraffic { iface: String, source: ProbeError },

    #[snafu(display("Failed to reassociate with WiFi network for interface: {}", iface))]
    Reassociate { iface: String },

    #[snafu(display("Failed to reconnect with WiFi network for interface: {}", iface))]
    Reconnect { iface: String },

    #[snafu(display("Regex command failed"))]
    Regex { source: regex::Error },

    #[snafu(display("Failed to run interface_checker script: {}", source))]
    RunApClientScript { source: io::Error },

    #[snafu(display("JSON serialization failed"))]
    SerdeSerialize { source: SerdeError },

    #[snafu(display("Failed to open control interface for wpasupplicant"))]
    WpaCtrlOpen {
        #[snafu(source(from(failure::Error, std::convert::Into::into)))]
        source: BoxError,
    },

    #[snafu(display("Request to wpasupplicant via wpactrl failed"))]
    WpaCtrlRequest {
        #[snafu(source(from(failure::Error, std::convert::Into::into)))]
        source: BoxError,
    },
}

impl From<NetworkError> for Error {
    fn from(err: NetworkError) -> Self {
        match &err {
            NetworkError::AddWifi { ssid } => Error {
                code: ErrorCode::ServerError(-32000),
                message: format!("Failed to add network for {}", ssid),
                data: None,
            },
            NetworkError::GetIp { iface, source } => Error {
                code: ErrorCode::ServerError(-32001),
                message: format!("Failed to retrieve IP address for {}: {}", iface, source),
                data: None,
            },
            NetworkError::GetRssi { iface } => Error {
                code: ErrorCode::ServerError(-32002),
                message: format!(
                    "Failed to retrieve RSSI for {}. Interface may not be connected",
                    iface
                ),
                data: None,
            },
            NetworkError::GetSsid { iface } => Error {
                code: ErrorCode::ServerError(-32003),
                message: format!(
                    "Failed to retrieve SSID for {}. Interface may not be connected",
                    iface
                ),
                data: None,
            },
            NetworkError::GetTraffic { iface } => Error {
                code: ErrorCode::ServerError(-32004),
                message: format!(
                    "No network traffic statistics found for {}. Interface may not exist",
                    iface
                ),
                data: None,
            },
            NetworkError::ListSavedNetworks => Error {
                code: ErrorCode::ServerError(-32005),
                message: "No saved networks found".to_string(),
                data: None,
            },
            NetworkError::ListScanResults { iface } => Error {
                code: ErrorCode::ServerError(-32006),
                message: format!("No networks found in range of {}", iface),
                data: None,
            },
            NetworkError::MissingParams { e } => e.clone(),
            NetworkError::NoIpFound { iface } => Error {
                code: ErrorCode::ServerError(-32007),
                message: format!("No IP address found for {}", iface),
                data: None,
            },
            NetworkError::ReadTraffic { iface, source } => Error {
                code: ErrorCode::ServerError(-32015),
                message: format!(
                    "Failed to retrieve network statistics measurement for {}: {}",
                    iface, source
                ),
                data: None,
            },
            NetworkError::Reassociate { iface } => Error {
                code: ErrorCode::ServerError(-32008),
                message: format!("Failed to reassociate with WiFi network for {}", iface),
                data: None,
            },
            NetworkError::Reconnect { iface } => Error {
                code: ErrorCode::ServerError(-32009),
                message: format!("Failed to reconnect with WiFi network for {}", iface),
                data: None,
            },
            NetworkError::Regex { source } => Error {
                code: ErrorCode::ServerError(-32010),
                message: format!("Regex command error: {}", source),
                data: None,
            },
            NetworkError::RunApClientScript { source } => Error {
                code: ErrorCode::ServerError(-32011),
                message: format!("Failed to run interface_checker script: {}", source),
                data: None,
            },
            NetworkError::SerdeSerialize { source } => Error {
                code: ErrorCode::ServerError(-32010),
                message: format!("JSON serialization failed: {}", source),
                data: None,
            },
            NetworkError::WpaCtrlOpen { source } => Error {
                code: ErrorCode::ServerError(-32012),
                message: format!(
                    "Failed to open control interface for wpasupplicant: {}",
                    source
                ),
                data: None,
            },
            NetworkError::WpaCtrlRequest { source } => Error {
                code: ErrorCode::ServerError(-32013),
                message: format!("WPA supplicant request failed: {}", source),
                data: None,
            },
        }
    }
}
