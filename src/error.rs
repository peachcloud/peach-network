use std::{error, io, str};

use jsonrpc_core::{types::error::Error, ErrorCode};
use probes::ProbeError;
use serde_json::error::Error as SerdeError;
use snafu::Snafu;

pub type BoxError = Box<dyn error::Error>;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum NetworkError {
    #[snafu(display("Failed to activate access-point mode: {}", err_msg))]
    ActivateAp { err_msg: String },

    #[snafu(display("Failed to activate client mode: {}", err_msg))]
    ActivateClient { err_msg: String },

    #[snafu(display("Failed to add network for {}", ssid))]
    Add { ssid: String },

    #[snafu(display("Failed to retrieve state for interface: {}", iface))]
    NoState { iface: String, source: io::Error },

    #[snafu(display("Failed to disable network {} for interface: {}", id, iface))]
    Disable { id: String, iface: String },

    #[snafu(display("Failed to disconnect {}", iface))]
    Disconnect { iface: String },

    #[snafu(display("Failed to generate wpa passphrase for {}: {}", ssid, source))]
    GenWpaPassphrase { ssid: String, source: io::Error },

    #[snafu(display("No ID found for {} on interface: {}", ssid, iface))]
    Id { ssid: String, iface: String },

    #[snafu(display("Could not access IP address for interface: {}", iface))]
    NoIp { iface: String, source: io::Error },

    #[snafu(display("Could not find RSSI for interface: {}", iface))]
    Rssi { iface: String },

    #[snafu(display("Could not find signal quality (%) for interface: {}", iface))]
    RssiPercent { iface: String },

    #[snafu(display("Could not find SSID for interface: {}", iface))]
    Ssid { iface: String },

    #[snafu(display("No state found for interface: {}", iface))]
    State { iface: String },

    #[snafu(display("No status found for interface: {}", iface))]
    Status { iface: String },

    #[snafu(display("Could not find network traffic for interface: {}", iface))]
    Traffic { iface: String },

    #[snafu(display("No saved networks found for default interface"))]
    SavedNetworks,

    #[snafu(display("No networks found in range of interface: {}", iface))]
    AvailableNetworks { iface: String },

    #[snafu(display("Missing expected parameters: {}", e))]
    MissingParams { e: Error },

    #[snafu(display("Failed to set new password for network {} on {}", id, iface))]
    Modify { id: String, iface: String },

    #[snafu(display("No IP found for interface: {}", iface))]
    Ip { iface: String },

    #[snafu(display("Failed to parse integer from string for RSSI value: {}", source))]
    ParseString { source: std::num::ParseIntError },

    #[snafu(display(
        "Failed to retrieve network traffic measurement for {}: {}",
        iface,
        source
    ))]
    NoTraffic { iface: String, source: ProbeError },

    #[snafu(display("Failed to reassociate with WiFi network for interface: {}", iface))]
    Reassociate { iface: String },

    #[snafu(display("Failed to force reread of wpa_supplicant configuration file"))]
    Reconfigure,

    #[snafu(display("Failed to reconnect with WiFi network for interface: {}", iface))]
    Reconnect { iface: String },

    #[snafu(display("Regex command failed"))]
    Regex { source: regex::Error },

    #[snafu(display("Failed to delete network {} for interface: {}", id, iface))]
    Delete { id: String, iface: String },

    #[snafu(display("Failed to run interface_checker script: {}", source))]
    CheckIface { source: io::Error },

    #[snafu(display("Failed to save configuration changes to file"))]
    Save,

    #[snafu(display("Failed to connect to network {} for interface: {}", id, iface))]
    Connect { id: String, iface: String },

    #[snafu(display("Failed to run activate_ap script: {}", source))]
    RunApScript { source: io::Error },

    #[snafu(display("Failed to run activate_client script: {}", source))]
    RunClientScript { source: io::Error },

    #[snafu(display("JSON serialization failed: {}", source))]
    SerdeSerialize { source: SerdeError },

    #[snafu(display("Failed to set ap0 interface up: {}", source))]
    SetApInterfaceUp { source: io::Error },

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
            NetworkError::ActivateAp { err_msg } => Error {
                code: ErrorCode::ServerError(-32015),
                message: format!("Failed to activate access-point mode: {}", err_msg),
                data: None,
            },
            NetworkError::ActivateClient { err_msg } => Error {
                code: ErrorCode::ServerError(-32017),
                message: format!("Failed to activate client mode: {}", err_msg),
                data: None,
            },
            NetworkError::Add { ssid } => Error {
                code: ErrorCode::ServerError(-32000),
                message: format!("Failed to add network for {}", ssid),
                data: None,
            },
            NetworkError::NoState { iface, source } => Error {
                code: ErrorCode::ServerError(-32022),
                message: format!(
                    "Failed to retrieve interface state for {}: {}",
                    iface, source
                ),
                data: None,
            },
            NetworkError::Disable { id, iface } => Error {
                code: ErrorCode::ServerError(-32029),
                message: format!("Failed to disable network {} for {}", id, iface),
                data: None,
            },
            NetworkError::Disconnect { iface } => Error {
                code: ErrorCode::ServerError(-32032),
                message: format!("Failed to disconnect {}", iface),
                data: None,
            },
            NetworkError::GenWpaPassphrase { ssid, source } => Error {
                code: ErrorCode::ServerError(-32025),
                message: format!("Failed to generate wpa passphrase for {}: {}", ssid, source),
                data: None,
            },
            NetworkError::Id { iface, ssid } => Error {
                code: ErrorCode::ServerError(-32026),
                message: format!("No ID found for {} on interface {}", ssid, iface),
                data: None,
            },
            NetworkError::NoIp { iface, source } => Error {
                code: ErrorCode::ServerError(-32001),
                message: format!("Failed to retrieve IP address for {}: {}", iface, source),
                data: None,
            },
            NetworkError::Rssi { iface } => Error {
                code: ErrorCode::ServerError(-32002),
                message: format!(
                    "Failed to retrieve RSSI for {}. Interface may not be connected",
                    iface
                ),
                data: None,
            },
            NetworkError::RssiPercent { iface } => Error {
                code: ErrorCode::ServerError(-32034),
                message: format!(
                    "Failed to retrieve signal quality (%) for {}. Interface may not be connected",
                    iface
                ),
                data: None,
            },
            NetworkError::Ssid { iface } => Error {
                code: ErrorCode::ServerError(-32003),
                message: format!(
                    "Failed to retrieve SSID for {}. Interface may not be connected",
                    iface
                ),
                data: None,
            },
            NetworkError::State { iface } => Error {
                code: ErrorCode::ServerError(-32023),
                message: format!("No state found for {}. Interface may not exist", iface),
                data: None,
            },
            NetworkError::Status { iface } => Error {
                code: ErrorCode::ServerError(-32024),
                message: format!("No status found for {}. Interface may not exist", iface),
                data: None,
            },
            NetworkError::Traffic { iface } => Error {
                code: ErrorCode::ServerError(-32004),
                message: format!(
                    "No network traffic statistics found for {}. Interface may not exist",
                    iface
                ),
                data: None,
            },
            NetworkError::SavedNetworks => Error {
                code: ErrorCode::ServerError(-32005),
                message: "No saved networks found".to_string(),
                data: None,
            },
            NetworkError::AvailableNetworks { iface } => Error {
                code: ErrorCode::ServerError(-32006),
                message: format!("No networks found in range of {}", iface),
                data: None,
            },
            NetworkError::MissingParams { e } => e.clone(),
            NetworkError::Modify { id, iface } => Error {
                code: ErrorCode::ServerError(-32033),
                message: format!("Failed to set new password for network {} on {}", id, iface),
                data: None,
            },
            NetworkError::Ip { iface } => Error {
                code: ErrorCode::ServerError(-32007),
                message: format!("No IP address found for {}", iface),
                data: None,
            },
            NetworkError::ParseString { source } => Error {
                code: ErrorCode::ServerError(-32035),
                message: format!(
                    "Failed to parse integer from string for RSSI value: {}",
                    source
                ),
                data: None,
            },
            NetworkError::NoTraffic { iface, source } => Error {
                code: ErrorCode::ServerError(-32015),
                message: format!(
                    "Failed to retrieve network traffic statistics for {}: {}",
                    iface, source
                ),
                data: None,
            },
            NetworkError::Reassociate { iface } => Error {
                code: ErrorCode::ServerError(-32008),
                message: format!("Failed to reassociate with WiFi network for {}", iface),
                data: None,
            },
            NetworkError::Reconfigure => Error {
                code: ErrorCode::ServerError(-32030),
                message: "Failed to force reread of wpa_supplicant configuration file".to_string(),
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
            NetworkError::Delete { id, iface } => Error {
                code: ErrorCode::ServerError(-32028),
                message: format!("Failed to delete network {} for {}", id, iface),
                data: None,
            },
            NetworkError::CheckIface { source } => Error {
                code: ErrorCode::ServerError(-32011),
                message: format!("Failed to run interface_checker script: {}", source),
                data: None,
            },
            NetworkError::Save => Error {
                code: ErrorCode::ServerError(-32031),
                message: "Failed to save configuration changes to file".to_string(),
                data: None,
            },
            NetworkError::Connect { id, iface } => Error {
                code: ErrorCode::ServerError(-32027),
                message: format!("Failed to connect to network {} for {}", id, iface),
                data: None,
            },
            NetworkError::RunApScript { source }=> Error {
                code: ErrorCode::ServerError(-32016),
                message: format!("Failed to run activate_ap script: {}", source),
                data: None,
            },
            NetworkError::RunClientScript { source }=> Error {
                code: ErrorCode::ServerError(-32018),
                message: format!("Failed to run activate_client script: {}", source),
                data: None,
            },
            NetworkError::SerdeSerialize { source } => Error {
                code: ErrorCode::ServerError(-32012),
                message: format!("JSON serialization failed: {}", source),
                data: None,
            },
            NetworkError::SetApInterfaceUp { source } => Error {
                code: ErrorCode::ServerError(-32036),
                message: format!("Failed to set ap0 interface up: {}", source),
                data: None,
            },
            NetworkError::WpaCtrlOpen { source } => Error {
                code: ErrorCode::ServerError(-32013),
                message: format!(
                    "Failed to open control interface for wpasupplicant: {}",
                    source
                ),
                data: None,
            },
            NetworkError::WpaCtrlRequest { source } => Error {
                code: ErrorCode::ServerError(-32014),
                message: format!("WPA supplicant request failed: {}", source),
                data: None,
            },
        }
    }
}
