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

    #[snafu(display("Failed to retrieve state for interface: {}", iface))]
    CatIfaceState { iface: String, source: io::Error },

    #[snafu(display("Failed to disable network {} for interface: {}", id, iface))]
    DisableWifi { id: String, iface: String },

    #[snafu(display("Failed to disconnect {}", iface))]
    DisconnectWifi { iface: String },

    #[snafu(display("Failed to generate wpa passphrase for {}: {}", ssid, source))]
    GenWpaPassphrase { ssid: String, source: io::Error },

    #[snafu(display("No ID found for {} on interface: {}", ssid, iface))]
    GetId { ssid: String, iface: String },

    #[snafu(display("Could not access IP address for interface: {}", iface))]
    GetIp { iface: String, source: io::Error },

    #[snafu(display("Could not find RSSI for interface: {}", iface))]
    GetRssi { iface: String },

    #[snafu(display("Could not find signal quality (%) for interface: {}", iface))]
    GetRssiPercent { iface: String },

    #[snafu(display("Could not find SSID for interface: {}", iface))]
    GetSsid { iface: String },

    #[snafu(display("No state found for interface: {}", iface))]
    GetState { iface: String },

    #[snafu(display("No status found for interface: {}", iface))]
    GetStatus { iface: String },

    #[snafu(display("Could not find network traffic for interface: {}", iface))]
    GetTraffic { iface: String },

    #[snafu(display("No saved networks found for default interface"))]
    ListSavedNetworks,

    #[snafu(display("No networks found in range of interface: {}", iface))]
    ListScanResults { iface: String },

    #[snafu(display("Missing expected parameters: {}", e))]
    MissingParams { e: Error },

    #[snafu(display("Failed to set new password for network {} on {}", id, iface))]
    NewPassword { id: String, iface: String },

    #[snafu(display("No IP found for interface: {}", iface))]
    NoIpFound { iface: String },

    #[snafu(display("Failed to parse integer from string for RSSI value: {}", source))]
    ParseString { source: std::num::ParseIntError },

    #[snafu(display(
        "Failed to retrieve network traffic measurement for {}: {}",
        iface,
        source
    ))]
    ReadTraffic { iface: String, source: ProbeError },

    #[snafu(display("Failed to reassociate with WiFi network for interface: {}", iface))]
    Reassociate { iface: String },

    #[snafu(display("Failed to force reread of wpa_supplicant configuration file"))]
    Reconfigure,

    #[snafu(display("Failed to reconnect with WiFi network for interface: {}", iface))]
    Reconnect { iface: String },

    #[snafu(display("Regex command failed"))]
    Regex { source: regex::Error },

    #[snafu(display("Failed to remove network {} for interface: {}", id, iface))]
    RemoveWifi { id: String, iface: String },

    #[snafu(display("Failed to run interface_checker script: {}", source))]
    RunApClientScript { source: io::Error },

    #[snafu(display("Failed to save configuration changes to file"))]
    SaveConfig,

    #[snafu(display("Failed to select network {} for interface: {}", id, iface))]
    SelectNetwork { id: String, iface: String },

    #[snafu(display("JSON serialization failed: {}", source))]
    SerdeSerialize { source: SerdeError },

    #[snafu(display("Failed to set ap0 interface up: {}", source))]
    SetApInterfaceUp { source: io::Error },

    #[snafu(display("Failed to set the wlan0 interface down: {}", source))]
    SetWlanInterfaceDown { source: io::Error },

    #[snafu(display("Failed to set the wlan0 interface up: {}", source))]
    SetWlanInterfaceUp { source: io::Error },

    #[snafu(display("Failed to stop wpasupplicant process: {}", source))]
    StopWpaSupplicant { source: io::Error },

    #[snafu(display("Failed to start dnsmasq process: {}", source))]
    StartDnsmasq { source: io::Error },

    #[snafu(display("Failed to stop dnsmasq process: {}", source))]
    StopDnsmasq { source: io::Error },

    #[snafu(display("Failed to start hostapd process: {}", source))]
    StartHostapd { source: io::Error },

    #[snafu(display("Failed to stop hostapd process: {}", source))]
    StopHostapd { source: io::Error },

    #[snafu(display("Failed to unmask hostapd process: {}", source))]
    UnmaskHostapd { source: io::Error },

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
            NetworkError::CatIfaceState { iface, source } => Error {
                code: ErrorCode::ServerError(-32022),
                message: format!(
                    "Failed to retrieve interface state for {}: {}",
                    iface, source
                ),
                data: None,
            },
            NetworkError::DisableWifi { id, iface } => Error {
                code: ErrorCode::ServerError(-32029),
                message: format!("Failed to disable network {} for {}", id, iface),
                data: None,
            },
            NetworkError::DisconnectWifi { iface } => Error {
                code: ErrorCode::ServerError(-32032),
                message: format!("Failed to disconnect {}", iface),
                data: None,
            },
            NetworkError::GenWpaPassphrase { ssid, source } => Error {
                code: ErrorCode::ServerError(-32025),
                message: format!("Failed to generate wpa passphrase for {}: {}", ssid, source),
                data: None,
            },
            NetworkError::GetId { iface, ssid } => Error {
                code: ErrorCode::ServerError(-32026),
                message: format!("No ID found for {} on interface {}", ssid, iface),
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
            NetworkError::GetRssiPercent { iface } => Error {
                code: ErrorCode::ServerError(-32034),
                message: format!(
                    "Failed to retrieve signal quality (%) for {}. Interface may not be connected",
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
            NetworkError::GetState { iface } => Error {
                code: ErrorCode::ServerError(-32023),
                message: format!("No state found for {}. Interface may not exist", iface),
                data: None,
            },
            NetworkError::GetStatus { iface } => Error {
                code: ErrorCode::ServerError(-32024),
                message: format!("No status found for {}. Interface may not exist", iface),
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
            NetworkError::NewPassword { id, iface } => Error {
                code: ErrorCode::ServerError(-32033),
                message: format!("Failed to set new password for network {} on {}", id, iface),
                data: None,
            },
            NetworkError::NoIpFound { iface } => Error {
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
            NetworkError::RemoveWifi { id, iface } => Error {
                code: ErrorCode::ServerError(-32028),
                message: format!("Failed to remove network {} for {}", id, iface),
                data: None,
            },
            NetworkError::RunApClientScript { source } => Error {
                code: ErrorCode::ServerError(-32011),
                message: format!("Failed to run interface_checker script: {}", source),
                data: None,
            },
            NetworkError::SaveConfig => Error {
                code: ErrorCode::ServerError(-32031),
                message: "Failed to save configuration changes to file".to_string(),
                data: None,
            },
            NetworkError::SelectNetwork { id, iface } => Error {
                code: ErrorCode::ServerError(-32027),
                message: format!("Failed to select network {} for {}", id, iface),
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
            NetworkError::SetWlanInterfaceDown { source } => Error {
                code: ErrorCode::ServerError(-32016),
                message: format!("Failed to set wlan0 interface down: {}", source),
                data: None,
            },
            NetworkError::SetWlanInterfaceUp { source } => Error {
                code: ErrorCode::ServerError(-32019),
                message: format!("Failed to set wlan0 interface up: {}", source),
                data: None,
            },
            NetworkError::StartDnsmasq { source } => Error {
                code: ErrorCode::ServerError(-32018),
                message: format!("Failed to start dnsmasq process: {}", source),
                data: None,
            },
            NetworkError::StopDnsmasq { source } => Error {
                code: ErrorCode::ServerError(-32020),
                message: format!("Failed to stop dnsmasq process: {}", source),
                data: None,
            },
            NetworkError::StartHostapd { source } => Error {
                code: ErrorCode::ServerError(-32017),
                message: format!("Failed to start hostapd process: {}", source),
                data: None,
            },
            NetworkError::StopHostapd { source } => Error {
                code: ErrorCode::ServerError(-32021),
                message: format!("Failed to stop hostapd process: {}", source),
                data: None,
            },
            NetworkError::StopWpaSupplicant { source } => Error {
                code: ErrorCode::ServerError(-32015),
                message: format!("Failed to stop wpasupplicant process: {}", source),
                data: None,
            },
            NetworkError::UnmaskHostapd { source } => Error {
                code: ErrorCode::ServerError(-32037),
                message: format!("Failed to unmask hostapd process: {}", source),
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
