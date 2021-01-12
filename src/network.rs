//! Retrieve network data and modify interface state.
//!
//! This module contains the core logic of the `peach-network` microservice and
//! provides convenience wrappers for a range of `wpasupplicant` commands,
//! many of which are ordinarily executed using `wpa_cli` (a WPA command line
//! client).
//!
//! The `wpactrl` crate ([docs](https://docs.rs/wpactrl/0.3.1/wpactrl/))
//! is used to interact with the `wpasupplicant` process.
//!
//! Further networking functionality is provided by executing scripts as
//! subprocesses, such as `activate_ap` and `activate_client`, as well as making
//! system calls to retrieve interface state and write access point credentials
//! to `wpa_supplicant.conf`.
//!
use std::{
    fs::OpenOptions,
    io::prelude::*,
    process::{Command, Stdio},
    result::Result,
    str,
};

use probes::network;
use serde::{Deserialize, Serialize};
use snafu::ResultExt;

use crate::error::*;
use crate::utils;

/// Network interface name.
#[derive(Debug, Deserialize)]
pub struct Iface {
    pub iface: String,
}

/// Network interface name and network identifier.
#[derive(Debug, Deserialize)]
pub struct IfaceId {
    pub iface: String,
    pub id: String,
}

/// Network interface name, network identifier and password.
#[derive(Debug, Deserialize)]
pub struct IfaceIdPass {
    pub iface: String,
    pub id: String,
    pub pass: String,
}

/// Network interface name and network SSID.
#[derive(Debug, Deserialize)]
pub struct IfaceSsid {
    pub iface: String,
    pub ssid: String,
}

/// Network SSID.
#[derive(Debug, Serialize)]
pub struct Network {
    pub ssid: String,
}

/// Access point data retrieved via scan.
#[derive(Debug, Serialize)]
pub struct Scan {
    pub frequency: String,
    pub protocol: String,
    pub signal_level: String,
    pub ssid: String,
}

/// Status data for a network interface.
#[derive(Debug, Serialize)]
pub struct Status {
    pub address: Option<String>,
    pub bssid: Option<String>,
    pub freq: Option<String>,
    pub group_cipher: Option<String>,
    pub id: Option<String>,
    pub ip_address: Option<String>,
    pub key_mgmt: Option<String>,
    pub mode: Option<String>,
    pub pairwise_cipher: Option<String>,
    pub ssid: Option<String>,
    pub wpa_state: Option<String>,
}

impl Status {
    fn new() -> Status {
        Status {
            address: None,
            bssid: None,
            freq: None,
            group_cipher: None,
            id: None,
            ip_address: None,
            key_mgmt: None,
            mode: None,
            pairwise_cipher: None,
            ssid: None,
            wpa_state: None,
        }
    }
}

/// Received and transmitted network traffic (bytes).
#[derive(Debug, Serialize)]
pub struct Traffic {
    pub received: u64,
    pub transmitted: u64,
}

/// SSID and password for a wireless access point.
#[derive(Debug, Deserialize)]
pub struct WiFi {
    pub ssid: String,
    pub pass: String,
}

/* GET - Methods for retrieving data */

/// Retrieve list of available wireless access points for a given network
/// interface.
///
/// # Arguments
///
/// * `iface` - A string slice holding the name of a wireless network interface
///
/// If the scan results include one or more access points for the given network
/// interface, an `Ok` `Result` type is returned containing `Some(String)` -
/// where `String` is a serialized vector of `Scan` structs containing
/// data for the in-range access points. If no access points are found,
/// a `None` type is returned in the `Result`. In the event of an error, a
/// `NetworkError` is returned in the `Result`. The `NetworkError` is then
/// enumerated to a specific error type and an appropriate JSON RPC response is
/// sent to the caller.
///
pub fn available_networks(iface: &str) -> Result<Option<String>, NetworkError> {
    let wpa_path: String = format!("/var/run/wpa_supplicant/{}", iface);
    let mut wpa = wpactrl::WpaCtrl::new()
        .ctrl_path(wpa_path)
        .open()
        .context(WpaCtrlOpen)?;
    wpa.request("SCAN").context(WpaCtrlRequest)?;
    let networks = wpa.request("SCAN_RESULTS").context(WpaCtrlRequest)?;
    let mut scan = Vec::new();
    for network in networks.lines() {
        let v: Vec<&str> = network.split('\t').collect();
        let len = v.len();
        if len > 1 {
            let frequency = v[1].to_string();
            let signal_level = v[2].to_string();
            let flags = v[3].to_string();
            let flags_vec: Vec<&str> = flags.split("][").collect();
            let mut protocol = String::new();
            // an open access point (no auth) will only have [ESS] in flags
            // we only want to return the auth / crypto flags
            if flags_vec[0] != "[ESS]" {
                // parse auth / crypto flag and assign it to protocol
                protocol.push_str(flags_vec[0].replace("[", "").replace("]", "").as_str());
            }
            let ssid = v[4].to_string();
            let response = Scan {
                frequency,
                protocol,
                signal_level,
                ssid,
            };
            scan.push(response)
        }
    }

    if scan.is_empty() {
        Ok(None)
    } else {
        let results = serde_json::to_string(&scan).context(SerdeSerialize)?;
        Ok(Some(results))
    }
}

/// Retrieve network identifier for the network specified by a given interface
/// and SSID.
///
/// # Arguments
///
/// * `iface` - A string slice holding the name of a wireless network interface
/// * `ssid` - A string slice holding the SSID of a wireless access point
///
/// If the identifier corresponding to the given interface and SSID is
/// found in the list of saved networks, an `Ok` `Result` type is returned
/// containing `Some(String)` - where `String` is the network identifier.
/// If no match is found, a `None` type is returned in the `Result`. In the
/// event of an error, a `NetworkError` is returned in the `Result`. The
/// `NetworkError` is then enumerated to a specific error type and an
/// appropriate JSON RPC response is sent to the caller.
///
pub fn id(iface: &str, ssid: &str) -> Result<Option<String>, NetworkError> {
    let wpa_path: String = format!("/var/run/wpa_supplicant/{}", iface);
    let mut wpa = wpactrl::WpaCtrl::new()
        .ctrl_path(wpa_path)
        .open()
        .context(WpaCtrlOpen)?;
    let networks = wpa.request("LIST_NETWORKS").context(WpaCtrlRequest)?;
    let mut id = Vec::new();
    for network in networks.lines() {
        let v: Vec<&str> = network.split('\t').collect();
        let len = v.len();
        if len > 1 && v[1] == ssid {
            id.push(v[0].trim())
        }
    }

    if id.is_empty() {
        Ok(None)
    } else {
        let network_id: String = id[0].to_string();
        Ok(Some(network_id))
    }
}

/// Retrieve IP address for a given interface.
///
/// # Arguments
///
/// * `iface` - A string slice holding the name of a wireless network interface
///
/// If the given interface is found in the list of available interfaces,
/// an `Ok` `Result` type is returned containing `Some(String)` - where `String`
/// is the IP address of the interface. If no match is found, a `None` type is
/// returned in the `Result`. In the event of an error, a `NetworkError` is
/// returned in the `Result`. The `NetworkError` is then enumerated to a
/// specific error type and an appropriate JSON RPC response is sent to the
/// caller.
///
pub fn ip(iface: &str) -> Result<Option<String>, NetworkError> {
    let net_if: String = iface.to_string();
    let ifaces = get_if_addrs::get_if_addrs().context(NoIp { iface: net_if })?;
    let ip = ifaces
        .iter()
        .find(|&i| i.name == iface)
        .map(|iface| iface.ip().to_string());

    Ok(ip)
}

/// Retrieve average signal strength (dBm) for the network associated with
/// a given interface.
///
/// # Arguments
///
/// * `iface` - A string slice holding the name of a wireless network interface
///
/// If the signal strength is found for the given interface after polling,
/// an `Ok` `Result` type is returned containing `Some(String)` - where `String`
/// is the RSSI (Received Signal Strength Indicator) of the connection measured
/// in dBm. If signal strength is not found, a `None` type is returned in the
/// `Result`. In the event of an error, a `NetworkError` is returned in the
/// `Result`. The `NetworkError` is then enumerated to a specific error type and
/// an appropriate JSON RPC response is sent to the caller.
///
pub fn rssi(iface: &str) -> Result<Option<String>, NetworkError> {
    let wpa_path: String = format!("/var/run/wpa_supplicant/{}", iface);
    let mut wpa = wpactrl::WpaCtrl::new()
        .ctrl_path(wpa_path)
        .open()
        .context(WpaCtrlOpen)?;
    let status = wpa.request("SIGNAL_POLL").context(WpaCtrlRequest)?;
    let rssi = utils::regex_finder(r"RSSI=(.*)\n", &status)?;

    if rssi.is_none() {
        let iface = iface.to_string();
        Err(NetworkError::Rssi { iface })
    } else {
        Ok(rssi)
    }
}

/// Retrieve average signal strength (%) for the network associated with
/// a given interface.
///
/// # Arguments
///
/// * `iface` - A string slice holding the name of a wireless network interface
///
/// If the signal strength is found for the given interface after polling,
/// an `Ok` `Result` type is returned containing `Some(String)` - where `String`
/// is the RSSI (Received Signal Strength Indicator) of the connection measured
/// as a percentage. If signal strength is not found, a `None` type is returned
/// in the `Result`. In the event of an error, a `NetworkError` is returned in
/// the `Result`. The `NetworkError` is then enumerated to a specific error type
/// and an appropriate JSON RPC response is sent to the caller.
///
pub fn rssi_percent(iface: &str) -> Result<Option<String>, NetworkError> {
    let wpa_path: String = format!("/var/run/wpa_supplicant/{}", iface);
    let mut wpa = wpactrl::WpaCtrl::new()
        .ctrl_path(wpa_path)
        .open()
        .context(WpaCtrlOpen)?;
    let status = wpa.request("SIGNAL_POLL").context(WpaCtrlRequest)?;
    let mut status_lines = status.lines();
    if let Some(rssi_line) = status_lines.next() {
        // AVG_RSSI fluctuates wildly, use RSSI instead
        let rssi = rssi_line.to_string().split_off(5);
        // parse the string to a signed integer (for math)
        let rssi_parsed = rssi.parse::<i32>().context(ParseString)?;
        // perform rssi (dBm) to quality (%) conversion
        let quality_percent = 2 * (rssi_parsed + 100);
        // convert signal quality integer to string
        let quality = quality_percent.to_string();
        Ok(Some(quality))
    } else {
        Ok(None)
    }
}

/// Retrieve list of all access points with credentials saved in the
/// wpasupplicant configuration file.
///
/// If the wpasupplicant configuration file contains credentials for one or
/// more access points, an `Ok` `Result` type is returned containing
/// `Some(String)` - where `String` is a serialized vector of `Network` structs
/// containing the SSIDs of all saved networks. If no network credentials are
/// found, a `None` type is returned in the `Result`. In the event of an error,
/// a `NetworkError` is returned in the `Result`. The `NetworkError` is then
/// enumerated to a specific error type and an appropriate JSON RPC response is
/// sent to the caller.
///
pub fn saved_networks() -> Result<Option<String>, NetworkError> {
    let mut wpa = wpactrl::WpaCtrl::new().open().context(WpaCtrlOpen)?;
    let networks = wpa.request("LIST_NETWORKS").context(WpaCtrlRequest)?;
    let mut ssids = Vec::new();
    for network in networks.lines() {
        let v: Vec<&str> = network.split('\t').collect();
        let len = v.len();
        if len > 1 {
            let ssid = v[1].trim().to_string();
            let response = Network { ssid };
            ssids.push(response)
        }
    }

    if ssids.is_empty() {
        Ok(None)
    } else {
        let results = serde_json::to_string(&ssids).context(SerdeSerialize)?;
        Ok(Some(results))
    }
}

/// Retrieve SSID for the network associated with a given interface.
///
/// # Arguments
///
/// * `iface` - A string slice holding the name of a wireless network interface
///
/// If the SSID is found in the status output for the given interface,
/// an `Ok` `Result` type is returned containing `Some(String)` - where `String`
/// is the SSID of the associated network. If SSID is not found, a `None` type
/// is returned in the `Result`. In the event of an error, a `NetworkError` is
/// returned in the `Result`. The `NetworkError` is then enumerated to a
/// specific error type and an appropriate JSON RPC response is sent to the
/// caller.
///
pub fn ssid(iface: &str) -> Result<Option<String>, NetworkError> {
    let wpa_path: String = format!("/var/run/wpa_supplicant/{}", iface);
    let mut wpa = wpactrl::WpaCtrl::new()
        .ctrl_path(wpa_path)
        .open()
        .context(WpaCtrlOpen)?;
    let status = wpa.request("STATUS").context(WpaCtrlRequest)?;

    // pass the regex pattern and status output to the regex finder
    let ssid = utils::regex_finder(r"\nssid=(.*)\n", &status)?;

    Ok(ssid)
}

/// Retrieve state for a given interface.
///
/// # Arguments
///
/// * `iface` - A string slice holding the name of a wireless network interface
///
/// If the state is found for the given interface, an `Ok` `Result` type is
/// returned containing `Some(String)` - where `String` is the state of the
/// network interface. If state is not found, a `None` type is returned in the
/// `Result`. In the event of an error, a `NetworkError` is returned in the
/// `Result`. The `NetworkError` is then enumerated to a specific error type and
/// an appropriate JSON RPC response is sent to the caller.
///
pub fn state(iface: &str) -> Result<Option<String>, NetworkError> {
    // construct the interface operstate path
    let iface_path: String = format!("/sys/class/net/{}/operstate", iface);
    // execute the cat command and save output, catching any errors
    let output = Command::new("cat")
        .arg(iface_path)
        .output()
        .context(NoState { iface })?;
    if !output.stdout.is_empty() {
        // unwrap the command result and convert to String
        let mut state = String::from_utf8(output.stdout).unwrap();
        // remove trailing newline character
        let len = state.len();
        state.truncate(len - 1);
        return Ok(Some(state));
    }

    Ok(None)
}

/// Retrieve status for a given interface.
///
/// # Arguments
///
/// * `iface` - A string slice holding the name of a wireless network interface
///
/// If the status is found for the given interface, an `Ok` `Result` type is
/// returned containing `Some(Status)` - where `Status` is a `struct`
/// containing the aggregated interface data in named fields. If status is not
/// found, a `None` type is returned in the `Result`. In the event of an error,
/// a `NetworkError` is returned in the `Result`. The `NetworkError` is then
/// enumerated to a specific error type and an appropriate JSON RPC response is
/// sent to the caller.
///
pub fn status(iface: &str) -> Result<Option<Status>, NetworkError> {
    let wpa_path: String = format!("/var/run/wpa_supplicant/{}", iface);
    let mut wpa = wpactrl::WpaCtrl::new()
        .ctrl_path(wpa_path)
        .open()
        .context(WpaCtrlOpen)?;
    let wpa_status = wpa.request("STATUS").context(WpaCtrlRequest)?;

    // pass the regex pattern and status output to the regex finder
    let state = utils::regex_finder(r"wpa_state=(.*)\n", &wpa_status)?;
    // regex_finder returns an Option type, unwrap or replace None with ERROR
    let wpa_state = state.unwrap_or_else(|| "ERROR".to_string());

    // create new Status object (all fields are None type by default)
    let mut status = Status::new();
    // match on wpa_state and set Status fields accordingly
    match wpa_state.as_ref() {
        "ERROR" => status.wpa_state = Some("ERROR".to_string()),
        "UNKNOWN" => status.wpa_state = Some("UNKNOWN".to_string()),
        "INTERFACE_DISABLED" => status.wpa_state = Some("DISABLED".to_string()),
        "INACTIVE" => status.wpa_state = Some("INACTIVE".to_string()),
        "DISCONNECTED" => status.wpa_state = Some("DISCONNECTED".to_string()),
        "SCANNING" => status.wpa_state = Some("SCANNING".to_string()),
        "ASSOCIATING" => status.wpa_state = Some("ASSOCIATING".to_string()),
        "ASSOCIATED" => status.wpa_state = Some("ASSOCIATED".to_string()),
        "AUTHENTICATING" => status.wpa_state = Some("AUTHENTICATING".to_string()),
        "4WAY_HANDSHAKE" => status.wpa_state = Some("4WAY_HANDSHAKE".to_string()),
        "GROUP_HANDSHAKE" => status.wpa_state = Some("GROUP_HANDSHAKE".to_string()),
        // retrieve additional status fields only if wpa_state is COMPLETED
        "COMPLETED" => {
            status.address = utils::regex_finder(r"\naddress=(.*)\n", &wpa_status)?;
            status.bssid = utils::regex_finder(r"\nbssid=(.*)\n", &wpa_status)?;
            status.freq = utils::regex_finder(r"\nfreq=(.*)\n", &wpa_status)?;
            status.group_cipher = utils::regex_finder(r"\ngroup_cipher=(.*)\n", &wpa_status)?;
            status.id = utils::regex_finder(r"\nid=(.*)\n", &wpa_status)?;
            status.ip_address = utils::regex_finder(r"\nip_address=(.*)\n", &wpa_status)?;
            status.key_mgmt = utils::regex_finder(r"\nkey_mgmt=(.*)\n", &wpa_status)?;
            status.mode = utils::regex_finder(r"\nmode=(.*)\n", &wpa_status)?;
            status.pairwise_cipher = utils::regex_finder(r"\npairwise_cipher=(.*)\n", &wpa_status)?;
            status.ssid = utils::regex_finder(r"\nssid=(.*)\n", &wpa_status)?;
            status.wpa_state = utils::regex_finder(r"\nwpa_state=(.*)\n", &wpa_status)?;
        }
        _ => (),
    }

    Ok(Some(status))
}

/// Retrieve network traffic statistics for a given interface.
///
/// # Arguments
///
/// * `iface` - A string slice holding the name of a wireless network interface
///
/// If the network traffic statistics are found for the given interface, an `Ok`
/// `Result` type is returned containing `Some(String)` - where `String` is a
/// serialized `Traffic` `struct` with fields for received and transmitted
/// network data statistics. If network traffic statistics are not found for the
/// given interface, a `None` type is returned in the `Result`. In the event of
/// an error, a `NetworkError` is returned in the `Result`. The `NetworkError`
/// is then enumerated to a specific error type and an appropriate JSON RPC
/// response is sent to the caller.
///
pub fn traffic(iface: &str) -> Result<Option<String>, NetworkError> {
    let network = network::read().context(NoTraffic { iface })?;
    // iterate through interfaces returned in network data
    for (interface, traffic) in network.interfaces {
        if interface == iface {
            let received = traffic.received;
            let transmitted = traffic.transmitted;
            let traffic = Traffic {
                received,
                transmitted,
            };
            // TODO: add test for SerdeSerialize error
            let t = serde_json::to_string(&traffic).context(SerdeSerialize)?;
            return Ok(Some(t));
        }
    }

    Ok(None)
}

/* SET - Methods for modifying state */

/// Activate wireless access point.
///
/// A command is invoked which executes the `activate_ap` bash script.
/// The script attempts to stop the `wpasupplicant` process, set the `wlan0`
/// interface down, start the `hostapd` and `dnsmasq` processes
/// and set the `ap0` interface up. If the script executes successfully,
/// an `Ok` `Result` type is returned. In the event of an error, a
/// `NetworkError` is returned in the `Result`. The `NetworkError` is then
/// enumerated to a specific error type and an appropriate JSON RPC response is
/// sent to the caller.
///
pub fn activate_ap() -> Result<(), NetworkError> {
    // execute the activate_ap bash script
    let output = Command::new("sudo")
        .arg("/usr/local/bin/activate_ap")
        .output()
        .context(RunApScript)?;
    if output.status.success() {
        Ok(())
    } else {
        let mut err_msg = String::from_utf8(output.stdout).unwrap();
        let len = err_msg.len();
        // truncate the error msg to remove the trailing newline character
        err_msg.truncate(len - 1);
        Err(NetworkError::ActivateAp { err_msg })
    }
}

/// Activate wireless client.
///
/// A command is invoked which executes the `activate_client` bash script.
/// The script attempts to stop the `hostapd` and `dnsmasq` processes and set
/// the `wlan0` interface up. If the commands execute successfully, an `Ok`
/// `Result` type is returned. In the event of an error, a `NetworkError` is
/// returned in the `Result`. The `NetworkError` is then enumerated to a
/// specific error type and an appropriate JSON RPC response is sent to the
/// caller.
///
pub fn activate_client() -> Result<(), NetworkError> {
    // execute the activate_client bash script
    let output = Command::new("sudo")
        .arg("/usr/local/bin/activate_client")
        .output()
        .context(RunClientScript)?;
    if output.status.success() {
        Ok(())
    } else {
        let mut err_msg = String::from_utf8(output.stdout).unwrap();
        let len = err_msg.len();
        // truncate the error msg to remove the trailing newline character
        err_msg.truncate(len - 1);
        Err(NetworkError::ActivateClient { err_msg })
    }
}

/// Add network credentials for a given wireless access point.
///
/// # Arguments
///
/// * `wifi` - An instance of the `WiFi` `struct` with fields `ssid` and `pass`
///
/// If configuration parameters are successfully generated from the provided
/// SSID and password and appended to `wpa_supplicant.conf`, an `Ok` `Result`
/// type is returned. In the event of an error, a `NetworkError` is returned in
/// the `Result`. The `NetworkError` is then enumerated to a specific error type
/// and an appropriate JSON RPC response is sent to the caller.
///
pub fn add(wifi: &WiFi) -> Result<(), NetworkError> {
    // generate configuration based on provided ssid & password
    let output = Command::new("wpa_passphrase")
        .arg(&wifi.ssid)
        .arg(&wifi.pass)
        .stdout(Stdio::piped())
        .output()
        .context(GenWpaPassphrase { ssid: &wifi.ssid })?;

    // prepend newline to wpa_details to safeguard against malformed supplicant
    let mut wpa_details = "\n".as_bytes().to_vec();
    wpa_details.extend(&*(output.stdout));

    // append wpa_passphrase output to wpa_supplicant.conf if successful
    if output.status.success() {
        // open file in append mode
        let file = OpenOptions::new()
            .append(true)
            .open("/etc/wpa_supplicant/wpa_supplicant.conf");

        let _file = match file {
            // if file exists & open succeeds, write wifi configuration
            Ok(mut f) => f.write(&wpa_details),
            // TODO: handle this better: create file if not found
            //  & seed with 'ctrl_interace' & 'update_config' settings
            //  config file could also be copied from peach/config fs location
            Err(e) => panic!("Failed to write to file: {}", e),
        };
    }

    Ok(())
}

/// Run interface checker script for automatically activating access point or
/// wireless client.
///
/// The `interface_checker.sh` script is executed. The script activates an
/// access point on the `ap0` interface if the `wlan0` interface is down and
/// deactivates the access point if the `wlan0` interface is up. If the command
/// executes successfully, an `Ok` `Result` type is returned. In the event of an
/// error, a `NetworkError` is returned in the `Result`. The `NetworkError` is
/// then enumerated to a specific error type and an appropriate JSON RPC
/// response is sent to the caller.
///
pub fn check_iface() -> Result<(), NetworkError> {
    Command::new("sudo")
        .arg("/bin/bash")
        .arg("/home/glyph/interface_checker.sh")
        .output()
        .context(CheckIface)?;
    Ok(())
}

/// Connect with an access point for a given network identifier and interface.
/// Results in connections with other access points being disabled.
///
/// # Arguments
///
/// * `id` - A string slice holding the network identifier of an access point
/// * `iface` - A string slice holding the name of a wireless network interface
///
/// If the network connection is successfully activated for the access point
/// represented by the given network identifier on the given wireless interface,
/// an `Ok` `Result`type is returned. In the event of an error, a `NetworkError`
/// is returned in the `Result`. The `NetworkError` is then enumerated to a
/// specific error type and an appropriate JSON RPC response is sent to the
/// caller.
///
pub fn connect(id: &str, iface: &str) -> Result<(), NetworkError> {
    let wpa_path: String = format!("/var/run/wpa_supplicant/{}", iface);
    let mut wpa = wpactrl::WpaCtrl::new()
        .ctrl_path(wpa_path)
        .open()
        .context(WpaCtrlOpen)?;
    let select = format!("SELECT {}", id);
    wpa.request(&select).context(WpaCtrlRequest)?;
    Ok(())
}

/// Delete network credentials for a given network identifier and interface.
///
/// # Arguments
///
/// * `id` - A string slice holding the network identifier of an access point
/// * `iface` - A string slice holding the name of a wireless network interface
///
/// If the network configuration parameters are successfully deleted for
/// the access point represented by the given network identifier, an `Ok`
/// `Result`type is returned. In the event of an error, a `NetworkError` is
/// returned in the `Result`. The `NetworkError` is then enumerated to a
/// specific error type and an appropriate JSON RPC response is sent to the
/// caller.
///
pub fn delete(id: &str, iface: &str) -> Result<(), NetworkError> {
    let wpa_path: String = format!("/var/run/wpa_supplicant/{}", iface);
    let mut wpa = wpactrl::WpaCtrl::new()
        .ctrl_path(wpa_path)
        .open()
        .context(WpaCtrlOpen)?;
    let remove = format!("REMOVE_NETWORK {}", id);
    wpa.request(&remove).context(WpaCtrlRequest)?;
    Ok(())
}

/// Disable network connection for a given network identifier and interface.
///
/// # Arguments
///
/// * `id` - A string slice holding the network identifier of an access point
/// * `iface` - A string slice holding the name of a wireless network interface
///
/// If the network connection is successfully disabled for the access point
/// represented by the given network identifier, an `Ok` `Result`type is
/// returned. In the event of an error, a `NetworkError` is returned in the
/// `Result`. The `NetworkError` is then enumerated to a specific error type and
/// an appropriate JSON RPC response is sent to the caller.
///
pub fn disable(id: &str, iface: &str) -> Result<(), NetworkError> {
    let wpa_path: String = format!("/var/run/wpa_supplicant/{}", iface);
    let mut wpa = wpactrl::WpaCtrl::new()
        .ctrl_path(wpa_path)
        .open()
        .context(WpaCtrlOpen)?;
    let disable = format!("DISABLE_NETWORK {}", id);
    wpa.request(&disable).context(WpaCtrlRequest)?;
    Ok(())
}

/// Disconnect network connection for a given wireless interface.
///
/// # Arguments
///
/// * `iface` - A string slice holding the name of a wireless network interface
///
/// If the network connection is successfully disconnected for the given
/// wireless interface, an `Ok` `Result` type is returned. In the event of an
/// error, a `NetworkError` is returned in the `Result`. The `NetworkError` is
/// then enumerated to a specific error type and an appropriate JSON RPC
/// response is sent to the caller.
///
pub fn disconnect(iface: &str) -> Result<(), NetworkError> {
    let wpa_path: String = format!("/var/run/wpa_supplicant/{}", iface);
    let mut wpa = wpactrl::WpaCtrl::new()
        .ctrl_path(wpa_path)
        .open()
        .context(WpaCtrlOpen)?;
    let disconnect = "DISCONNECT".to_string();
    wpa.request(&disconnect).context(WpaCtrlRequest)?;
    Ok(())
}

/// Modify password for a given network identifier and interface.
///
/// # Arguments
///
/// * `id` - A string slice holding the network identifier of an access point
/// * `iface` - A string slice holding the name of a wireless network interface
/// * `pass` - A string slice holding the password for a wireless access point
///
/// If the password is successfully updated for the access point represented by
/// the given network identifier, an `Ok` `Result` type is returned. In the
/// event of an error, a `NetworkError` is returned in the `Result`. The
/// `NetworkError` is then enumerated to a specific error type and an
/// appropriate JSON RPC response is sent to the caller.
///
pub fn modify(id: &str, iface: &str, pass: &str) -> Result<(), NetworkError> {
    let wpa_path: String = format!("/var/run/wpa_supplicant/{}", iface);
    let mut wpa = wpactrl::WpaCtrl::new()
        .ctrl_path(wpa_path)
        .open()
        .context(WpaCtrlOpen)?;
    let new_pass = format!("NEW_PASSWORD {} {}", id, pass);
    wpa.request(&new_pass).context(WpaCtrlRequest)?;
    Ok(())
}

/// Reassociate with an access point for a given wireless interface.
///
/// # Arguments
///
/// * `iface` - A string slice holding the name of a wireless network interface
///
/// If the network connection is successfully reassociated for the given
/// wireless interface, an `Ok` `Result` type is returned. In the event of an
/// error, a `NetworkError` is returned in the `Result`. The `NetworkError` is
/// then enumerated to a specific error type and an appropriate JSON RPC
/// response is sent to the caller.
///
pub fn reassociate(iface: &str) -> Result<(), NetworkError> {
    let wpa_path: String = format!("/var/run/wpa_supplicant/{}", iface);
    let mut wpa = wpactrl::WpaCtrl::new()
        .ctrl_path(wpa_path)
        .open()
        .context(WpaCtrlOpen)?;
    wpa.request("REASSOCIATE").context(WpaCtrlRequest)?;
    Ok(())
}

/// Reconfigure `wpa_supplicant` by forcing a reread of the configuration file.
///
/// If the reconfigure command is successfully executed, indicating a reread
/// of the `wpa_supplicant.conf` file by the `wpa_supplicant` process, an `Ok`
/// `Result` type is returned. In the event of an error, a `NetworkError` is
/// returned in the `Result`. The `NetworkError` is then enumerated to a
/// specific error type and an appropriate JSON RPC response is sent to the
/// caller.
///
pub fn reconfigure() -> Result<(), NetworkError> {
    let mut wpa = wpactrl::WpaCtrl::new().open().context(WpaCtrlOpen)?;
    wpa.request("RECONFIGURE").context(WpaCtrlRequest)?;
    Ok(())
}

/// Reconnect network connection for a given wireless interface.
///
/// # Arguments
///
/// * `iface` - A string slice holding the name of a wireless network interface
///
/// If the network connection is successfully disconnected and reconnected for
/// the given wireless interface, an `Ok` `Result` type is returned. In the
/// event of an error, a `NetworkError` is returned in the `Result`. The
/// `NetworkError` is then enumerated to a specific error type and an
/// appropriate JSON RPC response is sent to the caller.
///
pub fn reconnect(iface: &str) -> Result<(), NetworkError> {
    let wpa_path: String = format!("/var/run/wpa_supplicant/{}", iface);
    let mut wpa = wpactrl::WpaCtrl::new()
        .ctrl_path(wpa_path)
        .open()
        .context(WpaCtrlOpen)?;
    wpa.request("DISCONNECT").context(WpaCtrlRequest)?;
    wpa.request("RECONNECT").context(WpaCtrlRequest)?;
    Ok(())
}

/// Save configuration updates to the `wpa_supplicant` configuration file.
///
/// If wireless network configuration updates are successfully save to the
/// `wpa_supplicant.conf` file, an `Ok` `Result` type is returned. In the
/// event of an error, a `NetworkError` is returned in the `Result`. The
/// `NetworkError` is then enumerated to a specific error type and an
/// appropriate JSON RPC response is sent to the caller.
///
pub fn save() -> Result<(), NetworkError> {
    let mut wpa = wpactrl::WpaCtrl::new().open().context(WpaCtrlOpen)?;
    wpa.request("SAVE_CONFIG").context(WpaCtrlRequest)?;
    Ok(())
}
