extern crate get_if_addrs;
extern crate regex;
extern crate wpactrl;

use std::{process::Command, result::Result, str};

use regex::Regex;
use serde::Deserialize;
use snafu::ResultExt;

use crate::error::*;

#[derive(Debug, Deserialize)]
pub struct Iface {
    pub iface: String,
}

#[derive(Debug, Deserialize)]
pub struct WiFi {
    pub ssid: String,
    pub pass: String,
}

// retrieve ip address for specified interface
pub fn get_ip(iface: &str) -> Result<Option<String>, NetworkError> {
    let net_if: String = iface.to_string();
    let ifaces = get_if_addrs::get_if_addrs().context(GetIp { iface: net_if })?;
    let ip = ifaces
        .iter()
        .find(|&i| i.name == iface)
        .map(|iface| iface.ip().to_string());

    Ok(ip)
}

// retrieve ssid of connected network
pub fn get_ssid(iface: &str) -> Result<Option<String>, NetworkError> {
    let wpa_path: String = format!("/var/run/wpa_supplicant/{}", iface);
    let mut wpa = wpactrl::WpaCtrl::new()
        .ctrl_path(wpa_path)
        .open()
        .context(WpaCtrlOpen)?;
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
pub fn add_wifi(wifi: &WiFi) -> Result<(), NetworkError> {
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
pub fn reconnect_wifi(iface: &str) -> Result<(), NetworkError> {
    let wpa_path: String = format!("/var/run/wpa_supplicant/{}", iface);
    let mut wpa = wpactrl::WpaCtrl::new()
        .ctrl_path(wpa_path)
        .open()
        .context(WpaCtrlOpen)?;
    wpa.request("DISCONNECT").context(WpaCtrlRequest)?;
    wpa.request("RECONNECT").context(WpaCtrlRequest)?;
    Ok(())
}

// reassociate the wireless interface
pub fn reassociate_wifi(iface: &str) -> Result<(), NetworkError> {
    let wpa_path: String = format!("/var/run/wpa_supplicant/{}", iface);
    let mut wpa = wpactrl::WpaCtrl::new()
        .ctrl_path(wpa_path)
        .open()
        .context(WpaCtrlOpen)?;
    wpa.request("REASSOCIATE").context(WpaCtrlRequest)?;
    Ok(())
}

// run the interface checker script for ap-client mode switching
pub fn run_iface_script() -> Result<(), NetworkError> {
    Command::new("sudo")
        .arg("/bin/bash")
        .arg("/home/glyph/interface_checker.sh")
        .output()
        .context(RunApClientScript)?;
    Ok(())
}

// list all wireless networks saved to the wpasupplicant config
pub fn list_networks() -> Result<Option<Vec<String>>, NetworkError> {
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
