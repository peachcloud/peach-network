extern crate get_if_addrs;
extern crate regex;
extern crate wpactrl;

use std::{process::Command, result::Result, str};

use probes::network;
use regex::Regex;
use serde::{Deserialize, Serialize};
use snafu::ResultExt;

use crate::error::*;

#[derive(Debug, Deserialize)]
pub struct Iface {
    pub iface: String,
}

#[derive(Debug, Serialize)]
pub struct Traffic {
    pub received: u64,
    pub transmitted: u64,
}

#[derive(Debug, Deserialize)]
pub struct WiFi {
    pub ssid: String,
    pub pass: String,
}

// struct for wpa_cli 'status' data
#[derive(Debug, Serialize)]
pub struct IfaceStatus {
    pub address: String,
    pub bssid: String,
    pub freq: String,
    pub group_cipher: String,
    pub id: String,
    pub ip_address: String,
    pub key_mgmt: String,
    pub mode: String,
    pub pairwise_cipher: String,
    pub ssid: String,
    pub wpa_state: String,
}

// activate wifi access point
pub fn activate_ap() -> Result<(), NetworkError> {
    // systemctl stop wpa_supplicant
    Command::new("sudo")
        .arg("/usr/bin/systemctl")
        .arg("stop")
        .arg("wpa_supplicant")
        .output()
        .context(StopWpaSupplicant)?;
    // ifdown wlan0
    Command::new("sudo")
        .arg("/usr/sbin/ifdown")
        .arg("wlan0")
        .output()
        .context(SetWlanInterfaceDown)?;
    // systemctl start hostapd
    Command::new("sudo")
        .arg("/usr/bin/systemctl")
        .arg("start")
        .arg("hostapd")
        .output()
        .context(StartHostapd)?;
    // systemctl start dnsmasq
    Command::new("sudo")
        .arg("/usr/bin/systemctl")
        .arg("start")
        .arg("dnsmasq")
        .output()
        .context(StartDnsmasq)?;

    Ok(())
}

// activate wifi client connection
pub fn activate_client() -> Result<(), NetworkError> {
    // systemctl stop hostap
    Command::new("sudo")
        .arg("/usr/bin/systemctl")
        .arg("stop")
        .arg("hostapd")
        .output()
        .context(StopHostapd)?;
    // systemctl stop dnsmasq
    Command::new("sudo")
        .arg("/usr/bin/systemctl")
        .arg("stop")
        .arg("dnsmasq")
        .output()
        .context(StopDnsmasq)?;
    // ifup wlan0
    Command::new("sudo")
        .arg("/usr/sbin/ifup")
        .arg("wlan0")
        .output()
        .context(SetWlanInterfaceUp)?;

    Ok(())
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

// retrieve average signal strength for specified interface
pub fn get_rssi(iface: &str) -> Result<Option<String>, NetworkError> {
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
        Ok(Some(rssi))
    } else {
        return Ok(None);
    }
}

// retrieve ssid of connected network
pub fn get_ssid(iface: &str) -> Result<Option<String>, NetworkError> {
    let wpa_path: String = format!("/var/run/wpa_supplicant/{}", iface);
    let mut wpa = wpactrl::WpaCtrl::new()
        .ctrl_path(wpa_path)
        .open()
        .context(WpaCtrlOpen)?;
    let status = wpa.request("STATUS").context(WpaCtrlRequest)?;
    let re = Regex::new(r"\nssid=(.*)\n").context(Regex)?;
    let caps = re.captures(&status);
    let ssid = match caps {
        Some(caps) => {
            let ssid_name = &mut caps[0].to_string();
            // split ssid_name at 6th character
            // & assign 2nd half to ssid
            let mut ssid = ssid_name.split_off(6);
            let len = ssid.len();
            // remove newline character
            ssid.truncate(len - 1);
            Some(ssid)
        }
        None => None,
    };

    Ok(ssid)
}

// retrieve current state for the given interface by querying operstate
pub fn get_state(iface: &str) -> Result<Option<String>, NetworkError> {
    let iface_path: String = format!("/sys/class/net/{}/operstate", iface);
    let output = Command::new("cat")
        .arg(iface_path)
        .output()
        .context(CatIfaceState { iface })?;
    if !output.stdout.is_empty() {
        let mut state = String::from_utf8(output.stdout).unwrap();
        // remove trailing newline character
        let len = state.len();
        state.truncate(len - 1);
        return Ok(Some(state));
    }

    Ok(None)
}

// retrieve current status for the given interface
// - serves aggregated interface data
pub fn get_status(iface: &str) -> Result<Option<IfaceStatus>, NetworkError> {
    let wpa_path: String = format!("/var/run/wpa_supplicant/{}", iface);
    let mut wpa = wpactrl::WpaCtrl::new()
        .ctrl_path(wpa_path)
        .open()
        .context(WpaCtrlOpen)?;
    let status = wpa.request("STATUS").context(WpaCtrlRequest)?;
    // returns an iterator over the lines in status response
    let mut status_lines = status.lines();
    if let Some(line) = status_lines.next() {
        let bssid = line;
        let freq = status_lines
            .next()
            .expect("None value unwrap for freq in get_status");
        let ssid = status_lines
            .next()
            .expect("None value unwrap for ssid in get_status");
        let id = status_lines
            .next()
            .expect("None value unwrap for id in get_status");
        let mode = status_lines
            .next()
            .expect("None value unwrap for mode in get_status");
        let pairwise_cipher = status_lines
            .next()
            .expect("None value unwrap for pairwise_cipher in get_status");
        let group_cipher = status_lines
            .next()
            .expect("None value unwrap for group_cipher in get_status");
        let key_mgmt = status_lines
            .next()
            .expect("None value unwrap for key_mgmt in get_status");
        let wpa_state = status_lines
            .next()
            .expect("None value unwrap for wpa_state in get_status");
        let ip_address = status_lines
            .next()
            .expect("None value unwrap for ip_address in get_status");
        // skip line containing p2p_device_address
        status_lines.next();
        let address = status_lines
            .next()
            .expect("None value unwrap for address in get_status");

        // assign values to struct fields, splitting after the `=` sign
        let iface_status = IfaceStatus {
            address: address.to_string().split_off(8),
            bssid: bssid.to_string().split_off(6),
            freq: freq.to_string().split_off(5),
            group_cipher: group_cipher.to_string().split_off(13),
            id: id.to_string().split_off(3),
            ip_address: ip_address.to_string().split_off(11),
            key_mgmt: key_mgmt.to_string().split_off(9),
            mode: mode.to_string().split_off(5),
            pairwise_cipher: pairwise_cipher.to_string().split_off(16),
            ssid: ssid.to_string().split_off(5),
            wpa_state: wpa_state.to_string().split_off(10),
        };

        Ok(Some(iface_status))
    } else {
        return Ok(None);
    }
}

// retrieve network traffic stats for given interface
pub fn get_traffic(iface: &str) -> Result<Option<String>, NetworkError> {
    let network = network::read().context(ReadTraffic { iface })?;
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

// run the interface checker script for ap-client mode switching
pub fn run_iface_script() -> Result<(), NetworkError> {
    Command::new("sudo")
        .arg("/bin/bash")
        .arg("/home/glyph/interface_checker.sh")
        .output()
        .context(RunApClientScript)?;
    Ok(())
}

// list all wireless networks in range of the given interface
pub fn scan_networks(iface: &str) -> Result<Option<Vec<String>>, NetworkError> {
    let wpa_path: String = format!("/var/run/wpa_supplicant/{}", iface);
    let mut wpa = wpactrl::WpaCtrl::new()
        .ctrl_path(wpa_path)
        .open()
        .context(WpaCtrlOpen)?;
    wpa.request("SCAN").context(WpaCtrlRequest)?;
    let networks = wpa.request("SCAN_RESULTS").context(WpaCtrlRequest)?;
    let mut ssids = Vec::new();
    for network in networks.lines() {
        let v: Vec<&str> = network.split('\t').collect();
        let len = v.len();
        if len > 1 {
            ssids.push(v[4].to_string());
        }
    }

    if ssids.is_empty() {
        Ok(None)
    } else {
        Ok(Some(ssids))
    }
}

/*
 * Further functions to be implemented:
 *  - remove_network
 */
