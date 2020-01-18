# peach-network

[![Build Status](https://travis-ci.com/peachcloud/peach-network.svg?branch=master)](https://travis-ci.com/peachcloud/peach-network)

Networking microservice module for PeachCloud. Query and configure device interfaces using [JSON-RPC](https://www.jsonrpc.org/specification) over http.

Interaction with wireless interfaces occurs primarily through the [wpactrl crate](https://docs.rs/wpactrl/0.3.1/wpactrl/) which provides "a pure-Rust lowlevel library for controlling wpasupplicant remotely". This approach is akin to using `wpa_cli` (a WPA command line client).

_Note: This module is a work-in-progress._

### JSON-RPC API

| Method | Parameters | Description |
| --- | --- | --- |
| `activate_ap` | | Activate WiFi access point (stop `wpa_supplicant` and start `hostapd` and `dnsmasq`) |
| `activate_client` | | Activate WiFi client connection (stop `hostapd` and `dnsmasq` and start `wpa_supplicant`) |
| `add_wifi` | `ssid`, `pass` | Add WiFi credentials to `wpa_supplicant.conf` |
| `get_ip` | `iface` | Return IP of given network interface |
| `get_rssi` | `iface` | Return average signal strength for given interface |
| `get_ssid` | `iface` | Return SSID of currently-connected network for given interface |
| `get_state` | `iface` | Return state of given interface |
| `get_status` | `iface` | Return status parameters for given interface |
| `get_traffic` | `iface` | Return network traffic for given interface |
| `if_checker` | | Run AP / client-mode configuration script |
| `list_networks` | | List all networks saved in wpasupplicant config |
| `ping` | | Respond with `success` if microservice is running |
| `scan_networks` | `iface` | List SSID, flags (security), frequency and signal level for all networks in range of given interface |
| `reconnect_wifi` | `iface` | Disconnect and reconnect given interface |
| `reassociate_wifi` | `iface` | Reassociate with current AP for given interface |

### Environment

The JSON-RPC HTTP server address and port can be configured with the `PEACH_NETWORK_SERVER` environment variable:

`export PEACH_NETWORK_SERVER=127.0.0.1:5000`

When not set, the value defaults to `127.0.0.1:5110`.

Logging is made available with `env_logger`:

`export RUST_LOG=info`

Other logging levels include `debug`, `warn` and `error`.

### Setup

Clone this repo:

`git clone https://github.com/peachcloud/peach-network.git`

Move into the repo and compile:

`cd peach-network`  
`cargo build --release`

Run the binary (sudo needed to satisfy permission requirements):

`sudo ./target/release/peach-network`

### Example Usage

**Retrieve IP address for wlan0**

With microservice running, open a second terminal window and use `curl` to call server methods:

`curl -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method": "get_ip", "params" : {"iface": "wlan0" }, "id":1 }' 127.0.0.1:5000`

Server responds with:

`{"jsonrpc":"2.0","result":"192.168.1.21","id":1}`

**Retrieve SSID of connected access point for wlan1**

`curl -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method": "get_ssid", "params" : {"iface": "wlan1" }, "id":1 }' 127.0.0.1:5000`

Server response when interface is connected:

`{"jsonrpc":"2.0","result":"Home","id":1}`

Server response when interface is not connected:

`{"jsonrpc":"2.0","error":{"code":-32003,"message":"Failed to retrieve SSID for wlan1. Interface may not be connected."},"id":1}`

**Retrieve list of SSIDs for all networks in range of wlan0**

`curl -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method": "scan_networks", "params" : {"iface": "wlan0" }, "id":1 }' 127.0.0.1:5000`

Server response when interface is connected:

`{"jsonrpc":"2.0","result":"[{\"frequency\":\"2412\",\"signal_level\":\"-72\",\"ssid\":\"Home\",\"flags\":\"[WPA2-PSK-CCMP][ESS]\"},{\"frequency\":\"2472\",\"signal_level\":\"-56\",\"ssid\":\"podetium\",\"flags\":\"[WPA2-PSK-CCMP+TKIP][ESS]\"}]","id":1}`

Server response when interface is not connected:

`{"jsonrpc":"2.0","error":{"code":-32006,"message":"No networks found in range of wlan0"},"id":1}`

**Retrieve network traffic statistics for wlan1**

`curl -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method": "get_traffic", "params" : {"iface": "wlan1" }, "id":1 }' 127.0.0.1:5000`

Server response if interface exists:

`{"jsonrpc":"2.0","result":"{\"received\":26396361,\"transmitted\":22352530}","id":1}`

Server response when interface is not found:

`{"jsonrpc":"2.0","error":{"code":-32004,"message":"Failed to retrieve network traffic for wlan3. Interface may not be connected"},"id":1}`

**Retrieve status information for wlan0**

`curl -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method": "get_status", "params" : {"iface": "wlan0" }, "id":1 }' 127.0.0.1:5110`

Server response if interface exists:

`{"jsonrpc":"2.0","result":"{\"address\":\"b8:27:eb:9b:5d:5f\",\"bssid\":\"f4:8c:eb:cd:31:81\",\"freq\":\"2412\",\"group_cipher\":\"CCMP\",\"id\":\"0\",\"ip_address\":\"192.168.0.162\",\"key_mgmt\":\"WPA2-PSK\",\"mode\":\"station\",\"pairwise_cipher\":\"CCMP\",\"ssid\":\"Home\",\"wpa_state\":\"COMPLETED\"}","id":1}`

Server response when interface is not found:

`{"jsonrpc":"2.0","error":{"code":-32013,"message":"Failed to open control interface for wpasupplicant: No such file or directory (os error 2)"},"id":1}`

### Licensing

AGPL-3.0
