## peach-network

Networking microservice module for PeachCloud. Query and configure device interfaces using [JSON-RPC](https://www.jsonrpc.org/specification) over http.

Interaction with wireless interfaces occurs primarily through the [wpactrl crate](https://docs.rs/wpactrl/0.3.1/wpactrl/) which provides "a pure-Rust lowlevel library for controlling wpasupplicant remotely". This approach is akin to using `wpa_cli` (a WPA command line client).

_Note: This module is a work-in-progress._

### JSON-RPC API

| Method | Parameters | Description |
| --- | --- | --- |
| `get_ip` | `iface` | Return IP for given network interface |
| `get_ssid` | | Return SSID of currently-connected network |
| `if_checker` | | Run AP / client-mode configuration script |
| `list_networks` | `iface` | List available networks for given network interface |
| `add_wifi` | `ssid`, `pass` | Connect to WiFi with given SSID and password |
| `reconnect_wifi` | `iface` | Disconnect and reconnect given network interface |
| `reassociate_wifi` | `iface` | Reassociate with current AP for given network interface |

### Setup

Clone this repo:

`git clone https://github.com/peachcloud/peach-network.git`

Move into the repo and compile:

`cd peach-network`  
`cargo build`

Run the binary (sudo needed to satisfy permission requirements):

`sudo ./target/debug/peach-network`

### Example Usage

**Retrieve IP address for wlan0**

With microservice running, open a second terminal window and use `curl` to call server methods:

`curl -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method": "get_ip", "params" : {"iface": "wlan0" }, "id":1 }' 127.0.0.1:5000`

Server responds with:

`{"jsonrpc":"2.0","result":"192.168.1.21","id":1}`

### Licensing

AGPL-3.0
