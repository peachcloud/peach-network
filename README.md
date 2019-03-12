## peach-network

Networking microservice module for PeachCloud. Query and configure device interfaces using [JSON-RPC](https://www.jsonrpc.org/specification) over http.

### Setup

Clone this repo:

`git clone https://github.com/peachcloud/peach-network.git`

Move into the repo and compile:

`cd peach-network`  
`cargo build`

Run the binary (sudo needed to satisfy permission requirements):

`sudo ./target/debug/peach-network`

-----

### API

| Method | Parameters | Description |
| --- | --- | --- |
| `get_ip` | `iface` | Return IP for given network interface |
| `get_ssid` | | Return SSID of currently-connected network |
| `if_down` | `iface` | Take the given network interface down |
| `if_up` | `iface` | Bring the given network interface up |
| `if_checker` | | Run AP / client-mode configuration script |
| `add_wifi` | ssid, pass | Connect to WiFi with given SSID and password |

### Licensing

AGPL-3.0
