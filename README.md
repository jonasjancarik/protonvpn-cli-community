# ProtonVPN CLI

This is a fork of https://github.com/Rafficer/linux-cli-community with some new features, such as:
- HTTP API
- Docker setup
- whitelist/blacklists 

While an [official ProtonVPN Linux](https://protonvpn.com/blog/protonvpn-linux-app/) app is available, at this point it still doesn't include a command-line interface. This community Linux client is useful for automatad workflows, including in Docker Compose setups where it can serve as a VPN client for other containers.

## Installation & Updating

### Manual Installation from source

It is recommended to do the manual installation in a virtual environment. Especially if it serves the purpose of developing.

1. Clone this repository

    `git clone https://github.com/jonasjancarik/protonvpn-cli-community`

2. Step into the directory

   `cd protonvpn-cli-community`

3. Install

    `pip3 install -e .`

For updating, you just need to pull the latest version of the repository with git.

### Docker Compose

See the example in `docker-compose.yml` which will set up an example service and networking to route all requests from the example service through the ProtonVPN client.

To control the client from the other containers, use the HTTP API (see below). Due to the way the networking is set up, `localhost` points to the ProtonVPN container, meaning API requests should also be directed to http://localhost:8000/.

#### Setup Instructions

1. Create a `.env` file in the same directory as your `docker-compose.yml` with your ProtonVPN credentials:

   ```
   PROTONVPN_USERNAME=your_username
   PROTONVPN_PASSWORD=your_password
   PROTONVPN_TIER=2  # Optional, defaults to 1
   PROTONVPN_PROTOCOL=udp  # Optional, defaults to udp
   ```

2. Start the containers:

   ```bash
   docker-compose up -d
   ```

3. Check the logs to ensure the VPN connection is established:

   ```bash
   docker-compose logs -f protonvpn-cli
   ```

#### How It Works

The Docker setup uses a custom entrypoint script (`vpn-entrypoint.sh`) that:

1. Installs the ProtonVPN CLI package
2. Enables IP forwarding for network routing
3. Sets up iptables for NAT (Network Address Translation)
4. Connects to ProtonVPN using the provided credentials
5. Starts the HTTP API server on port 8000

The example service (`example-service`) uses `network_mode: "service:protonvpn-cli"` to share the network namespace with the ProtonVPN container, ensuring all its traffic is routed through the VPN.

#### Customization Options

You can customize the Docker setup by:

- Changing the VPN connection parameters in the `.env` file
- Modifying the `vpn-entrypoint.sh` script to use different connection options
- Adding more services that use the VPN by setting `network_mode: "service:protonvpn-cli"`
- Adjusting the API port by setting the `API_PORT` environment variable

#### Security Considerations

- The ProtonVPN container runs with `privileged: true` and requires `NET_ADMIN` and `SYS_MODULE` capabilities to set up the VPN tunnel
- The kill switch is enabled in the docker-compose.yml file (`VPN_ENABLE_KILLSWITCH=true`) for better security
- Your ProtonVPN credentials are stored in the `.env` file, which should be kept secure and not committed to version control

For more detailed Docker setup instructions, including development container configuration and troubleshooting, see [DOCKER.md](DOCKER.md).

## How to use

### Command-line interface

| **Command**                       | **Description**                                       |
|:----------------------------------|:------------------------------------------------------|
|`protonvpn init`                   | Initialize ProtonVPN profile.                         |
|`protonvpn connect, c`             | Select a ProtonVPN server and connect to it.          |
|`protonvpn c [servername]`         | Connect to a specified server.                        |
|`protonvpn c -r`                   | Connect to a random server.                           |
|`protonvpn c -f`                   | Connect to the fastest server.                        |
|`protonvpn c --p2p`                | Connect to the fastest P2P server.                    |
|`protonvpn c --cc [countrycode]`   | Connect to the fastest server in a specified country. |
|`protonvpn c --sc`                 | Connect to the fastest Secure Core server.            |
|`protonvpn reconnect, r`           | Reconnect or connect to the last server used.         |
|`protonvpn disconnect, d`          | Disconnect the current session.                       |
|`protonvpn status, s`              | Print connection status.                              |
|`protonvpn configure`              | Change CLI configuration.                             |
|`protonvpn refresh`                | Refresh OpenVPN configuration and server data.        |
|`protonvpn examples`               | Print example commands.                               |
|`protonvpn --version`              | Display version.                                      |
|`protonvpn --help`                 | Show help message.                                    |

All connect options can be used with the `-p` flag to explicitly specify which transmission protocol is used for that connection (either `udp` or `tcp`).

### HTTP API

The ProtonVPN CLI includes an HTTP API that allows you to control the VPN programmatically. The API is built with FastAPI and can be started using the `protonvpn-cli-api` command.

#### Starting the API Server

```bash
protonvpn-cli-api
```

By default, the API server runs on `http://localhost:8000`. You can also start it programmatically:

```python
from protonvpn_cli.api import start_api

# Start the API server on a specific host and port
start_api(host="0.0.0.0", port=8000)
```

#### API Endpoints

| **Endpoint** | **Method** | **Description** |
|:-------------|:-----------|:----------------|
| `/init` | POST | Initialize ProtonVPN with credentials |
| `/connect` | POST | Connect to ProtonVPN |
| `/disconnect` | POST | Disconnect from ProtonVPN |
| `/status` | GET | Get VPN connection status |
| `/reconnect` | POST | Reconnect to the last server |

#### Example Requests

##### Initialize ProtonVPN

```bash
curl -X POST "http://localhost:8000/init" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "your_username",
    "password": "your_password",
    "tier": 2,
    "protocol": "udp",
    "force": false
  }'
```

##### Connect to a Specific Server

```bash
curl -X POST "http://localhost:8000/connect" \
  -H "Content-Type: application/json" \
  -d '{
    "server": "US",
    "protocol": "udp"
  }'
```

##### Connect to Fastest Server

```bash
curl -X POST "http://localhost:8000/connect" \
  -H "Content-Type: application/json" \
  -d '{
    "fastest": true,
    "protocol": "udp"
  }'
```

##### Connect to a Specific Country

```bash
curl -X POST "http://localhost:8000/connect" \
  -H "Content-Type: application/json" \
  -d '{
    "country_code": "US",
    "protocol": "udp"
  }'
```

##### Check VPN Status

```bash
curl -X GET "http://localhost:8000/status"
```

##### Disconnect from VPN

```bash
curl -X POST "http://localhost:8000/disconnect"
```

##### Reconnect to the Last Server

```bash
curl -X POST "http://localhost:8000/reconnect"
```

#### Python Example

```python
import requests

# Base URL for the API
base_url = "http://localhost:8000"

# Connect to a specific server
def connect_to_server(server="US"):
    url = f"{base_url}/connect"
    payload = {
        "server": server,
        "protocol": "udp"
    }
    response = requests.post(url, json=payload)
    return response.json()

# Check VPN status
def check_status():
    url = f"{base_url}/status"
    response = requests.get(url)
    return response.json()

# Example usage
if __name__ == "__main__":
    # Connect to a specific server
    connect_result = connect_to_server("US")
    print("Connection result:", connect_result)
    
    # Check status
    status = check_status()
    print("VPN status:", status)
```

#### API Documentation

When the API server is running, you can access the interactive API documentation at:

- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

These provide detailed information about all available endpoints, request/response schemas, and allow you to test the API directly from your browser.
