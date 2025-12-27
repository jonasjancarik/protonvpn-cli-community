# ProtonVPN-CLI Usage Documentation

This document provides an extensive guide on how to install and use this fork of ProtonVPN-CLI, as well as explanations about its advanced features like the HTTP API, Docker support, and optional enhancements.

**Note:** ProtonVPN now offers an [official Linux app](https://protonvpn.com/support/official-linux-client) with a graphical user interface, which may be preferred for desktop users. This community CLI remains useful for server environments, automation, Docker, and users who prefer a command-line interface.

## Table of Contents

- [ProtonVPN-CLI Usage Documentation](#protonvpn-cli-usage-documentation)
  - [Table of Contents](#table-of-contents)
  - [Installation & Updating](#installation--updating)
    - [Quick Install from GitHub (pip/uv)](#quick-install-from-github-pipuv)
    - [Manual Installation from Source (Recommended for Development)](#manual-installation-from-source-recommended-for-development)
      - [Dependencies](#dependencies)
      - [Install Steps](#install-steps)
      - [Updating](#updating)
      - [Uninstall](#uninstall)
    - [Installing in a virtual environment (Alternative)](#installing-in-a-virtual-environment-alternative)
      - [Install](#install)
      - [Update](#update)
      - [Uninstall](#uninstall-1)
    - [Installation via Docker Compose (for Container VPN)](#installation-via-docker-compose-for-container-vpn)
  - [Initialization](#initialization)
    - [Interactive Initialization](#interactive-initialization)
    - [Non-Interactive Initialization](#non-interactive-initialization)
    - [Initialization Steps Detail](#initialization-steps-detail)
  - [Commands](#commands)
    - [List of all Commands](#list-of-all-commands)
    - [Command Explanations](#command-explanations)
  - [Features](#features)
    - [DNS Management](#dns-management)
      - [DNS Leak Protection](#dns-leak-protection)
      - [Custom DNS](#custom-dns)
      - [Disabling DNS Management](#disabling-dns-management)
    - [IPv6 Leak Protection](#ipv6-leak-protection)
    - [Kill Switch](#kill-switch)
    - [Split Tunneling](#split-tunneling)
    - [Custom OpenVPN Down Script](#custom-openvpn-down-script)
  - [HTTP API](#http-api)
    - [Starting the API Server](#starting-the-api-server)
    - [API Endpoints](#api-endpoints)
    - [Example Requests](#example-requests)
    - [API Documentation](#api-documentation)
  - [Enhancements](#enhancements)
    - [Disable sudo password query](#disable-sudo-password-query)
    - [Configure alias for quicker access](#configure-alias-for-quicker-access)
    - [Auto-connect on boot](#auto-connect-on-boot)
      - [via Systemd Service](#via-systemd-service)

## Installation & Updating

### Quick Install from GitHub (pip/uv)

If you don't need to modify the source code, you can install directly from GitHub. Both the `master` branch and official [GitHub Releases](https://github.com/jonasjancarik/protonvpn-cli-community/releases) are supported:

```bash
# Using pip (latest release):
sudo pip3 install git+https://github.com/jonasjancarik/protonvpn-cli-community.git@v3.1.1

# Or using uv (latest release):
sudo uv pip install git+https://github.com/jonasjancarik/protonvpn-cli-community.git@v3.1.1 --system
```

To install the bleeding-edge version from the `master` branch:
`sudo pip3 install git+https://github.com/jonasjancarik/protonvpn-cli-community.git`

**To update**, add `--upgrade`:

```bash
sudo pip3 install --upgrade git+https://github.com/jonasjancarik/protonvpn-cli-community.git@v3.1.1
# or
sudo uv pip install --upgrade git+https://github.com/jonasjancarik/protonvpn-cli-community.git@v3.1.1 --system
```

Updates are also announced via the CLI and tracked on the GitHub Releases page.

> [!NOTE]
> This method installs the package globally and requires root privileges because `protonvpn` must manage network interfaces.

### Manual Installation from Source (Recommended for Development)

This is the primary method for installing this specific fork (`jonasjancarik/protonvpn-cli-community`).

#### Dependencies

First, ensure you have the necessary system-level dependencies installed:

-   `python3` (Version 3.5+ required)
-   `python3-pip`
-   `python3-setuptools`
-   `git`
-   `openvpn`
-   `dialog` (optional, needed for interactive server selection)
-   `iptables` & `ip6tables`
-   `iproute2` (provides `ip` command)
-   `procps` (provides `pgrep`, `pkill`)
-   `coreutils` (provides `sysctl`)
-   `python3-distro` (Python library)

Use your distribution's package manager to install them. Example commands:

| **Distro** | **Command** |
| :-------------------------------------- | :---------------------------------------------------------------------------------------------------------------------------- |
| Fedora/CentOS/RHEL                      | `sudo dnf install -y git openvpn dialog iptables iproute procps-ng coreutils python3-pip python3-setuptools python3-distro`        |
| Ubuntu/Linux Mint/Debian and derivatives | `sudo apt update && sudo apt install -y git openvpn dialog iptables iproute2 procps coreutils python3-pip python3-setuptools python3-distro` |
| OpenSUSE/SLES                           | `sudo zypper ref && sudo zypper in -y git openvpn dialog iptables iproute2 procps coreutils python3-pip python3-setuptools python3-distro` |
| Arch Linux/Manjaro                      | `sudo pacman -Syu --needed git openvpn dialog iptables iproute2 procps-ng coreutils python-pip python-setuptools python-distro`     |

*Note: Package names might vary slightly.*

#### Install Steps

1.  **Clone the repository:**
    ```sh
    git clone https://github.com/jonasjancarik/protonvpn-cli-community.git
    ```

2.  **Navigate into the directory:**
    ```sh
    cd protonvpn-cli-community
    ```

3.  **Install using pip:**
    ```sh
    sudo pip3 install -e .
    ```
    * `sudo` is used because the `protonvpn` command typically needs root privileges to manage network interfaces and rules, and this installs it globally.
    * `-e` installs the package in "editable" mode, meaning changes pulled via `git pull` in the source directory are reflected immediately without reinstalling. Python dependencies (`requests`, `fastapi`, etc.) are installed automatically.

You should now be able to run `sudo protonvpn --version`.

#### Updating

1.  Navigate to the cloned repository directory:
    ```sh
    cd path/to/protonvpn-cli-community
    ```
2.  Pull the latest changes from GitHub:
    ```sh
    git pull origin master # Or the relevant branch
    ```
    Because it was installed with `-e`, the updates are immediately available. If dependencies in `setup.py` changed, you might need to run `sudo pip3 install -e .` again.

#### Uninstall

1.  Uninstall the package using pip:
    ```sh
    sudo pip3 uninstall protonvpn-cli
    ```
2.  Remove the cloned repository directory:
    ```sh
    rm -rf path/to/protonvpn-cli-community
    ```
3.  Consider purging the configuration first (optional): `sudo protonvpn configure` -> Option 8.

### Installing in a virtual environment (Alternative)

If you prefer not to install globally, use a Python virtual environment.

#### Install

1.  Install the system dependencies (see [Dependencies](#dependencies) above).
2.  Install `virtualenv`:
    ```sh
    pip3 install virtualenv --user
    ```
3.  Clone the repository:
    ```sh
    git clone https://github.com/jonasjancarik/protonvpn-cli-community.git ~/protonvpn-cli-community-venv-src
    ```
4.  Create and activate a virtual environment:
    ```sh
    virtualenv ~/protonvpn-cli-venv
    source ~/protonvpn-cli-venv/bin/activate
    ```
5.  Install the package in editable mode from the cloned source *within* the virtual environment:
    ```sh
    pip install -e ~/protonvpn-cli-community-venv-src
    ```
6.  Verify the executable path within the venv:
    ```sh
    which protonvpn
    # Should output something like /home/youruser/protonvpn-cli-venv/bin/protonvpn
    ```
7.  Deactivate:
    ```sh
    deactivate
    ```
8.  Create a system-wide symbolic link to the executable within the venv (replace the source path with the output from step 6):
    ```sh
    sudo ln -sf ~/protonvpn-cli-venv/bin/protonvpn /usr/local/bin/protonvpn
    ```
    Now you can run `sudo protonvpn ...` system-wide, but it uses the installation inside the virtual environment.

#### Update

1.  Navigate to the *source* directory:
    ```sh
    cd ~/protonvpn-cli-community-venv-src
    ```
2.  Pull the latest changes:
    ```sh
    git pull origin master
    ```
3.  Activate the virtual environment:
    ```sh
    source ~/protonvpn-cli-venv/bin/activate
    ```
4.  Update dependencies if necessary (usually needed only if `setup.py` changed):
    ```sh
    pip install -e .
    ```
5.  Deactivate:
    ```sh
    deactivate
    ```

#### Uninstall

1.  Purge configuration (optional): `sudo protonvpn configure` -> Option 8.
2.  Remove the symbolic link:
    ```sh
    sudo rm /usr/local/bin/protonvpn
    ```
3.  Remove the virtual environment directory:
    ```sh
    rm -rf ~/protonvpn-cli-venv
    ```
4.  Remove the source code directory:
    ```sh
    rm -rf ~/protonvpn-cli-community-venv-src
    ```

### Installation via Docker Compose (for Container VPN)

**This method runs ProtonVPN-CLI inside a Docker container, primarily intended to provide a VPN connection for *other Docker containers* within the same Docker Compose setup. It does *not* directly VPN the host machine's traffic.**

1.  **Prerequisites:** Docker and Docker Compose.
2.  **Configuration:** Create a `.env` file in your project directory with your credentials:
    ```env
    PROTONVPN_USERNAME=your_openvpn_username
    PROTONVPN_PASSWORD=your_openvpn_password
    PROTONVPN_TIER=3 # Optional: 1=Free, 2=Basic, 3=Plus/Visionary (default: 1)
    PROTONVPN_PROTOCOL=udp # Optional: udp or tcp (default: udp)
    # VPN_ENABLE_KILLSWITCH=true # Optional: uncomment to enable kill switch
    # API_PORT=8000 # Optional: Port for the HTTP API (default: 8000)
    ```
3.  **Docker Compose:** Use or adapt the provided `docker-compose.yml` from the repository. It includes the `protonvpn-cli` service and an example service (`example-service`) routed through the VPN.
4.  **Start:**
    ```bash
    docker-compose up -d
    ```
5.  **Usage:**
    * The container automatically initializes and connects based on the `.env` file.
    * Other services use `network_mode: "service:protonvpn-cli"` to route their traffic through the VPN container.
    * Manage the VPN via the [HTTP API](#http-api) (available at `http://localhost:8000` from within linked containers) or `docker exec`:
        ```bash
        docker exec -it <protonvpn-container-name> protonvpn status
        docker exec -it <protonvpn-container-name> protonvpn disconnect
        ```

For more details, refer to the `README.md` and `DOCKER.md` files in the source code repository.

## Initialization

Before you can use ProtonVPN-CLI, you need to initialize it with your account details.

### Interactive Initialization

Run the initialization command and follow the prompts:

```sh
sudo protonvpn init
```

You will be asked for:

1.  **OpenVPN Username and Password:** Find these in your ProtonVPN Account page under Account -> OpenVPN / IKEv2 username. *These are different from your main Proton account login.*
2.  **Your ProtonVPN Tier:** Select the plan you are subscribed to (or trial plan).
    * 1: Free
    * 2: Basic
    * 3: Plus
    * 4: Visionary (Functionally equivalent to Plus for server access)
3.  **Default Protocol:** Choose between UDP (faster) or TCP (more reliable, better for restricted networks).

Confirm your details to save the configuration.

### Non-Interactive Initialization

You can provide credentials and settings via command-line flags, useful for automation or scripting:

```sh
sudo protonvpn init --username "YOUR_OVPN_USERNAME" --password "YOUR_OVPN_PASSWORD" --tier 3 --protocol udp
```

* `--username <username>`: Your OpenVPN username.
* `--password <password>`: Your OpenVPN password.
* `--tier <tier>`: Your plan (1, 2, 3, or 4).
* `--protocol <protocol>`: Your default protocol (`udp` or `tcp`).
* `--force`: Skip confirmation if re-initializing an existing profile.

### Initialization Steps Detail

The initialization process (`protonvpn init`) performs the following actions:

1.  Creates the configuration directory (`~/.pvpn-cli/` for the user running sudo).
2.  Prompts for or receives credentials, tier, and protocol.
3.  Stores the username, tier, protocol, and other default settings in `~/.pvpn-cli/pvpn-cli.cfg`.
4.  Creates a password file `~/.pvpn-cli/pvpnpass` containing the username (with `+plc` suffix) and password for OpenVPN authentication. Sets permissions to 600.
5.  Pulls the latest server information from the ProtonVPN API and saves it to `~/.pvpn-cli/serverinfo.json`.
6.  Sets the `initialized` flag in the configuration file.

## Commands

### List of all Commands

Based on the `docopt` definition in `cli.py`:

| **Command** | **Description** |
| :---------------------------------------- | :------------------------------------------------------------------------------ |
| `protonvpn init [...]`                    | Initialize ProtonVPN profile. Accepts `--username`, `--password`, `--tier`, `-p`/`--protocol`, `--force`. |
| `protonvpn (c \| connect) [<servername>]` | Connect to a specific server (e.g., `US-NY#6`, `CH-US-1`).                      |
| `protonvpn (c \| connect) -f`             | Connect to the fastest available server (non-SC, non-Tor).                      |
| `protonvpn (c \| connect) -r`             | Connect to a random server.                                                     |
| `protonvpn (c \| connect) --cc <code>`    | Connect to the fastest server in a specific country (e.g., `--cc US`).          |
| `protonvpn (c \| connect) --sc`           | Connect to the fastest Secure Core server.                                      |
| `protonvpn (c \| connect) --p2p`          | Connect to the fastest P2P-enabled server.                                      |
| `protonvpn (c \| connect) --tor`          | Connect to the fastest Tor-enabled server.                                      |
| `protonvpn (c \| connect)`                | Select a server interactively via a menu (requires `dialog` package).           |
| `protonvpn (r \| reconnect)`              | Reconnect to the last used server and protocol.                                 |
| `protonvpn (d \| disconnect)`             | Disconnect the current VPN session.                                             |
| `protonvpn (s \| status)`                 | Print connection status information (IP, server, time, data transfer, etc.).    |
| `protonvpn configure`                     | Change CLI configuration settings interactively.                                |
| `protonvpn refresh`                       | Refresh OpenVPN configuration and server data from the API.                     |
| `protonvpn examples`                      | Print example commands.                                                         |
| `protonvpn api [...]`                     | Start the HTTP API server. Accepts `--host` and `--port`.                       |
| `protonvpn (-h \| --help)`                | Show the help message.                                                          |
| `protonvpn (-v \| --version)`             | Display the installed version (e.g., 2.2.12).                                   |

**Common Options for `connect`:**

* `-p <protocol>`, `--protocol <protocol>`: Specify the protocol (`udp` or `tcp`) for *this connection only*, overriding the default.
* `--st <IP>`, `--split-tunnel <IP>`: Enable split tunneling for this connection, excluding/including the specified IP, CIDR, or domain (comma-separated). *Requires split tunneling to be configured/enabled.*
* `--stt <type>`, `--split-tunnel-type <type>`: Specify split tunnel type (`whitelist` or `blacklist`) for this connection when using `--st`.

### Command Explanations

**Most commands require root privileges, so use `sudo` (e.g., `sudo protonvpn connect`).**

* **`init`**: Sets up your profile. See [Initialization](#initialization).
* **`connect` / `c`**: Establishes a VPN connection.
    * Without arguments: Opens an interactive TUI menu to select country, server, and protocol (requires `dialog`).
    * `<servername>`: Connects directly (e.g., `sudo protonvpn c JP-HK-01`, `sudo protonvpn c usny6`). Format is flexible.
    * `-f` / `--fastest`: Connects to the server with the best score (latency/load), excluding Secure Core and Tor servers.
    * `-r` / `--random`: Connects to a randomly chosen server allowed by your tier.
    * `--cc <code>`: Connects to the fastest server within the specified country code (e.g., `sudo protonvpn c --cc DE`).
    * `--sc`: Connects to the fastest Secure Core server.
    * `--p2p`: Connects to the fastest P2P-enabled server.
    * `--tor`: Connects to the fastest Tor-enabled server.
    * `-p <protocol>`: Overrides the default protocol for this connection (e.g., `sudo protonvpn c -f -p tcp`).
    * `--st <targets>` / `--stt <type>`: Use split tunneling for this specific connection (see [Split Tunneling](#split-tunneling)).
* **`reconnect` / `r`**: Disconnects if needed, then connects to the server and protocol stored from the *last successful connection*. Useful if the connection dropped.
* **`disconnect` / `d`**: Terminates the current OpenVPN session and restores network settings (DNS, IPv6, Kill Switch rules).
* **`status` / `s`**: Shows current connection details: Status (Connected/Disconnected), IP Address, ISP, Server Name, Features, Protocol, Kill Switch status, Location (Country/City), Server Load, Connection Time, Data Transferred (Received/Sent). Does *not* require root.
* **`configure`**: Opens an interactive menu to modify settings stored in `pvpn-cli.cfg`:
    1.  Username and Password
    2.  ProtonVPN Plan (Tier)
    3.  Default Protocol (UDP/TCP)
    4.  DNS Management (Leak Protection / Custom / Disabled)
    5.  Kill Switch (Disabled / Enabled-Block LAN / Enabled-Allow LAN)
    6.  Split Tunneling (Enable/Disable, Whitelist/Blacklist, Manage IPs)
    7.  Lost Connection Options (Manage OpenVPN's `ping-restart` and `ping-exit` behavior)
    8.  Purge Configuration (Deletes the `~/.pvpn-cli` directory after disconnecting)
* **`refresh`**: Forces an update of the server list (`serverinfo.json`) from the ProtonVPN API. Useful if servers seem outdated.
* **`examples`**: Prints usage examples for various connect commands.
* **`api`**: Starts the [HTTP API](#http-api) server (requires `fastapi` and `uvicorn`).
    * `--host <host>`: IP address to bind the server to (default: `127.0.0.1`).
    * `--port <port>`: Port to listen on (default: `8000`).
* `--help`, `--version`: Standard help and version flags.

## Features

### DNS Management

Managed via `sudo protonvpn configure` -> Option 4.

#### DNS Leak Protection

* **Purpose:** Prevents your DNS queries (website lookups) from leaking to your ISP or other third parties by forcing traffic through ProtonVPN's DNS servers (or custom ones).
* **Mechanism:** When connecting, backs up `/etc/resolv.conf`, then modifies it to contain *only* the designated VPN DNS server(s). On disconnect, the original file is restored (unless it was modified externally during the session).
* **Default:** Enabled by default, using ProtonVPN's DNS servers provided during connection.
* **Configuration:**
    * `1) Enable DNS Leak Protection (recommended)`: Uses DNS servers pushed by the ProtonVPN server during connection.
    * `2) Configure Custom DNS Servers`: Uses specific DNS IP addresses you provide instead of ProtonVPN's.
    * `3) Disable DNS Management`: The CLI will not touch `/etc/resolv.conf` at all.

#### Custom DNS

Allows specifying up to 3 custom DNS server IP addresses to be used when connected, instead of the ProtonVPN DNS servers. Configure via Option `2` in the DNS Management menu.

#### Disabling DNS Management

If you prefer to manage `/etc/resolv.conf` yourself or use your system's default DNS settings even when connected, select Option `3` in the DNS Management menu.

### IPv6 Leak Protection

* **Purpose:** Prevents your real IPv6 address from being exposed while connected to the VPN (as ProtonVPN tunnels primarily use IPv4).
* **Mechanism:** Uses `ip6tables` to block IPv6 traffic on the primary network interface while the VPN is active. It backs up existing `ip6tables` rules before applying blocks and restores them upon disconnection. It automatically detects if system IPv6 is disabled and skips modification.
* **Status:** Enabled by default and cannot be disabled for security reasons.

### Kill Switch

Managed via `sudo protonvpn configure` -> Option 5.

* **Purpose:** Protects your real IP address if the VPN connection drops unexpectedly (e.g., OpenVPN process crashes). It blocks all internet traffic except that going through the VPN tunnel.
* **Mechanism:** When enabled and a connection starts, it backs up current `iptables` rules, then replaces them with strict rules allowing traffic only via the VPN interface (`proton0` or `tun0`), the loopback interface (`lo`), and the necessary VPN connection traffic (UDP/TCP to the server). When `protonvpn disconnect` is called, the original rules are restored.
* **Configuration:**
    * `1) Enable Kill Switch (Block access to/from LAN)`: Most restrictive. Blocks local network traffic too. Recommended for laptops on untrusted networks.
    * `2) Enable Kill Switch (Allow access to/from LAN)`: Allows traffic within your local network (e.g., accessing local printers, file shares). Suitable for desktops on trusted home networks.
    * `3) Disable Kill Switch`: Kill switch is not activated.
* **Important Notes:**
    * The Kill Switch *only* activates on unexpected connection drops (e.g., process killed). It does *not* activate when you manually run `protonvpn disconnect`.
    * It does *not* persist across system reboots.
    * Enabling the Kill Switch will automatically **disable** Split Tunneling (they are incompatible).

### Split Tunneling

Managed via `sudo protonvpn configure` -> Option 6. Also controllable per-connection via `--st` and `--stt` flags.

* **Purpose:** Allows specific IP addresses, IP ranges (CIDR notation), or domain names to either bypass the VPN tunnel (blacklist mode) or be the *only* traffic routed through the VPN (whitelist mode).
* **Mechanism:** Modifies the OpenVPN configuration (`connect.ovpn`) before connecting, adding specific `route` directives to control traffic flow based on the configured mode and target list. Domain names are resolved to IPs during configuration generation.
* **Configuration (`protonvpn configure` -> 6):**
    1.  Enable/Disable Split Tunneling.
    2.  Choose Mode:
        * `1) Blacklist`: Specified targets bypass the VPN and use the regular internet connection. All other traffic goes through the VPN.
        * `2) Whitelist`: *Only* traffic to specified targets goes through the VPN. All other traffic uses the regular internet connection.
    3.  Manage Targets: Add or remove IPs (e.g., `1.1.1.1`), CIDR ranges (e.g., `192.168.1.0/24`), or domain names (e.g., `example.com`). Targets are stored in `~/.pvpn-cli/split_tunnel.txt`, one per line. You can edit this file directly and run `sudo protonvpn refresh` to apply changes.
* **Per-Connection Usage:**
    * Use `sudo protonvpn connect ... --st <target1>,<target2>,...`
    * Optionally add `--stt <whitelist|blacklist>` to specify the mode for this connection.
* **Important Notes:**
    * Split Tunneling is **incompatible** with the Kill Switch. Enabling Split Tunneling will disable the Kill Switch, and vice versa.
    * Domain name resolution happens *before* connecting. If the IP for a domain changes while connected, the split tunneling rule might become ineffective until reconnection.

### Custom OpenVPN Down Script

* **Purpose:** Allows advanced users to execute custom commands automatically when the OpenVPN connection managed by this CLI is terminated (either through `protonvpn disconnect` or unexpectedly).
* **Mechanism:** Before initiating an OpenVPN connection, the CLI checks for the existence of the file `/usr/bin/protonvpn-down.sh`. If this specific file exists, the CLI automatically adds the `--script-security 2` and `--down /usr/bin/protonvpn-down.sh` arguments to the `openvpn` command. This tells OpenVPN to execute the script upon disconnection.
* **Usage:** Create an executable script at `/usr/bin/protonvpn-down.sh` containing any cleanup actions you need (e.g., restoring specific firewall rules, logging disconnection). Ensure the script has execute permissions (`sudo chmod +x /usr/bin/protonvpn-down.sh`).
* **Note:** This feature is implicit and not managed via the `protonvpn configure` menu. The CLI simply checks for the script's presence at the predefined path.

## HTTP API

The CLI includes a FastAPI-based HTTP API for programmatic control.

### Starting the API Server

* **Command Line:**
    ```bash
    protonvpn api [--host <ip>] [--port <port>]
    ```
    Defaults to `127.0.0.1:8000`. Use `0.0.0.0` to make it accessible from other machines (use with caution).
* **Docker:** The `docker-compose.yml` setup typically starts the API automatically inside the container, accessible as `http://localhost:8000` from other containers in the same Docker Compose setup.

### API Endpoints

| Endpoint      | Method | Description                     | Request Body (`application/json`)                                                                                                                                | Response (`application/json`)                                |
| :------------ | :----- | :------------------------------ | :--------------------------------------------------------------------------------------------------------------------------------------------------------------- | :----------------------------------------------------------- |
| `/init`       | POST   | Initialize profile             | `InitRequest` (username, password, tier, protocol, force)                                                                                                        | `{"success": true/false, "output": "..."}`                   |
| `/connect`    | POST   | Connect to VPN                  | `ConnectRequest` (server, protocol, fastest, random, country_code, secure_core, p2p, tor, split_tunnel\[list], split_tunnel_type)                                | `{"success": true/false, "output": "..."}`                   |
| `/disconnect` | POST   | Disconnect VPN                  | (No body)                                                                                                                                                        | `{"success": true/false, "output": "..."}`                   |
| `/status`     | GET    | Get current connection status | (No body)                                                                                                                                                        | `{"success": true/false, "output": "Current Status Output"}` |
| `/reconnect`  | POST   | Reconnect last session          | (No body)                                                                                                                                                        | `{"success": true/false, "output": "..."}`                   |

### Example Requests

(Replace `localhost:8000` if needed)

* **Initialize:**
    ```bash
    curl -X POST "http://localhost:8000/init" -H "Content-Type: application/json" \
    -d '{"username": "YOUR_OVPN_USER", "password": "YOUR_OVPN_PASS", "tier": 3, "protocol": "udp"}'
    ```
* **Connect Fastest:**
    ```bash
    curl -X POST "http://localhost:8000/connect" -H "Content-Type: application/json" \
    -d '{"fastest": true, "protocol": "udp"}'
    ```
* **Connect Specific Server:**
    ```bash
    curl -X POST "http://localhost:8000/connect" -H "Content-Type: application/json" \
    -d '{"server": "CH#5", "protocol": "tcp"}'
    ```
* **Get Status:**
    ```bash
    curl -X GET "http://localhost:8000/status"
    ```
* **Disconnect:**
    ```bash
    curl -X POST "http://localhost:8000/disconnect"
    ```

### API Documentation

When the API server is running, access interactive documentation in your browser:

* **Swagger UI:** `http://localhost:8000/docs`
* **ReDoc:** `http://localhost:8000/redoc`

## Enhancements

Optional configurations to improve usability.

### Disable sudo password query

Allow running `protonvpn` commands with `sudo` without entering your password every time.

1.  Find the executable path:
    ```sh
    which protonvpn
    # Example output: /usr/local/bin/protonvpn
    ```
2.  Edit the sudoers file using `sudo visudo`. **Be very careful when editing this file.**
3.  Add the following line at the end, replacing `your_username` with your actual Linux username and `/path/to/protonvpn` with the output from step 1:
    ```
    your_username ALL=(root) NOPASSWD: /path/to/protonvpn
    ```
4.  Save and exit the editor.

### Configure alias for quicker access

Create shell aliases for shorter commands. Open your shell's configuration file (e.g., `~/.bashrc` for bash, `~/.zshrc` for zsh) and add:

```sh
alias pvpn='sudo protonvpn'
alias protonvpn='sudo protonvpn' # Optional: allows typing protonvpn without sudo
```

Save the file and restart your shell or run `source ~/.bashrc` (or `~/.zshrc`). You can now use `pvpn c -f`, `pvpn status`, etc.

### Auto-connect on boot

#### via Systemd Service

Automatically connect to ProtonVPN when your system boots using systemd.

1.  Find the executable path:
    ```sh
    which protonvpn
    # Example output: /usr/local/bin/protonvpn
    ```
2.  Create a systemd unit file:
    ```sh
    sudo nano /etc/systemd/system/protonvpn-autoconnect.service
    ```
3.  Paste the following content, modifying paths and user as needed:

    ```ini
    [Unit]
    Description=ProtonVPN-CLI Auto-Connect Service
    # Start after the network is online
    After=network-online.target
    Wants=network-online.target

    [Service]
    Type=forking
    # Replace /usr/local/bin/protonvpn with your path from step 1
    # Replace 'connect -f' with your desired connect command (e.g., 'connect CH#5')
    ExecStart=/usr/local/bin/protonvpn connect -f
    # Set the user who initialized protonvpn-cli. Required for finding config.
    Environment=SUDO_USER=your_username
    # Wait up to 120 seconds for network before connecting
    Environment=PVPN_WAIT=120
    # Optional: Enable debug logging for the service
    # Environment=PVPN_DEBUG=1
    # Ensure the OpenVPN process is killed if the service stops
    KillMode=process
    Restart=on-failure
    RestartSec=5s

    [Install]
    WantedBy=multi-user.target
    ```
    * Replace `your_username` with the user who ran `sudo protonvpn init`.
    * Adjust `ExecStart` command and `PVPN_WAIT` value as desired.

4.  Reload systemd, enable, and start the service:
    ```sh
    sudo systemctl daemon-reload
    sudo systemctl enable protonvpn-autoconnect.service
    sudo systemctl start protonvpn-autoconnect.service
    ```
5.  Check the status:
    ```sh
    sudo systemctl status protonvpn-autoconnect.service
    # Check logs if needed:
    # sudo journalctl -u protonvpn-autoconnect.service
    ```

The VPN should now connect automatically on subsequent boots.