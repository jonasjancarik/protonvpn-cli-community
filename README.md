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

TBA