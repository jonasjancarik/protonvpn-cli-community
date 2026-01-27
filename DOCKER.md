# Docker Setup for ProtonVPN CLI

This document provides instructions on how to use the Docker setup for the ProtonVPN CLI application.

## Prerequisites

- Docker
- Docker Compose

## Production Setup

### Environment Configuration

Create a `.env` file in the project root with your ProtonVPN credentials:

```bash
PROTONVPN_USERNAME=your_username
PROTONVPN_PASSWORD=your_password
PROTONVPN_2FA=123456  # Optional: 2FA code if enabled on your Proton account. If not set, CLI will prompt.
OPENVPN_USERNAME=your_openvpn_username  # get it from https://account.protonvpn.com/account-password#openvpn
OPENVPN_PASSWORD=your_openvpn_password
PROTONVPN_TIER=1  # Optional: Your ProtonVPN tier (1=Free, 2=Basic, 3=Plus/Visionary (default: 1))
PROTONVPN_PROTOCOL=udp  # Optional: Connection protocol (UDP or TCP, defaults to UDP)
```

### Building and Starting the Container

```bash
docker compose up -d
```

This will build the Docker image and start a container in detached mode.

### Running ProtonVPN Commands

Since the ProtonVPN CLI requires root privileges, you'll need to execute commands inside the running container:

```bash
# Connect to the container
docker exec -it protonvpn-cli bash

# Inside the container, you can run ProtonVPN commands
protonvpn --help
protonvpn connect  # Connect to ProtonVPN
protonvpn status  # Check connection status
protonvpn disconnect  # Disconnect from ProtonVPN
protonvpn init  # Initialize ProtonVPN - this is done automatically on startup
```

### Using as a Service Provider

The Docker setup is designed to allow other containers to use the VPN connection. This is achieved through Docker's network mode feature. The example service in the docker-compose.yml demonstrates this:

```yaml
example-service:
  image: alpine:latest
  network_mode: "service:protonvpn-cli"
  # ... other configuration
```

Any container that needs to use the VPN connection should:
1. Set `network_mode: "service:protonvpn-cli"`
2. Depend on the protonvpn-cli service using `depends_on`

## Development Setup

This project includes a development container configuration for VS Code or other compatible editors.

### Using VS Code Dev Containers

1. Install the [Remote - Containers](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers) extension in VS Code.
2. Open the project folder in VS Code.
3. Click on the green icon in the bottom-left corner of VS Code and select "Reopen in Container".
4. VS Code will build and start the development container, and you'll be able to develop inside it.

### Development Container Features

- The development container mounts the project directory, allowing you to edit files directly from your host machine.
- It includes all necessary dependencies for development and debugging.
- The container runs with root privileges, which are required for the ProtonVPN CLI.
- Python packages are installed in development mode (`pip install -e .`).

### Running Commands in the Development Container

You can run commands directly in the VS Code terminal, which will be connected to the development container:

```bash
protonvpn --help
```

## Configuration Persistence

Both the production and development setups include a volume for persistent storage of ProtonVPN configuration:

```yaml
volumes:
  - protonvpn-config:/root/.pvpn-cli
```

This ensures that your ProtonVPN configuration is preserved even if the container is restarted or rebuilt.

## Security Considerations

The container runs with elevated privileges (`privileged: true`) and has additional capabilities (`NET_ADMIN`, `SYS_MODULE`) to allow VPN functionality. This is necessary for the VPN to work correctly, but it means the container has more access to the host system than a typical Docker container.

Additional security features:
- Kill switch can be enabled by setting `VPN_ENABLE_KILLSWITCH=true` in the environment
- The VPN connection is isolated in its own network
- Credentials are managed through environment variables

## Troubleshooting

If you encounter issues with the VPN connection, ensure that:

1. The container has access to the internet
2. The `/dev/net/tun` device is properly mounted
3. The container has the necessary privileges and capabilities
4. Your ProtonVPN credentials are correctly set in the `.env` file

You can check the logs with:

```bash
docker compose logs
```

## Stopping the Container

```bash
docker compose down
```

To remove the persistent volume as well:

```bash
docker compose down -v
``` 
