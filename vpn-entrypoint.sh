#!/bin/bash
set -e

# Install the package in development mode
echo "Installing package in development mode..."
pip install -e .

# Enable IP forwarding
echo "Enabling IP forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward

# Set up iptables for NAT
echo "Setting up NAT..."
iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE
iptables -A FORWARD -i tun0 -o eth0 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i eth0 -o tun0 -j ACCEPT

# Connect to ProtonVPN (customize these parameters as needed)
echo "Connecting to ProtonVPN..."
protonvpn init --username $PROTONVPN_USERNAME --password $PROTONVPN_PASSWORD --tier $PROTONVPN_TIER --protocol $PROTONVPN_PROTOCOL --force
protonvpn connect --fastest # or specify country, server, etc.

# Launch the API server in the background
echo "Starting ProtonVPN API server..."
protonvpn api --host 0.0.0.0 --port ${API_PORT:-8000} &

# Keep the container running and log the API output
echo "VPN connected and API server running..."
tail -f /dev/null 