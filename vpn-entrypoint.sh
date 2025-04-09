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

# Function to attempt VPN connection with retries
connect_vpn_with_retry() {
    local max_attempts=5
    local attempt=1
    local delay=10  # seconds between attempts

    while [ $attempt -le $max_attempts ]; do
        echo "Attempting to connect to ProtonVPN (attempt $attempt/$max_attempts)..."
        if protonvpn connect --fastest; then
            echo "Successfully connected to ProtonVPN!"
            return 0
        fi
        
        if [ $attempt -lt $max_attempts ]; then
            echo "Connection failed. Waiting $delay seconds before next attempt..."
            sleep $delay
        fi
        attempt=$((attempt + 1))
    done
    
    echo "Failed to connect to ProtonVPN after $max_attempts attempts"
    return 1
}

# Connect to ProtonVPN (customize these parameters as needed)
echo "Connecting to ProtonVPN..."
protonvpn init --username $PROTONVPN_USERNAME --password $PROTONVPN_PASSWORD --tier $PROTONVPN_TIER --protocol $PROTONVPN_PROTOCOL --force

# Attempt to connect with retries
if ! connect_vpn_with_retry; then
    echo "Fatal: Could not establish VPN connection after multiple attempts"
    exit 1
fi

# Launch the API server in the background
echo "Starting ProtonVPN API server..."
protonvpn api --host 0.0.0.0 --port ${API_PORT:-8000} &

# Keep the container running and log the API output
echo "VPN connected and API server running..."
tail -f /dev/null 