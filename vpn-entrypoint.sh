#!/bin/bash
set -e

env_flag_enabled() {
    case "${1:-}" in
        1|true|TRUE|yes|YES|y|Y|on|ON)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

positive_integer_or_default() {
    local value="${1:-}"
    local default="$2"
    local name="$3"

    if [[ "$value" =~ ^[1-9][0-9]*$ ]]; then
        printf '%s' "$value"
        return
    fi

    if [ -n "$value" ]; then
        echo "Invalid ${name}=${value}; using ${default}" >&2
    fi
    printf '%s' "$default"
}

# # Install the package in development mode
# echo "Installing package in development mode..."
# pip install -e .

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

run_health_probe() {
    vpn-healthcheck >/dev/null
}

reconnect_vpn() {
    local reconnect_timeout
    reconnect_timeout="$(positive_integer_or_default "${PROTONVPN_RECONNECT_TIMEOUT:-}" 120 PROTONVPN_RECONNECT_TIMEOUT)"

    echo "Watchdog attempting protonvpn reconnect..."
    if timeout "$reconnect_timeout" protonvpn reconnect; then
        echo "Watchdog reconnect succeeded."
        return 0
    fi

    echo "Watchdog reconnect failed; falling back to disconnect + connect --fastest..."
    timeout "$reconnect_timeout" protonvpn disconnect || true

    if timeout "$reconnect_timeout" protonvpn connect --fastest; then
        echo "Watchdog fallback connect succeeded."
        return 0
    fi

    echo "Watchdog fallback connect failed."
    return 1
}

watchdog_loop() {
    local interval
    local failure_threshold
    local failures=0

    interval="$(positive_integer_or_default "${PROTONVPN_WATCHDOG_INTERVAL:-}" 30 PROTONVPN_WATCHDOG_INTERVAL)"
    failure_threshold="$(positive_integer_or_default "${PROTONVPN_RECONNECT_AFTER_FAILURES:-}" 3 PROTONVPN_RECONNECT_AFTER_FAILURES)"

    echo "Auto-reconnect watchdog enabled: interval=${interval}s failures=${failure_threshold} health_timeout=${PROTONVPN_HEALTH_TIMEOUT:-10}s"

    while true; do
        sleep "$interval"

        if run_health_probe; then
            if [ "$failures" -gt 0 ]; then
                echo "VPN health recovered after ${failures} failed probe(s)."
            fi
            failures=0
            continue
        fi

        failures=$((failures + 1))
        echo "VPN health probe failed (${failures}/${failure_threshold})."

        if [ "$failures" -lt "$failure_threshold" ]; then
            continue
        fi

        if reconnect_vpn && run_health_probe; then
            failures=0
            echo "VPN health restored by watchdog."
        else
            failures="$failure_threshold"
            echo "VPN health still failing after watchdog reconnect attempt."
        fi
    done
}

# Initialize ProtonVPN
echo "Initializing ProtonVPN..."
protonvpn init --username $PROTONVPN_USERNAME --password $PROTONVPN_PASSWORD --tier $PROTONVPN_TIER --protocol $PROTONVPN_PROTOCOL --openvpn-username "$OPENVPN_USERNAME" --openvpn-password "$OPENVPN_PASSWORD" --force

# Check if serverinfo.json was created
if [ ! -f ~/.pvpn-cli/serverinfo.json ]; then
    echo "Error: serverinfo.json not found after initialization. Server data pull likely failed."
    # Optional: Print logs if available
    if [ -f ~/.pvpn-cli/protonvpn-cli.log ]; then
        echo "---- protonvpn-cli.log ----"
        cat ~/.pvpn-cli/protonvpn-cli.log
        echo "--------------------------"
    fi
    exit 1
fi

# # Verify that the passfile was created with the OpenVPN credentials
# echo "Verifying passfile..."
# if [ -f ~/.pvpn-cli/pvpnpass ]; then
#     echo "Passfile created successfully."
#     # Display the first line of the passfile (username) to verify it's using the OpenVPN credentials
#     head -n 1 ~/.pvpn-cli/pvpnpass
# else
#     echo "Error: Passfile not created."
# fi

# Attempt to connect with retries
if ! connect_vpn_with_retry; then
    echo "Fatal: Could not establish VPN connection after multiple attempts"
    exit 1
fi

# Launch the API server in the background
echo "Starting ProtonVPN API server..."
protonvpn api --host 0.0.0.0 --port ${API_PORT:-8000} &
api_pid=$!

watchdog_pid=""
if env_flag_enabled "${PROTONVPN_AUTO_RECONNECT:-false}"; then
    watchdog_loop &
    watchdog_pid=$!
else
    echo "Auto-reconnect watchdog disabled. Set PROTONVPN_AUTO_RECONNECT=true to enable it."
fi

shutdown() {
    echo "Stopping ProtonVPN container processes..."
    if [ -n "$watchdog_pid" ]; then
        kill "$watchdog_pid" 2>/dev/null || true
    fi
    kill "$api_pid" 2>/dev/null || true
    if [ -n "${tail_pid:-}" ]; then
        kill "$tail_pid" 2>/dev/null || true
    fi
}

trap shutdown INT TERM

# Keep the container running and log the API output
echo "VPN connected and API server running..."
tail -f /dev/null &
tail_pid=$!
wait "$tail_pid"
