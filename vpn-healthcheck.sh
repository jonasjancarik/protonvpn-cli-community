#!/bin/bash
set -u

health_timeout="${PROTONVPN_HEALTH_TIMEOUT:-10}"
health_url="${PROTONVPN_HEALTHCHECK_URL:-https://api.ipify.org?format=json}"

fail() {
    echo "[healthcheck] $*" >&2
    exit 1
}

status_output="$(timeout "${health_timeout}" protonvpn status 2>&1)"
status_code=$?

if [ "$status_code" -eq 124 ]; then
    fail "protonvpn status timed out after ${health_timeout}s"
fi

if [ "$status_code" -ne 0 ]; then
    printf '%s\n' "$status_output" >&2
    fail "protonvpn status exited with ${status_code}"
fi

if ! printf '%s\n' "$status_output" | grep -Eq '^Status:[[:space:]]+Connected\b'; then
    printf '%s\n' "$status_output" >&2
    fail "protonvpn status did not report Connected"
fi

outbound_output="$(timeout "${health_timeout}" python3 - "$health_url" "$health_timeout" <<'PY' 2>&1
import sys

import requests

url = sys.argv[1]
timeout = float(sys.argv[2])

try:
    response = requests.get(
        url,
        headers={"User-Agent": "protonvpn-cli-healthcheck/1.0"},
        timeout=timeout,
    )
    response.raise_for_status()
except Exception as exc:
    print(f"Outbound connectivity probe failed: {exc}", file=sys.stderr)
    sys.exit(1)
PY
)"
outbound_code=$?

if [ "$outbound_code" -eq 124 ]; then
    fail "outbound connectivity probe timed out after ${health_timeout}s"
fi

if [ "$outbound_code" -ne 0 ]; then
    printf '%s\n' "$outbound_output" >&2
    fail "outbound connectivity probe failed"
fi

echo "VPN healthcheck passed"
