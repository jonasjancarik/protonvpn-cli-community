"""Run in a disposable child so DNS and HTTP have a total deadline."""
import sys

import requests


def main():
    try:
        response = requests.get(
            sys.argv[1],
            headers={"User-Agent": "protonvpn-cli-healthcheck/1.0"},
            timeout=float(sys.argv[2]),
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        print("outbound connectivity probe failed: {}".format(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
