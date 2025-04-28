"""
A CLI for ProtonVPN.

Usage:
    protonvpn init [--username <username>] [--password <password>] [--tier <tier>] [-p | --protocol <protocol>] [--force] [--openvpn-username <ovpn_user>] [--openvpn-password <ovpn_pass>]
    protonvpn (c | connect) [<servername>] [-p | --protocol <protocol>] [--st | --split-tunnel <IP>]
    protonvpn (c | connect) [-f | --fastest] [-p | --protocol <protocol>] [--st | --split-tunnel <IP>]
    protonvpn (c | connect) [--cc <code>] [-p | --protocol <protocol>] [--st | --split-tunnel <IP>] [--stt | --split-tunnel-type <split_type>]
    protonvpn (c | connect) [--sc] [-p | --protocol <protocol>] [--st | --split-tunnel <IP>]
    protonvpn (c | connect) [--p2p] [-p | --protocol <protocol>] [--st | --split-tunnel <IP>]
    protonvpn (c | connect) [--tor] [-p | --protocol <protocol>] [--st | --split-tunnel <IP>]
    protonvpn (c | connect) [-r | --random] [-p | --protocol <protocol>] [--st | --split-tunnel <IP>]
    protonvpn (r | reconnect)
    protonvpn (d | disconnect)
    protonvpn (s | status)
    protonvpn configure
    protonvpn refresh
    protonvpn examples
    protonvpn (-h | --help)
    protonvpn (-v | --version)
    protonvpn api [--host <host>] [--port <port>]

Options:
    --username <username>                OpenVPN username for initialization
    --password <password>                OpenVPN password for initialization
    --tier <tier>                        Plan tier for initialization (1=Free, 2=Basic, 3=Plus, 4=Visionary)
    --force                              Skip confirmation when reinitializing existing profile
    -f, --fastest                        Select the fastest ProtonVPN server.
    -r, --random                         Select a random ProtonVPN server.
    --cc CODE                            Determine the country for fastest connect.
    --sc                                 Connect to the fastest Secure-Core server.
    --p2p                                Connect to the fastest torrent server.
    --tor                                Connect to the fastest Tor server.
    -p, --protocol PROTOCOL              Determine the protocol (UDP or TCP).
    -h, --help                           Show this help message.
    -v, --version                        Display version.
    --st, --split-tunnel IP              Split tunnel IP address, CIDR or domain. Comma-separated.
    --stt, --split-tunnel-type type      Split tunnel type (whitelist or blacklist).
    --host <host>                        Host to bind API server (default: 127.0.0.1)
    --port <port>                        Port for API server (default: 8000)
    --openvpn-username <ovpn_user>       OpenVPN username for initialization
    --openvpn-password <ovpn_pass>       OpenVPN password for initialization
    --no-upgrade-notice                  Do not show the upgrade notice on startup

Commands:
    init                Initialize a ProtonVPN profile.
    c, connect          Connect to a ProtonVPN server.
    r, reconnect        Reconnect to the last server.
    d, disconnect       Disconnect the current session.
    s, status          Show connection status.
    configure          Change ProtonVPN-CLI configuration.
    refresh            Refresh OpenVPN configuration and server data.
    examples           Print some example commands.
    api                Start the API server (for controlling the VPN connection).

Arguments:
    <servername>        Servername (CH#4, CH-US-1, HK5-Tor).
"""

import configparser
import getpass
import os
import shutil

# Standard Libraries
import sys
import textwrap
import time

# External Libraries
from docopt import docopt

# protonvpn-cli Functions
from . import connection
from . import api

# Constants
from .constants import (
    CLIENT_SUFFIX,
    CONFIG_DIR,
    CONFIG_FILE,
    PASSFILE,
    SPLIT_TUNNEL_FILE,
    USER,
    VERSION,
)
from .logger import logger
from .utils import (
    change_file_owner,
    check_init,
    check_root,
    get_config_value,
    is_valid_ip,
    is_valid_domain,
    pull_server_data,
    set_config_value,
    wait_for_network,
)


# Try to load environment variables from .env file if python-dotenv is available
try:
    from dotenv import load_dotenv

    load_dotenv()

    logger.debug("Environment variables loaded from .env file")
except ImportError:
    pass


def main():
    """Main function"""
    try:
        cli()
    except KeyboardInterrupt:
        print("\nQuitting...")
        sys.exit(1)


def cli():
    """Run user's input command."""

    if shutil.which("NetworkManager") or shutil.which("nmcli"):
        try:
            show_notice = int(get_config_value("USER", "show_upgrade_notice"))
        except (KeyError, ValueError):
            # Default to showing the notice if the config value is missing or invalid
            show_notice = 1

        # Only show notice if the flag is NOT set AND the config allows it
        if (
            not docopt(__doc__, version="ProtonVPN-CLI v{0}".format(VERSION)).get(
                "--no-upgrade-notice"
            )
            and show_notice
        ):
            print(
                "\nProtonVPN now offers an official, user-friendly Linux app, recommended for most desktop users. If you prefer or require a command-line tool, you can continue using this CLI.\n\n"
                "Visit https://protonvpn.com/support/official-linux-client to learn more and upgrade.\n\n"
            )
            # Set the config value to 0 so it doesn't show again
            try:
                set_config_value("USER", "show_upgrade_notice", 0)
            except KeyError:
                # Handle cases where the config file might not be fully initialized yet
                pass

    # Initial log values
    change_file_owner(os.path.join(CONFIG_DIR, "pvpn-cli.log"))
    logger.debug("###########################")
    logger.debug("### NEW PROCESS STARTED ###")
    logger.debug("###########################")
    logger.debug(sys.argv)
    logger.debug("USER: {0}".format(USER))
    logger.debug("CONFIG_DIR: {0}".format(CONFIG_DIR))

    args = docopt(__doc__, version="ProtonVPN-CLI v{0}".format(VERSION))
    logger.debug("Arguments\n{0}".format(str(args).replace("\n", "")))

    if shutil.which("NetworkManager") or shutil.which("nmcli"):
        # Check the flag first. If set, skip the notice entirely.
        if not args.get("--no-upgrade-notice"):
            try:
                show_notice = int(get_config_value("USER", "show_upgrade_notice"))
            except (KeyError, ValueError):
                # Default to showing the notice if the config value is missing or invalid
                show_notice = 1

            # Only show notice if the config allows it (flag already checked)
            if show_notice:
                print(
                    "\nProtonVPN now offers an official, user-friendly Linux app, recommended for most desktop users. If you prefer or require a command-line tool, you can continue using this CLI.\n\n"
                    "Visit https://protonvpn.com/support/official-linux-client to learn more and upgrade.\n\n"
                )
                # Set the config value to 0 so it doesn't show again
                try:
                    set_config_value("USER", "show_upgrade_notice", 0)
                except KeyError:
                    # Handle cases where the config file might not be fully initialized yet
                    pass

    # Parse arguments
    if args.get("init"):
        init_cli()
    elif args.get("c") or args.get("connect"):
        check_root()
        check_init()

        # Wait until a connection to the ProtonVPN API can be made
        # As this is mainly for automatically connecting on boot, it only
        # activates when the environment variable PVPN_WAIT is 1
        # Otherwise it wouldn't connect when a VPN process without
        # internet access exists or the Kill Switch is active
        if int(os.environ.get("PVPN_WAIT", 0)) > 0:
            wait_for_network(int(os.environ["PVPN_WAIT"]))

        # Handle protocol argument which can come from either -p or --protocol
        protocol = None
        if args.get("-p"):
            protocol = (
                args.get("-p")[0]
                if isinstance(args.get("-p"), list)
                else args.get("-p")
            )
        elif args.get("--protocol"):
            protocol = (
                args.get("--protocol")[0]
                if isinstance(args.get("--protocol"), list)
                else args.get("--protocol")
            )

        if protocol is not None and protocol.lower().strip() in ["tcp", "udp"]:
            protocol = protocol.lower().strip()

        # Split tunneling
        if args.get("--split-tunnel"):
            split_tunnel = args.get("--split-tunnel")
            # on-the-fly split tunneling
            for i in split_tunnel.split(","):
                if not (is_valid_ip(i) or is_valid_domain(i)):
                    print(
                        "[!] Invalid split tunnel option. You must supply a valid IP address, CIDR or domain."
                    )
                    logger.debug("Invalid split tunnel option.")
                    sys.exit(1)
            os.environ["PVPN_SPLIT_TUNNEL"] = split_tunnel

        if args.get("--split-tunnel-type"):
            split_tunnel_type = args.get("--split-tunnel-type")
            if split_tunnel_type.lower().strip() in ["whitelist", "blacklist"]:
                os.environ["PVPN_SPLIT_TUNNEL_TYPE"] = split_tunnel_type.lower().strip()
            else:
                print(
                    "[!] Invalid split tunnel type. You must supply either 'whitelist' or 'blacklist'."
                )
                logger.debug("Invalid split tunnel type.")
                sys.exit(1)

        if args.get("--random"):
            connection.random_c(protocol)
        elif args.get("--fastest"):
            connection.fastest(protocol)
        elif args.get("<servername>"):
            connection.direct(args.get("<servername>"), protocol)
        elif args.get("--cc") is not None:
            connection.country_f(args.get("--cc"), protocol)
        # Features: 1: Secure-Core, 2: Tor, 4: P2P
        elif args.get("--p2p"):
            connection.feature_f(4, protocol)
        elif args.get("--sc"):
            connection.feature_f(1, protocol)
        elif args.get("--tor"):
            connection.feature_f(2, protocol)
        else:
            connection.dialog()
    elif args.get("r") or args.get("reconnect"):
        check_root()
        check_init()
        connection.reconnect()
    elif args.get("d") or args.get("disconnect"):
        check_root()
        check_init()
        connection.disconnect()
    elif args.get("s") or args.get("status"):
        connection.status()
    elif args.get("configure"):
        check_root()
        check_init()
        configure_cli()
    elif args.get("refresh"):
        check_init()
        pull_server_data(force=True)
    elif args.get("examples"):
        print_examples()
    elif args.get("api"):
        host = args.get("--host") or "127.0.0.1"
        port_arg = args.get("--port")
        try:
            port = int(port_arg) if port_arg is not None else 8000
        except ValueError:
            print("[!] Port must be a number")
            sys.exit(1)
        api.start_api(host=host, port=port)


def init_config_file():
    """Initialize configuration file."""
    config = configparser.ConfigParser()
    config["USER"] = {
        "username": "None",
        "tier": "None",
        "default_protocol": "None",
        "initialized": "0",
        "dns_leak_protection": "1",
        "custom_dns": "None",
        "check_update_interval": "3",
        "api_domain": "https://api.protonvpn.ch",
        "show_upgrade_notice": "1",
    }
    config["metadata"] = {
        "last_api_pull": "0",
        "last_update_check": str(int(time.time())),
        "resolvconf_hash": "0",  # Initialize with default hash
        "connected_server": "None",
        "connected_proto": "None",
        "dns_server": "None",
    }

    with open(CONFIG_FILE, "w") as f:
        config.write(f)
    change_file_owner(CONFIG_FILE)
    logger.debug("pvpn-cli.cfg initialized")


def _configure_profile(
    username, password, tier, ovpn_username, ovpn_password, protocol="udp"
):
    """Helper function to configure ProtonVPN profile with given credentials"""
    init_config_file()

    # Store the password in the config for API authentication
    set_config_value("USER", "password", password)

    # Pull server data using the new API library
    print("Pulling server configuration...")
    if not pull_server_data(force=True, username=username, password=password):
        print("Error: Failed to pull server configuration.")
        print("Please check your credentials and network connection.")
        # Optional: Check and print logs if available
        log_path = os.path.join(CONFIG_DIR, "protonvpn-cli.log")
        if os.path.exists(log_path):
            print(f"---- {log_path} ----")
            with open(log_path, "r") as log_file:
                print(log_file.read())
            print("--------------------------")
        sys.exit(1)  # Exit if pull failed
    print("Server configuration pulled successfully.")

    # Adjust tier value to match API requirements
    if tier == 4:
        tier = 3
    tier -= 1

    # Set configuration values
    set_config_value("USER", "username", username)
    set_config_value("USER", "tier", tier)
    set_config_value("USER", "default_protocol", protocol)
    set_config_value("USER", "dns_leak_protection", 1)
    set_config_value("USER", "custom_dns", None)
    set_config_value("USER", "killswitch", 0)
    set_config_value("USER", "ignore_ping_restart", 0)
    set_config_value("USER", "ping", 0)
    set_config_value("USER", "ping_exit", 0)

    # Create password file with OpenVPN credentials
    with open(PASSFILE, "w") as f:
        f.write("{0}+{1}\n{2}".format(ovpn_username, CLIENT_SUFFIX, ovpn_password))
        logger.debug("{0}+{1}\n{2}".format(ovpn_username, CLIENT_SUFFIX, ovpn_password))
        logger.debug("Passfile created")
        os.chmod(PASSFILE, 0o600)

    set_config_value("USER", "initialized", 1)


def init_cli():
    """Initialize the CLI."""
    check_root()

    if not os.path.isdir(CONFIG_DIR):
        os.mkdir(CONFIG_DIR)
        logger.debug("Config Directory created")
    change_file_owner(CONFIG_DIR)

    args = docopt(__doc__, version="ProtonVPN-CLI v{0}".format(VERSION))

    # Check for command line arguments for non-interactive setup
    cli_username = args.get("--username")
    cli_password = args.get("--password")
    cli_tier = args.get("--tier")
    cli_ovpn_username = args.get("--openvpn-username")
    cli_ovpn_password = args.get("--openvpn-password")

    # Handle protocol argument which can come from either -p or --protocol
    cli_protocol = None
    if args.get("-p"):
        cli_protocol = (
            args.get("-p")[0] if isinstance(args.get("-p"), list) else args.get("-p")
        )
    elif args.get("--protocol"):
        cli_protocol = (
            args.get("--protocol")[0]
            if isinstance(args.get("--protocol"), list)
            else args.get("--protocol")
        )
    else:
        cli_protocol = "udp"

    force_reinit = args.get("--force", False)

    # Warn user about reinitialization unless --force is used
    try:
        if int(get_config_value("USER", "initialized")) and not force_reinit:
            print("An initialized profile has been found.")
            overwrite = input(
                "Are you sure you want to overwrite that profile? [y/N]: "
            )
            if overwrite.strip().lower() != "y":
                print("Quitting...")
                sys.exit(1)
            # Disconnect, so every setting (Kill Switch, IPv6, ...)
            # will be reverted (See #62)
            connection.disconnect(passed=True)
    except KeyError:
        pass

    # If all required args are present, use them for non-interactive setup
    if all(
        [cli_username, cli_password, cli_tier, cli_ovpn_username, cli_ovpn_password]
    ):
        logger.debug("Using command line arguments for initialization")

        # Validate inputs
        try:
            user_tier = int(cli_tier)
            if user_tier not in [1, 2, 3, 4]:
                raise ValueError("tier")

            cli_protocol = cli_protocol.lower()
            if cli_protocol not in ["udp", "tcp"]:
                raise ValueError("protocol")

            # Configure the profile with the provided credentials
            _configure_profile(
                cli_username,
                cli_password,
                user_tier,
                cli_ovpn_username,
                cli_ovpn_password,
                cli_protocol,
            )
            print("ProtonVPN-CLI has been initialized with your credentials.")
            sys.exit(0)
        except ValueError as e:
            if str(e) == "tier":
                print("Error: Tier must be 1, 2, 3, or 4.")
            elif str(e) == "protocol":
                print("Error: Protocol must be 'udp' or 'tcp'.")
            else:
                print(f"Error: {str(e)}")
            sys.exit(1)
    else:
        # Interactive setup
        print("ProtonVPN-CLI initialization")
        print("==========================")
        print("")

        # Get ProtonVPN username and password
        username, password = set_protonvpn_credentials_config()
        if not username or not password:
            print("Error: ProtonVPN username and password are required.")
            sys.exit(1)

        # Get OpenVPN username and password
        ovpn_username, ovpn_password = set_openvpn_credentials_config(write=False)
        if not ovpn_username or not ovpn_password:
            print("Error: OpenVPN username and password are required.")
            sys.exit(1)

        # Get tier
        tier = set_protonvpn_tier(write=False)
        if not tier:
            print("Error: Tier is required.")
            sys.exit(1)

        # Get protocol
        protocol = set_default_protocol(write=False)
        if not protocol:
            protocol = "udp"  # Default to UDP if not specified

        # Configure the profile with the provided credentials
        _configure_profile(
            username, password, tier, ovpn_username, ovpn_password, protocol
        )
        print("ProtonVPN-CLI has been initialized with your credentials.")
        sys.exit(0)


def print_examples():
    """Print some examples on how to use this program"""

    examples = (
        "protonvpn connect\n"
        "               Display a menu and select server interactively.\n\n"
        "protonvpn c BE-5\n"
        "               Connect to BE#5 with the default protocol.\n\n"
        "protonvpn connect NO#3 -p tcp\n"
        "               Connect to NO#3 with TCP.\n\n"
        "protonvpn connect NO#3 --protocol tcp\n"
        "               Connect to NO#3 with TCP (alternative syntax).\n\n"
        "protonvpn c --fastest\n"
        "               Connect to the fastest VPN Server.\n\n"
        "protonvpn connect --cc AU\n"
        "               Connect to the fastest Australian server\n"
        "               with the default protocol.\n\n"
        "protonvpn c --p2p -p tcp\n"
        "               Connect to the fastest torrent server with TCP.\n\n"
        "protonvpn c --sc\n"
        "               Connect to the fastest Secure-Core server with\n"
        "               the default protocol.\n\n"
        "protonvpn reconnect\n"
        "               Reconnect the currently active session or connect\n"
        "               to the last connected server.\n\n"
        "protonvpn disconnect\n"
        "               Disconnect the current session.\n\n"
        "protonvpn s\n"
        "               Print information about the current session."
    )

    print(examples)


def configure_cli():
    """Change single configuration values"""

    while True:
        print(
            "What do you want to change?\n"
            "\n"
            "1) ProtonVPN Credentials (for API)\n"
            "2) OpenVPN Credentials (for connection)\n"
            "3) ProtonVPN Plan\n"
            "4) Default Protocol\n"
            "5) DNS Management\n"
            "6) Kill Switch\n"
            "7) Split Tunneling\n"
            "8) Lost Connection Options\n"
            "9) Purge Configuration\n"
            "10) Toggle Upgrade Notice\n"
        )

        user_choice = input("Please enter your choice or leave empty to quit: ")

        user_choice = user_choice.lower().strip()
        if user_choice == "1":
            set_protonvpn_credentials_config()
            break
        elif user_choice == "2":
            set_openvpn_credentials_config(write=True)
            break
        elif user_choice == "3":
            set_protonvpn_tier(write=True)
            break
        elif user_choice == "4":
            set_default_protocol(write=True)
            break
        elif user_choice == "5":
            set_dns_protection()
            break
        elif user_choice == "6":
            set_killswitch()
            break
        elif user_choice == "7":
            set_split_tunnel()
            break
        elif user_choice == "8":
            set_lost_connection_options()
            break
        elif user_choice == "9":
            purge_configuration()
            break
        elif user_choice == "10":
            set_upgrade_notice()
            break
        elif user_choice == "":
            print("Quitting configuration.")
            sys.exit(0)
        else:
            print("[!] Invalid choice. Please enter the number of your choice.\n")
            time.sleep(0.5)


def purge_configuration():
    """Purges CLI configuration"""

    user_choice = (
        input("Are you sure you want to purge the configuration? [y/N]: ")
        .lower()
        .strip()
    )

    if not user_choice == "y":
        return

    print("Okay :(")
    time.sleep(0.5)

    connection.disconnect(passed=True)
    if os.path.isdir(CONFIG_DIR):
        shutil.rmtree(CONFIG_DIR)
    print("Configuration purged.")


def set_openvpn_credentials_config(write=True):
    """Set the OpenVPN Username and Password in the PASSFILE."""

    print()
    ovpn_username = input("Enter your OpenVPN username: ")

    # Ask for the password and confirmation until both are the same
    while True:
        ovpn_password1 = getpass.getpass("Enter your OpenVPN password: ")
        ovpn_password2 = getpass.getpass("Confirm your OpenVPN password: ")

        if not ovpn_password1 == ovpn_password2:
            print()
            print("[!] The OpenVPN passwords do not match. Please try again.")
        else:
            break

    if write:
        # Create password file with OpenVPN credentials
        with open(PASSFILE, "w") as f:
            f.write("{0}+{1}\n{2}".format(ovpn_username, CLIENT_SUFFIX, ovpn_password1))
            logger.debug(
                "{0}+{1}\n{2}".format(ovpn_username, CLIENT_SUFFIX, ovpn_password1)
            )
            logger.debug("Passfile updated")
            os.chmod(PASSFILE, 0o600)

        print("OpenVPN credentials have been updated!")

    return ovpn_username, ovpn_password1


def set_protonvpn_credentials_config():
    """Set the ProtonVPN Username and Password in the config."""

    print()
    username = input("Enter your ProtonVPN username: ")

    # Ask for the password and confirmation until both are the same
    while True:
        password_1 = getpass.getpass("Enter your ProtonVPN password: ")
        password_2 = getpass.getpass("Confirm your ProtonVPN password: ")

        if not password_1 == password_2:
            print()
            print("[!] The passwords do not match. Please try again.")
        else:
            break

    set_config_value("USER", "username", username)
    set_config_value(
        "USER", "password", password_1
    )  # Store password in config for API auth

    print("ProtonVPN credentials have been updated!")

    return username, password_1


def set_protonvpn_tier(write=False):
    """Set the users ProtonVPN Plan."""

    protonvpn_plans = {1: "Free", 2: "Basic", 3: "Plus", 4: "Visionary"}

    print()
    print("Please choose your ProtonVPN Plan")

    for plan in protonvpn_plans:
        print("{0}) {1}".format(plan, protonvpn_plans[plan]))

    while True:
        print()
        user_tier = input("Your plan: ")

        try:
            user_tier = int(user_tier)
            # Check if the choice exists in the dictionary
            protonvpn_plans[user_tier]
            break
        except (KeyError, ValueError):
            print()
            print("[!] Invalid choice. Please enter the number of your plan.")

    if write:
        # Set Visionary to plus as it has the same access
        if user_tier == 4:
            user_tier = 3

        # Lower tier by one to match API allocation
        user_tier -= 1

        set_config_value("USER", "tier", str(user_tier))

        print("ProtonVPN Plan has been updated!")

    return user_tier


def set_default_protocol(write=False):
    """Set the users default protocol"""

    print()
    print(
        "Choose the default OpenVPN protocol.\n"
        "OpenVPN can act on two different protocols: UDP and TCP.\n"
        "UDP is preferred for speed but might be blocked in some networks.\n"
        "TCP is not as fast but a lot harder to block.\n"
        "Input your preferred protocol. (Default: UDP)\n"
    )

    protonvpn_protocols = {1: "UDP", 2: "TCP"}

    for protocol in protonvpn_protocols:
        print("{0}) {1}".format(protocol, protonvpn_protocols[protocol]))

    while True:
        print()
        user_protocol_choice = input("Your choice: ")

        try:
            if user_protocol_choice == "":
                user_protocol_choice = 1
            user_protocol_choice = int(user_protocol_choice)
            # Check if the choice exists in the dictionary
            user_protocol = protonvpn_protocols[user_protocol_choice].lower()
            break
        except (KeyError, ValueError):
            print()
            print(
                "[!] Invalid choice. "
                "Please enter the number of your preferred protocol."
            )

    if write:
        set_config_value("USER", "default_protocol", user_protocol)
        print("Default protocol has been updated.")

    return user_protocol


def set_dns_protection():
    """Enable or disable DNS Leak Protection and custom DNS"""

    while True:
        print()
        print(
            "DNS Leak Protection makes sure that you always use "
            "ProtonVPN's DNS servers.\n"
            "For security reasons this option is recommended.\n"
            "\n"
            "1) Enable DNS Leak Protection (recommended)\n"
            "2) Configure Custom DNS Servers\n"
            "3) Disable DNS Management"
        )
        print()
        user_choice = input("Please enter your choice or leave empty to quit: ")
        user_choice = user_choice.lower().strip()
        if user_choice == "1":
            dns_leak_protection = 1
            custom_dns = None
            break
        elif user_choice == "2":
            dns_leak_protection = 0
            custom_dns = input(
                "Please enter your custom DNS servers (space separated): "
            )
            custom_dns = custom_dns.strip().split()

            # Check DNS Servers for validity
            if len(custom_dns) > 3:
                print("[!] Don't enter more than 3 DNS Servers")
                return

            for dns in custom_dns:
                if not is_valid_ip(dns):
                    print("[!] {0} is invalid. Please try again.".format(dns))
                    return
            custom_dns = " ".join(dns for dns in custom_dns)
            break
        elif user_choice == "3":
            dns_leak_protection = 0
            custom_dns = None
            break
        elif user_choice == "":
            print("Quitting configuration.")
            sys.exit(0)
        else:
            print("[!] Invalid choice. Please enter the number of your choice.\n")
            time.sleep(0.5)

    set_config_value("USER", "dns_leak_protection", dns_leak_protection)
    set_config_value("USER", "custom_dns", custom_dns)
    print("DNS Management updated.")


def set_killswitch():
    """Enable or disable the Kill Switch."""

    while True:
        print()
        print(
            "The Kill Switch will block all network traffic\n"
            "if the VPN connection drops unexpectedly.\n"
            "\n"
            "Please note that the Kill Switch assumes only one network interface being active.\n"  # noqa
            "\n"
            "1) Enable Kill Switch (Block access to/from LAN)\n"
            "2) Enable Kill Switch (Allow access to/from LAN)\n"
            "3) Disable Kill Switch"
        )
        print()
        user_choice = input("Please enter your choice or leave empty to quit: ")
        user_choice = user_choice.lower().strip()
        if user_choice == "1":
            killswitch = 1
            break
        elif user_choice == "2":
            killswitch = 2
            break
        elif user_choice == "3":
            killswitch = 0
            break
        elif user_choice == "":
            print("Quitting configuration.")
            sys.exit(0)
        else:
            print("[!] Invalid choice. Please enter the number of your choice.\n")
            time.sleep(0.5)

    if killswitch and int(get_config_value("USER", "split_tunnel")):
        set_config_value("USER", "split_tunnel", 0)
        print()
        print(
            "[!] Kill Switch can't be used with Split Tunneling.\n"
            + "[!] Split Tunneling has been disabled."
        )
        time.sleep(1)

    set_config_value("USER", "killswitch", killswitch)
    print()
    print("Kill Switch configuration updated.")


def set_split_tunnel():
    """Enable or disable split tunneling"""

    print()
    user_choice = input("Enable split tunneling? [y/N]: ")

    if user_choice.strip().lower() == "y":
        if int(get_config_value("USER", "killswitch")):
            set_config_value("USER", "killswitch", 0)
            print()
            print(
                "[!] Split Tunneling can't be used with Kill Switch.\n"
                + "[!] Kill Switch has been disabled.\n"
            )
            time.sleep(1)

        set_config_value("USER", "split_tunnel", 1)

        # ask user whether they want the split tunnel to be a blakclist or whitelist
        while True:
            print(
                "\nDo you want to use a blacklist or a whitelist?\n\n"
                "Blacklist means the VPN will not be used for the specified endpoints,\n"
                "while in the whitelist mode, the VPN will only be used for those endpoints.\n"
                "\n"
                "1) Blacklist\n"
                "2) Whitelist"
            )

            print()
            user_choice = input("Please enter your choice or leave empty to quit: ")
            user_choice = user_choice.lower().strip()
            if user_choice == "1":
                split_type = "blacklist"
                break
            elif user_choice == "2":
                split_type = "whitelist"
                break
            elif user_choice == "":
                print("Quitting configuration.")
                sys.exit(0)
            else:
                print("[!] Invalid choice. Please enter the number of your choice.\n")
                time.sleep(0.5)

        set_config_value("USER", "split_type", split_type)

        # check if the split tunnel file exists and if it's not empty
        if os.path.isfile(SPLIT_TUNNEL_FILE):
            with open(SPLIT_TUNNEL_FILE, "r") as f:
                if f.read().strip() != "":
                    print(
                        f"\n[!] Split tunnel file ({SPLIT_TUNNEL_FILE}) already exists and is not empty.\n"
                        + "[!] Do you want to overwrite it?\n"
                    )
                    user_choice = input("Overwrite? [y/N]: ")
                    if user_choice.strip().lower() != "y":
                        print("Quitting configuration.")
                        sys.exit(0)

        split_tunnel_file_wiped = False

        while True:
            user_input = input(
                f"\nPlease enter an IP, CIDR or domain to {'exclude from VPN' if split_type == 'blacklist' else 'use VPN for'}.\n"
                "Or leave empty to stop: "
            ).strip()

            if user_input == "":
                break

            i = user_input.strip()
            if not (is_valid_domain(i) or is_valid_ip(i)):
                print(f"[!] Invalid input: ({i}).")
                print()
                continue
            else:
                if not split_tunnel_file_wiped:
                    with open(SPLIT_TUNNEL_FILE, "w") as f:
                        f.write("")
                    split_tunnel_file_wiped = True
                with open(SPLIT_TUNNEL_FILE, "a") as f:
                    f.write(f"\n{i.strip()}")

        if os.path.isfile(SPLIT_TUNNEL_FILE):
            change_file_owner(SPLIT_TUNNEL_FILE)
        else:
            # If no no config file exists,
            # split tunneling should be disabled again
            logger.debug("No split tunneling file existing.")
            set_config_value("USER", "split_tunnel", 0)

    else:
        set_config_value("USER", "split_tunnel", 0)

        if os.path.isfile(SPLIT_TUNNEL_FILE):
            clear_config = input("Remove split tunnel configuration? [y/N]: ")

            if clear_config.strip().lower() == "y":
                os.remove(SPLIT_TUNNEL_FILE)

    print()
    print("Split tunneling configuration updated.")


def set_lost_connection_options():
    """Configure options for lost connection."""
    print()
    print(
        'ProtonVPN by default pushes the "ping-restart" option to the client with the value of 60,\n'
        "which means that if the client does not receive a ping from the server for 60 seconds,\n"
        "the client will restart. If the server does not work anymore, the client will be stuck in a loop,\n"
        "but won't terminate. This can lead to the machine being cut off from the internet."
    )
    print()
    user_choice = input("Ignore ping-restart option pushed by the server? [y/N]: ")

    if user_choice.strip().lower() == "y":
        ignore_ping_restart = True
    else:
        ignore_ping_restart = False

    set_config_value("USER", "ignore_ping_restart", int(ignore_ping_restart))

    if ignore_ping_restart:
        apply_ping_exit = input("Apply ping-exit option? [y/N]: ")
        if apply_ping_exit.strip().lower() == "y":
            while True:
                try:
                    ping_value = int(
                        input("Please enter the ping value (in seconds): ")
                    )
                    if ping_value < 1:
                        raise ValueError
                except ValueError:
                    print("[!] Invalid value. Please enter a positive integer.")

                try:
                    ping_exit_value = int(
                        input("Please enter the ping-exit value (in seconds): ")
                    )
                    if ping_exit_value < 1 or ping_exit_value <= ping_value:
                        raise ValueError
                    break
                except ValueError:
                    print(
                        f"[!] Invalid value. Please enter a positive integer higher than the ping interval (${ping_value})."
                    )

            set_config_value("USER", "ping", ping_value)
            set_config_value("USER", "ping_exit", ping_exit_value)
        else:
            set_config_value("USER", "ping", 0)
            set_config_value("USER", "ping_exit", 0)

    else:
        print(
            "[!] Ping-exit can't be used with the ping-restart option not ignored.\n"
            + "[!] Ping-exit has been disabled.\n"
        )

        set_config_value("USER", "ping", 0)
        set_config_value("USER", "ping_exit", 0)

    print()
    print("Lost connection options updated.")


def set_upgrade_notice():
    """Enable or disable the upgrade notice."""

    try:
        current_status = int(get_config_value("USER", "show_upgrade_notice"))
    except (KeyError, ValueError):
        current_status = 1  # Default to enabled if missing or invalid

    print()
    print(
        f"The upgrade notice is currently {'enabled' if current_status else 'disabled'}."
    )
    print("This notice informs about the official ProtonVPN Linux app.")
    print()
    print("1) Enable upgrade notice\n2) Disable upgrade notice")

    while True:
        print()
        user_choice = input("Please enter your choice or leave empty to quit: ")
        user_choice = user_choice.strip()

        if user_choice == "1":
            new_status = 1
            break
        elif user_choice == "2":
            new_status = 0
            break
        elif user_choice == "":
            print("Quitting configuration.")
            return  # Use return instead of sys.exit to go back to the main loop
        else:
            print("[!] Invalid choice. Please enter 1 or 2.")

    set_config_value("USER", "show_upgrade_notice", new_status)
    print()
    print(f"Upgrade notice has been {'enabled' if new_status else 'disabled'}.")
