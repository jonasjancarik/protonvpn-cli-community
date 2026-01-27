# Standard Libraries
import os
import sys
import configparser
import time
import json
import subprocess
import re
import random
import ipaddress
import math
import getpass

# External Libraries
import requests
from jinja2 import Environment, FileSystemLoader

# ProtonVPN-CLI functions
from .logger import logger

# Constants
from .constants import (
    USER,
    CONFIG_FILE,
    SERVER_INFO_FILE,
    SPLIT_TUNNEL_FILE,
    VERSION,  # we could use this for the API identification, but it blocks low version numbers as no longer supported
    OVPN_FILE,
    CLIENT_SUFFIX,
)
import socket
import asyncio
from proton.vpn.core.api import ProtonVPNAPI
from proton.vpn.core.session_holder import ClientTypeMetadata


def pull_server_data(force=False, username=None, password=None):
    """
    Pull current server data from the ProtonVPN API using the proton-python-client library.
    Returns True on success, False on failure.
    """
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)

    if not force:
        # Check if last server pull happened within the last 15 min (900 sec)
        # Added check for existence of last_api_pull key
        if "metadata" in config and "last_api_pull" in config["metadata"]:
            try:
                last_pull_time = int(config["metadata"]["last_api_pull"])
                if int(time.time()) - last_pull_time <= 900:
                    logger.debug("Last server pull within 15mins, assuming success")
                    return True  # Assume cached data is good
            except ValueError:
                logger.debug(
                    "Invalid last_api_pull value in config, proceeding with API call."
                )
        else:
            logger.debug("last_api_pull not found in config, proceeding with API call.")

    # Get username and password from parameters or config
    if username is None:
        try:
            username = get_config_value("USER", "username")
        except KeyError:
            logger.debug(
                "Username not found in config, cannot use ProtonVPN API library"
            )
            return False

    if password is None:
        try:
            password = get_config_value("USER", "password")
        except KeyError:
            logger.debug(
                "Password not found in config, cannot use ProtonVPN API library"
            )
            return False

    # Define metadata for the client application (match official CLI)
    client_meta = ClientTypeMetadata(
        type="cli",
        version="99.99.99",
    )

    # Create the API object
    api = ProtonVPNAPI(client_type_metadata=client_meta)

    # Define the authentication function
    async def authenticate():
        try:
            login_result = await api.login(username, password)
            if login_result.twofa_required:
                twofa_code = (
                    os.getenv("PROTONVPN_2FA")
                    or os.getenv("PROTONVPN_2FA_CODE")
                )
                if not twofa_code:
                    try:
                        twofa_code = getpass.getpass("2FA Token: ")
                    except Exception as e:
                        logger.error(f"Failed to read 2FA token: {e}")
                        return False
                if not twofa_code:
                    logger.error(
                        "2FA required. Set PROTONVPN_2FA (or PROTONVPN_2FA_CODE) or enter a token."
                    )
                    return False
                try:
                    login_result = await api.submit_2fa_code(twofa_code.strip())
                except Exception as e:
                    logger.error(f"2FA submission failed: {e}", exc_info=True)
                    return False
                if login_result.twofa_required:
                    logger.error("2FA required, invalid or expired token")
                    return False
            if not login_result.authenticated:
                logger.error("Authentication failed")
                return False
            logger.debug("Authentication successful")
            return True
        except Exception as e:
            logger.error(f"Authentication error during API login: {e}", exc_info=True)
            return False

    # Run the authentication
    auth_success = asyncio.run(authenticate())

    if not auth_success:
        logger.error("Failed to authenticate with ProtonVPN API library")
        return False

    # Enable the refresher to get server data
    async def enable_refresher():
        try:
            await api.refresher.enable()
            # Wait for the refresher to indicate data is ready
            timeout = 30  # seconds
            start_time = time.time()
            while not api.refresher.is_vpn_data_ready:
                if time.time() - start_time > timeout:
                    logger.error("Timed out waiting for VPN data from API library")
                    return False
                await asyncio.sleep(0.5)
            logger.debug("Refresher enabled and data ready.")
            return True
        except Exception as e:
            logger.error(f"Error enabling API refresher: {e}", exc_info=True)
            return False

    # Run the refresher
    refresher_success = asyncio.run(enable_refresher())

    if not refresher_success:
        logger.error("Failed to enable refresher or get VPN data")
        return False

    # Get the server list data
    if api.vpn_session_loaded and api.server_list:
        logger.debug("Accessing server list data from ProtonVPN API library")
        server_data = api.server_list

        # Convert the server data to the expected format using the to_dict method
        data = server_data.to_dict()

        try:
            with open(SERVER_INFO_FILE, "w") as f:
                json.dump(data, f)
                logger.debug("SERVER_INFO_FILE written")

            change_file_owner(SERVER_INFO_FILE)
            # Ensure metadata section exists before writing
            if "metadata" not in config:
                config.add_section("metadata")
            config["metadata"]["last_api_pull"] = str(int(time.time()))

            with open(CONFIG_FILE, "w+") as f:
                config.write(f)
                logger.debug("last_api_call updated")
            return True
        except (IOError, OSError) as e:
            logger.debug(f"Error writing server/config file: {e}")
            return False
    else:
        logger.debug("Server list data is not available from ProtonVPN API library")
        return False


def get_servers():
    """Return a list of all servers for the users Tier."""

    with open(SERVER_INFO_FILE, "r") as f:
        logger.debug("Reading servers from file")
        server_data = json.load(f)

    servers = server_data["LogicalServers"]

    user_tier = int(get_config_value("USER", "tier"))

    # Sort server IDs by Tier
    return [
        server
        for server in servers
        if server["Tier"] <= user_tier and server["Status"] == 1
    ]  # noqa


def get_server_value(servername, key, servers):
    """Return the value of a key for a given server."""
    value = [server[key] for server in servers if server["Name"] == servername]
    return value[0]


def get_config_value(group, key):
    """Return specific value from CONFIG_FILE as string"""
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)

    return config[group][key]


def set_config_value(group, key, value):
    """Set specific value in CONFIG_FILE"""
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)

    if not config.has_section(group):
        config.add_section(group)

    config[group][key] = str(value)

    with open(CONFIG_FILE, "w+") as f:
        config.write(f)


def remove_config_value(group, key):
    """Remove a specific key from a group in CONFIG_FILE"""
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)

    if config.has_section(group) and config.has_option(group, key):
        config.remove_option(group, key)
        logger.debug(f"Removed [{group}] {key} from config.")
        with open(CONFIG_FILE, "w") as f:
            config.write(f)
    else:
        logger.debug(f"Key [{group}] {key} not found in config, nothing to remove.")


def get_ip_info():
    """Return current IP address and ISP info using ipinfo.io"""
    logger.debug("Getting IP Information")
    try:
        # Use ipify.org to get the public IP address
        response = requests.get("https://api.ipify.org?format=json")
        response.raise_for_status()
        ip_data = response.json()
        ip = ip_data.get("ip")

        # Use ip-api.com to get ISP information
        isp_response = requests.get(f"http://ip-api.com/json/{ip}")
        isp_response.raise_for_status()
        isp_data = isp_response.json()
        isp = isp_data.get("isp")

        return ip, isp
    except Exception as e:
        logger.debug(f"Error getting IP info: {e}")
        return None, None


def get_country_name(code):
    """Return the full name of a country from code"""

    from .country_codes import country_codes

    return country_codes.get(code, code)


def get_fastest_server(server_pool):
    """Return the fastest server from a list of servers"""

    # Sort servers by "speed" and select top n according to pool_size
    fastest_pool = sorted(server_pool, key=lambda server: server["Score"])
    if len(fastest_pool) >= 50:
        pool_size = 4
    else:
        pool_size = 1
    logger.debug("Returning fastest server with pool size {0}".format(pool_size))
    fastest_server = random.choice(fastest_pool[:pool_size])["Name"]
    return fastest_server


def get_default_nic():
    """Find and return the default network interface"""
    default_route = subprocess.run(
        "ip route show | grep default", stdout=subprocess.PIPE, shell=True
    )

    # Get the default nic from ip route show output
    default_nic = default_route.stdout.decode().strip().split()[4]
    return default_nic


def is_connected():
    """Check if a VPN connection already exists."""
    ovpn_processes = subprocess.run(["pgrep", "-x", "openvpn"], stdout=subprocess.PIPE)
    ovpn_processes = ovpn_processes.stdout.decode("utf-8").split()
    logger.debug(f"OpenVPN processes: {ovpn_processes}")

    logger.debug(
        "Checking connection Status. OpenVPN processes: {0}".format(len(ovpn_processes))
    )
    return True if ovpn_processes != [] else False


def is_ipv6_disabled():
    """Returns True if IPv6 is disabled and False if it's enabled"""
    ipv6_state = subprocess.run(
        ["sysctl", "-n", "net.ipv6.conf.all.disable_ipv6"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )

    if ipv6_state.returncode != 0 or int(ipv6_state.stdout):
        return True
    else:
        return False


def wait_for_network(wait_time):
    """Check if internet access is working by attempting to refresh server data."""

    print("Waiting for connection...")
    start = time.time()

    while True:
        if time.time() - start > wait_time:
            logger.debug("Max waiting time reached.")
            print("Max waiting time reached.")
            sys.exit(1)

        logger.debug("Attempting to refresh server data to check connection...")
        # TODO: Using full server data pull just for connectivity check is inefficient.
        # Consider a lighter API check if available in the library or a simple HTTP GET.
        success = pull_server_data(force=True)

        if success:
            print("Connection working! Tested by refreshing server data.")
            logger.debug("Connection confirmed via server data refresh.")
            break
        else:
            logger.debug(
                "Server data refresh failed, likely no connection. Retrying..."
            )
            time.sleep(2)


def cidr_to_netmask(cidr):
    subnet = ipaddress.IPv4Network("0.0.0.0/{0}".format(cidr))
    return str(subnet.netmask)


def render_j2_template(template_file, destination_file, values):
    """
    Render a Jinja2 template from a file and save it to a specified location
    template_file = name of jinja2 template
    destination_file = path where rendered file will be saved to
    values = dictionary with values for jinja2 templates
    """

    j2 = Environment(
        loader=FileSystemLoader(
            os.path.join(os.path.dirname(os.path.realpath(__file__)), "templates")
        )
    )
    template = j2.get_template(template_file)

    # Render Template and write to file
    with open(destination_file, "w") as f:
        f.write(template.render(values))
    logger.debug("Rendered {0} from {1}".format(destination_file, template_file))
    change_file_owner(destination_file)


def create_openvpn_config(serverlist, protocol, ports):
    """
    Create the OpenVPN Config file
    serverlist = list with IPs or hostnames
    protocol = "udp" or "tcp"
    ports = list with possible ports
    """

    # Split Tunneling
    content = []

    try:
        if get_config_value("USER", "split_tunnel") == "1":
            split = True
            with open(SPLIT_TUNNEL_FILE, "r") as f:
                content = f.readlines()
        else:
            split = False
    except KeyError:
        split = False

    if os.getenv("PVPN_SPLIT_TUNNEL"):
        split = True

    ip_nm_pairs = []

    if split:
        if os.getenv("PVPN_SPLIT_TUNNEL"):
            content += [
                item.strip() for item in os.getenv("PVPN_SPLIT_TUNNEL").split(",")
            ]

        # deduplicate content
        content = list(set(content))

        for line in content:
            line = line.rstrip("\n")
            netmask = "255.255.255.255"
            if not (is_valid_ip(line) or is_valid_domain(line)):
                logger.debug("[!] '{0}' is invalid. Skipped.".format(line))
                continue
            if is_valid_domain(line):
                try:
                    ip = socket.gethostbyname_ex(line)[2]  # returns a list
                except socket.gaierror:
                    logger.debug("[!] '{0}' is invalid. Skipped.".format(line))
                    continue
            else:
                if "/" in line:
                    ip, cidr = line.split("/")
                    netmask = cidr_to_netmask(int(cidr))
                else:
                    ip = line

            # check if ip is a string or a list (multiple IPs)
            if isinstance(ip, str):
                ip_nm_pairs.append({"ip": ip, "nm": netmask})
            else:
                for item in ip:
                    ip_nm_pairs.append({"ip": item, "nm": netmask})

    # IPv6
    ipv6_disabled = is_ipv6_disabled()

    ignore_ping_restart = get_config_value("USER", "ignore_ping_restart") == "1"

    j2_values = {
        "openvpn_protocol": protocol,
        "serverlist": serverlist,
        "openvpn_ports": ports,
        "split": split,
        "ip_nm_pairs": ip_nm_pairs,
        "ipv6_disabled": ipv6_disabled,
        "ignore_ping_restart": ignore_ping_restart,
    }

    if os.getenv("PVPN_SPLIT_TUNNEL"):
        j2_values["split_type"] = os.getenv("PVPN_SPLIT_TUNNEL")
    elif get_config_value("USER", "split_tunnel") == "1":
        j2_values["split_type"] = get_config_value("USER", "split_type")
    else:
        j2_values["split_type"] = (
            "blacklist"  # default for CLI args-based split tunneling (no config file)
        )

    render_j2_template(
        template_file="openvpn_template.j2",
        destination_file=OVPN_FILE,
        values=j2_values,
    )


def change_file_owner(path):
    """Change the owner of specific files to the sudo user."""
    uid = int(subprocess.run(["id", "-u", USER], stdout=subprocess.PIPE).stdout)
    gid = int(subprocess.run(["id", "-u", USER], stdout=subprocess.PIPE).stdout)

    current_owner = subprocess.run(
        ["id", "-nu", str(os.stat(path).st_uid)], stdout=subprocess.PIPE
    ).stdout
    current_owner = current_owner.decode().rstrip("\n")

    # Only change file owner if it wasn't owned by current running user.
    if current_owner != USER:
        os.chown(path, uid, gid)
        logger.debug("Changed owner of {0} to {1}".format(path, USER))


def check_root():
    """Check if the program was executed as root and prompt the user."""
    if os.geteuid() != 0:
        print("[!] The program was not executed as root.\n[!] Please run as root.")
        logger.debug("Program wasn't executed as root")
        sys.exit(1)
    else:
        # Check for dependencies
        dependencies = ["openvpn", "ip", "sysctl", "pgrep", "pkill"]
        for program in dependencies:
            check = subprocess.run(
                ["which", program], stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            if not check.returncode == 0:
                logger.debug("{0} not found".format(program))
                print(
                    "'{0}' not found. \n".format(program)
                    + "Please install {0}.".format(program)
                )
                sys.exit(1)


def check_update():
    """Return the download URL if an Update is available, False if otherwise"""

    def get_latest_version():
        """Return the latest version from GitHub Releases"""
        logger.debug("Calling GitHub API")
        try:
            r = requests.get(
                "https://api.github.com/repos/jonasjancarik/protonvpn-cli-community/releases/latest"
            )
        except (
            requests.exceptions.ConnectionError,
            requests.exceptions.ConnectTimeout,
        ):
            logger.debug("Couldn't connect to GitHub API")
            return False
        try:
            r.raise_for_status()
        except requests.exceptions.HTTPError:
            logger.debug("HTTP Error with GitHub API: {0}".format(r.status_code))
            return False

        # version tag is usually vX.Y.Z, we want to strip the 'v'
        tag_name = r.json().get("tag_name", "")
        if tag_name.startswith("v"):
            release = tag_name[1:]
        else:
            release = tag_name

        return release

    # Determine if an update check should be run
    check_interval = int(get_config_value("USER", "check_update_interval"))
    check_interval = check_interval * 24 * 3600
    last_check = int(get_config_value("metadata", "last_update_check"))

    if (last_check + check_interval) >= time.time():
        # Don't check for update
        return

    logger.debug("Checking for new update")
    current_version = list(VERSION.split("."))
    current_version = [int(i) for i in current_version]
    logger.debug("Current: {0}".format(current_version))

    latest_version = get_latest_version()
    if not latest_version:
        # Skip if get_latest_version() ran into errors
        return
    latest_version = latest_version.split(".")
    latest_version = [int(i) for i in latest_version]
    logger.debug("Latest: {0}".format(latest_version))

    for idx, i in enumerate(latest_version):
        if i > current_version[idx]:
            logger.debug("Update found")
            update_available = True
            break
        elif i < current_version[idx]:
            logger.debug("No update")
            update_available = False
            break
    else:
        logger.debug("No update")
        update_available = False

    set_config_value("metadata", "last_update_check", int(time.time()))

    if update_available:
        latest_v_str = ".".join([str(x) for x in latest_version])
        print()
        print(
            "A new Update for ProtonVPN-CLI Community (v{0}) ".format(latest_v_str)
            + "is available.\n"
            + "To update to the latest release, run one of the following:\n"
            + "\n"
            + "  # with uv (recommended):\n"
            + "  uv tool upgrade protonvpn-cli\n"
            + "\n"
            + "  # or with pip:\n"
            + "  pip install --upgrade git+https://github.com/jonasjancarik/protonvpn-cli-community.git@v{0}\n".format(
                latest_v_str
            )
            + "\n"
            + "For more info, see:\n"
            + "https://github.com/jonasjancarik/protonvpn-cli-community/releases/tag/v{0}".format(
                latest_v_str
            )
        )


def check_init():
    """Check if a profile has been initialized, quit otherwise."""

    try:
        if not int(get_config_value("USER", "initialized")):
            print(
                "[!] There has been no profile initialized yet. "
                "Please run 'protonvpn init'."
            )
            logger.debug("Initialized Profile not found")
            sys.exit(1)
        else:
            # Check if required configuration values are set
            # If this isn't the case it will set a default value

            default_conf = {
                "USER": {
                    "username": "username",
                    "tier": "0",
                    "default_protocol": "udp",
                    "dns_leak_protection": "1",
                    "custom_dns": "None",
                    "check_update_interval": "3",
                    "killswitch": "0",
                    "split_tunnel": "0",
                    "api_domain": "https://api.protonvpn.ch",
                },
            }

            for section in default_conf:
                for config_key in default_conf[section]:
                    try:
                        get_config_value(section, config_key)
                    except KeyError:
                        logger.debug(
                            "Config {0}/{1} not found, default set".format(
                                section, config_key
                            )
                        )
                        set_config_value(
                            section, config_key, default_conf[section][config_key]
                        )

    except KeyError:
        print(
            "[!] There has been no profile initialized yet. "
            "Please run 'protonvpn init'."
        )
        logger.debug("Initialized Profile not found")
        sys.exit(1)


def is_valid_ip(ipaddr):
    valid_ip_re = re.compile(
        r"^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\."
        r"(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\."
        r"(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\."
        r"(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)"
        r"(/(3[0-2]|[12][0-9]|[1-9]))?$"  # Matches CIDR
    )

    if valid_ip_re.match(ipaddr):
        return True

    else:
        return False


def is_valid_domain(domain):
    """
    Validates a domain name. Returns True if the domain is valid, otherwise False.

    Args:
        domain (str): A domain name as a string. Whitespaces will be stripped.

    Returns:
        bool: Returns True if domain is valid, otherwise False.

    Example:
        >>> is_valid_domain("google.com")
        True
        >>> is_valid_domain("invalid_domain")
        False
    """

    # Check for valid characters and length in each domain part
    pattern = re.compile(
        r"^(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.){1,}(?!-)[A-Za-z0-9-]{1,63}(?<!-)$"
    )

    if pattern.match(domain.strip()):
        return True
    else:
        return False


def get_transferred_data():
    """Reads and returns the amount of data transferred during a session
    from the /sys/ directory"""

    def convert_size(size_bytes):
        """Converts byte amounts into human readable formats"""
        if size_bytes == 0:
            return "0B"
        size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")

        i = int(math.floor(math.log(size_bytes, 1000)))
        p = math.pow(1000, i)
        s = round(size_bytes / p, 2)
        return "{0} {1}".format(s, size_name[i])

    base_path = "/sys/class/net/{0}/statistics/{1}"

    if os.path.isfile(base_path.format("proton0", "rx_bytes")):
        adapter_name = "proton0"
    elif os.path.isfile(base_path.format("tun0", "rx_bytes")):
        adapter_name = "tun0"
    else:
        logger.debug("No usage stats for VPN interface available")
        return "-", "-"

    # Get transmitted and received bytes from /sys/ directory
    with open(base_path.format(adapter_name, "tx_bytes"), "r") as f:
        tx_bytes = int(f.read())

    with open(base_path.format(adapter_name, "rx_bytes"), "r") as f:
        rx_bytes = int(f.read())

    return convert_size(tx_bytes), convert_size(rx_bytes)


def patch_passfile(passfile):
    try:
        with open(passfile, "r") as f:
            ovpn_username = f.readline()
            ovpn_password = f.readline()
    except FileNotFoundError:
        print(
            f"[!] Password file not found at {passfile}\\n"
            "[!] Please make sure you have initialized the client "
            "with 'protonvpn init'"
        )
        logger.error(f"Password file not found: {passfile}")
        sys.exit(1)

    if CLIENT_SUFFIX not in ovpn_username.strip().split("+")[1:]:
        # Let's append the CLIENT_SUFFIX
        with open(passfile, "w") as f:
            f.write(
                "{0}+{1}\n{2}".format(
                    ovpn_username.strip(), CLIENT_SUFFIX, ovpn_password
                )
            )
        os.chmod(passfile, 0o600)
