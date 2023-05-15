from __future__ import annotations

import socket
import re
import netifaces

SUBNET_REGEX_PATTERN = r"^(?:(?:25[0-5]|2[0-4]\d|1\d{2}|\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|\d{1,2})/(?:[1-9]|[1-2]\d|3[0-2])$"

def can_use_raw_sockets() -> bool:
    """
    Checks if the current user has the necessary permissions to use raw sockets.

    :return: True if the user has the necessary permissions, False otherwise.
    """
    raw_socket = None
    try:
        # Attempt to create a raw socket
        raw_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_RAW, proto=socket.IPPROTO_ICMP)
        return True
    except PermissionError:
        # The user doesn't have the necessary permissions
        return False
    finally:
        # Make sure to close the socket
        if raw_socket is not None:
            raw_socket.close()

def check_is_subnet(subnet: str) -> bool:
    """
    Checks if the given IP address is a valid network mask. (For example: 192.168.1.0/24)

    :return: True if the given IP address is a valid network mask, False otherwise.
    """
    return re.match(SUBNET_REGEX_PATTERN, subnet) is not None

def get_my_ip() -> str:
    """
    This function returns the IP address of the current device.

    :return: IP address of the current device.
    :rtype: str
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip


def get_default_gateway() -> str|None:
    """
    Returns the default gateway IP address of the current device.

    :return: Gateway IP address
    :rtype: str
    """
    try:
        default_gateway = netifaces.gateways()['default'][netifaces.AF_INET][0]
    except KeyError:
        default_gateway = None
    return default_gateway

def get_my_subnet() -> str|None:
    """
    Returns the subnet of the device.

    :return: Subnet of the device.
    :rtype: str
    """
    for iface in netifaces.interfaces():
        addr = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addr:
            ip_info = addr[netifaces.AF_INET][0]
            ip = ip_info['addr']
            netmask = ip_info['netmask']

            # Convert netmask to cidr
            netmask = sum([bin(int(x)).count('1') for x in netmask.split('.')])

            return f"{ip}/{netmask}"
    return None