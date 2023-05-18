from __future__ import annotations

import socket
import re
import netifaces
import ipaddress

SUBNET_REGEX_PATTERN = r"^(?:(?:25[0-5]|2[0-4]\d|1\d{2}|\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|\d{1,2})/(?:[1-9]|[1-2]\d|3[0-2])$"
IP, NETMASK, SUBNET = 'ip', 'netmask', 'subnet'


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

def check_is_ip_range(subnet: str) -> bool:
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

def get_my_subnets() -> tuple[dict[str, str], ...]:
    """
    Returns the subnet of the device.

    :return: Subnet of the device.
    :rtype: str
    """
    valid_addr = tuple(netifaces.ifaddresses(iface) for iface in netifaces.interfaces()
                       if netifaces.AF_INET in netifaces.ifaddresses(iface))
    submasks = []
    for addr in valid_addr:
        ip_info = addr[netifaces.AF_INET][0]
        ip, netmask = ip_info['addr'], ip_info['netmask']

        submasks.append({
            IP: ip,
            NETMASK: netmask,
            SUBNET: to_cidr(ip=ip, netmask=netmask)
        })
    return tuple(submasks)

def get_router_subnet() -> dict[str, str]|None:
    """
    Returns the subnet that includes the default gateway (router).

    :return: Subnet of the router, or None if no matching subnet was found.
    """
    default_gateway = get_default_gateway()
    if default_gateway is None:
        return None

    for subnet in get_my_subnets():
        # Convert the CIDR to a network object
        network = ipaddress.ip_network(subnet[SUBNET], strict=False)

        # Check if the default gateway is in this subnet
        if ipaddress.ip_address(default_gateway) in network:
            return subnet

    return None


def get_network_address(ip: str, netmask: str) -> str:
    """
    Returns the network address for the given IP and netmask.

    :param ip: IP address.
    :param netmask: Network mask.
    :return: Network address.
    """
    ip_parts = map(int, ip.split('.'))
    netmask_parts = map(int, netmask.split('.'))
    network_parts = [ip_part & netmask_part for ip_part, netmask_part in zip(ip_parts, netmask_parts)]
    return '.'.join(map(str, network_parts))


def to_cidr(ip: str, netmask: str) -> str:
    """
    Converts IP and netmask to CIDR notation.

    :param ip: IP address.
    :param netmask: Network mask.
    :return: IP and network in CIDR notation.
    """
    network = get_network_address(ip, netmask)
    mask = sum(bin(int(x)).count('1') for x in netmask.split('.'))
    return f"{network}/{mask}"

