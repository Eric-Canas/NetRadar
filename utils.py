import socket
import re

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