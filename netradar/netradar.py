"""
This class implements a network scanner. It implements multiple methods to find devices on a network.

Author: Eric-Canas
Email: eric@ericcanas.com
Date: 15-05-2023
"""
import socket
from threading import Thread

from .utils import can_use_raw_sockets, check_is_ip_range, get_my_ip, get_default_gateway, get_my_subnets, \
    get_router_subnet, SUBNET

MAC, NAME, VENDOR, PORTS, STATE, SUBNET, GATEWAY = 'mac', 'name', 'vendor', 'ports', 'state', SUBNET, 'gateway'
# Frozen dictionary to use as a template for the database
BASE_DICT = {MAC: None, NAME: None, VENDOR: None, PORTS: None, STATE: None, SUBNET: None, GATEWAY: None}


class NetRadar:
    def __init__(self, ip_range: str = None, max_threads: int = 25):

        # Auto-detect the subnet if necessary
        self.device_subnets_info = get_my_subnets()
        self.router_subnet_info = get_router_subnet()
        self.subnet = self.router_subnet_info[SUBNET] if ip_range is None else ip_range
        assert ip_range is None, f"Invalid ip range: {ip_range}{'. Could not detect device subnet' if ip_range == self.router_subnet_info else ''}"
        assert check_is_ip_range(self.subnet), f"Invalid subnet: {ip_range}. Must be in CIDR notation."

        self.device_ip = get_my_ip()
        self._gateway = get_default_gateway()
        self.have_privileges = can_use_raw_sockets()

        self.max_threads = max_threads
        self.devices = {}

    def get_device_info(self, ip: str) -> dict:
        """
        Retrieve all the information for a device.

        :param ip: IP address of the device
        :type ip: str
        :return: A dictionary with all the device information
        :rtype: dict
        """
        device_info = BASE_DICT.copy() if ip not in self.devices else self.devices[ip].copy()

        device_info[MAC] = self.get_mac_address(ip) if device_info[MAC] is None else device_info[MAC]
        device_info[NAME] = self.get_hostname(ip) if device_info[NAME] is None else device_info[NAME]
        device_info[VENDOR] = self.get_vendor(device_info[MAC]) if device_info[VENDOR] is None else device_info[VENDOR]
        device_info[PORTS] = self.scan_ports(ip) if device_info[PORTS] is None else device_info[PORTS]
        device_info[STATE] = self.get_device_state(ip) if device_info[STATE] is None else device_info[STATE]
        device_info[SUBNET] = self.subnet if device_info[SUBNET] is None else device_info[SUBNET]
        device_info[GATEWAY] = self._gateway if device_info[GATEWAY] is None else device_info[GATEWAY]

        return device_info

    def scan_device(self, ip: str):
        """
        Tries to get the hostname for the given IP.
        If it succeeds, adds the device to the devices dict.
        """
        try:
            name = socket.gethostbyaddr(ip)[0]
            self.devices[ip] = self.get_device_info(ip)
            self.devices[ip][NAME] = name
        except socket.herror:
            pass

    def scan(self):
        """
        This method will scan the network and populate the devices dictionary with the devices found.
        The devices dictionary will be a dictionary of dictionaries, where the key is the IP address of the device
        and the content will be the BASE_DICT, containing only the information we could retrieve from the scan.
        """
        threads = []
        for i in range(1, 256):
            ip = f"{self.subnet.split('.')[0:-1]}.{i}"
            thread = Thread(target=self.scan_device, args=(ip,))
            threads.append(thread)
            thread.start()
            if len(threads) >= self.max_threads:
                for thread in threads:
                    thread.join()
                threads = []
        # Join remaining threads
        for thread in threads:
            thread.join()

    def get_mac_address(self, ip):
        # Implement MAC address lookup
        pass

    def get_hostname(self, ip: str) -> str:
        """
        Get the hostname for a given IP address.

        :param ip: IP address of the device
        :type ip: str
        :return: Hostname of the device
        :rtype: str
        """
        # Implement hostname lookup
        pass

    def get_vendor(self, mac: str) -> str:
        """
        Get the vendor name for a given MAC address.

        :param mac: MAC address of the device
        :type mac: str
        :return: Vendor of the device
        :rtype: str
        """
        # Implement vendor lookup
        pass

    def scan_ports(self, ip: str) -> list:
        """
        Scan the ports for a given IP address.

        :param ip: IP address of the device
        :type ip: str
        :return: List of open ports
        :rtype: list
        """
        # Implement port scanning
        pass

    def get_device_state(self, ip: str) -> str:
        """
        Get the state of a device for a given IP address.

        :param ip: IP address of the device
        :type ip: str
        :return: State of the device
        :rtype: str
        """
        # Implement device state determination
        pass

    def get_network_info(self) -> dict:
        """
        Scan the network and retrieve all the device information.

        :return: A dictionary of device information
        :rtype: dict
        """
        self.scan()
        return self.devices

    def __str__(self):
        def pretty_dict(d: dict, indent=0) -> str:
            """Returns a string representation of a dictionary with custom formatting."""
            lines = []
            for key, value in d.items():
                lines.append('\t' * indent + f'{key}: {value}')
            return '\n'.join(lines)

        return f"My Device Info:\n" \
               f"{pretty_dict(self.get_device_info(ip=self.device_ip), indent=1)}\n" \
               f"Router subnet:\n" \
               f"{pretty_dict(self.router_subnet_info, indent=1)}\n"

