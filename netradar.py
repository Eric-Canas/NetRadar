"""
This class implements a network scanner. It implements multiple methods to find devices on a network.

Author: Eric-Canas
Email: eric@ericcanas.com
Date: 12-05-2023
"""

import scapy
import socket
from threading import Thread
import os

from utils import can_use_raw_sockets, check_is_subnet

MAC, NAME, VENDOR, PORTS, STATE = 'mac', 'name', 'vendor', 'ports', 'state'
# Frozen dictionary to use as a template for the database
BASE_DICT = {MAC: None, NAME: None, VENDOR: None, PORTS: None, STATE: None}


class NetRadar:
    def __init__(self, subnet: str, max_threads: int = 25):
        #assert check_is_subnet(subnet=subnet), "The given subnet is not valid."
        self.subnet = subnet
        self.max_threads = max_threads
        self.devices = {}

        self.have_privileges = can_use_raw_sockets()

    def scan_device(self, ip: str):
        """
        Tries to get the hostname for the given IP.
        If it succeeds, adds the device to the devices dict.
        """
        try:
            name = socket.gethostbyaddr(ip)[0]
            self.devices[ip] = {MAC: None, NAME: name, VENDOR: None, PORTS: None, STATE: None}
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
            ip = f"{self.ip_range}.{i}"
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

    def get_hostname(self, ip):
        # Implement hostname lookup
        pass

    def get_vendor(self, mac):
        # Implement vendor lookup
        pass

    def scan_ports(self, ip):
        # Implement port scanning
        pass

    def get_device_state(self, ip):
        # Implement device state determination
        pass

    def get_network_info(self):
        self.scan()
        for ip, device in self.devices.items():
            device['mac'] = self.get_mac_address(ip)
            device['name'] = self.get_hostname(ip)
            device['vendor'] = self.get_vendor(device['mac'])
            device['ports'] = self.scan_ports(ip)
            device['state'] = self.get_device_state(ip)
        return self.devices
