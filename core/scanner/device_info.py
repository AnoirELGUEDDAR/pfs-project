"""
Device information gathering module
"""
import logging
import platform
import socket
import subprocess
import re
from typing import Dict, Optional

import psutil
import netifaces
import nmap

logger = logging.getLogger(__name__)

class DeviceInfoScanner:
    """Scanner for gathering detailed information about network devices"""
    
    def __init__(self):
        self.nm = nmap.PortScanner()
    
    def get_device_details(self, ip_address: str) -> Dict:
        """
        Get detailed information about a specific device
        
        Args:
            ip_address: IP address of the device
            
        Returns:
            Dictionary with detailed device information
        """
        device_info = {
            "ip": ip_address,
            "mac": self._get_mac_address(ip_address),
            "hostname": self._get_hostname(ip_address),
            "os": self._detect_os(ip_address),
            "open_ports": self._scan_common_ports(ip_address),
            "services": {}
        }
        
        return device_info
    
    def _get_mac_address(self, ip_address: str) -> str:
        """
        Get MAC address for an IP address
        
        Args:
            ip_address: IP address of the device
            
        Returns:
            MAC address as string or empty string if not found
        """
        try:
            # Try to get from ARP table first (faster)
            if platform.system() == "Windows":
                output = subprocess.check_output(f"arp -a {ip_address}", shell=True).decode()
                matches = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", output)
                if matches:
                    return matches.group(0)
            elif platform.system() in ["Linux", "Darwin"]:
                output = subprocess.check_output(["arp", "-n", ip_address]).decode()
                matches = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", output)
                if matches:
                    return matches.group(0)
                    
            # If local, get from interfaces
            if ip_address == "127.0.0.1" or self._is_self_ip(ip_address):
                for interface in netifaces.interfaces():
                    addresses = netifaces.ifaddresses(interface)
                    if netifaces.AF_LINK in addresses and addresses[netifaces.AF_LINK][0].get('addr'):
                        return addresses[netifaces.AF_LINK][0]['addr']
        except Exception as e:
            logger.error(f"Error getting MAC address for {ip_address}: {e}")
        
        return ""
    
    def _get_hostname(self, ip_address: str) -> str:
        """
        Resolve hostname for an IP address
        
        Args:
            ip_address: IP address to resolve
            
        Returns:
            Hostname as string or IP if not resolvable
        """
        try:
            if ip_address == "127.0.0.1" or self._is_self_ip(ip_address):
                return socket.gethostname()
            return socket.gethostbyaddr(ip_address)[0]
        except (socket.herror, socket.gaierror):
            return ip_address
    
    def _detect_os(self, ip_address: str) -> str:
        """
        Try to detect the operating system of a device
        
        Args:
            ip_address: IP address of the device
            
        Returns:
            String with OS information or "Unknown"
        """
        # If local machine, return actual OS info
        if ip_address == "127.0.0.1" or self._is_self_ip(ip_address):
            return f"{platform.system()} {platform.release()}"
        
        try:
            # Use Nmap for OS detection (requires root/admin privileges)
            self.nm.scan(ip_address, arguments="-O --osscan-guess -T4")
            if ip_address in self.nm and 'osmatch' in self.nm[ip_address]:
                if len(self.nm[ip_address]['osmatch']) > 0:
                    return self.nm[ip_address]['osmatch'][0]['name']
            
            # Alternative: Try to guess from open ports
            self.nm.scan(ip_address, arguments="-sV -T4")
            if ip_address in self.nm and 'tcp' in self.nm[ip_address]:
                ports = self.nm[ip_address]['tcp']
                if 445 in ports:  # SMB
                    return "Windows"
                if 22 in ports:  # SSH
                    return "Linux/Unix"
        except Exception as e:
            logger.error(f"Error detecting OS for {ip_address}: {e}")
        
        return "Unknown"
    
    def _scan_common_ports(self, ip_address: str) -> Dict:
        """
        Scan common ports on a device
        
        Args:
            ip_address: IP address to scan
            
        Returns:
            Dictionary of open ports with service information
        """
        open_ports = {}
        common_ports = '21,22,23,25,53,80,443,445,3389,8080'
        
        try:
            self.nm.scan(ip_address, common_ports)
            if ip_address in self.nm and 'tcp' in self.nm[ip_address]:
                for port, data in self.nm[ip_address]['tcp'].items():
                    if data['state'] == 'open':
                        open_ports[port] = {
                            'service': data.get('name', 'unknown'),
                            'product': data.get('product', ''),
                            'version': data.get('version', '')
                        }
        except Exception as e:
            logger.error(f"Error scanning ports for {ip_address}: {e}")
        
        return open_ports
    
    def _is_self_ip(self, ip_address: str) -> bool:
        """Check if IP address belongs to local machine"""
        for iface in netifaces.interfaces():
            iface_addresses = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in iface_addresses:
                for addr in iface_addresses[netifaces.AF_INET]:
                    if addr.get('addr') == ip_address:
                        return True
        return False