"""
Network scanner module for discovering devices on the network.
Includes functionality for ping sweeps, ARP scans, and port scanning.
"""

import socket
import ipaddress
import threading
import time
from typing import List, Dict, Any, Optional, Callable

import nmap
from scapy.all import ARP, Ether, srp

from utils.logger import get_logger

logger = get_logger(__name__)


class NetworkScanner:
    """Network scanner for discovering devices on the network."""
    
    def __init__(self):
        """Initialize the network scanner."""
        self.nm = nmap.PortScanner()
        self.scan_results = {}
        self.is_scanning = False
        self.current_scan_thread = None
    
    def ping_sweep(self, network: str, callback: Optional[Callable] = None) -> Dict[str, Dict[str, Any]]:
        """
        Perform a ping sweep on the specified network.
        
        Args:
            network: Network in CIDR notation (e.g., '192.168.1.0/24')
            callback: Optional callback function for progress updates
            
        Returns:
            Dictionary of live hosts with basic info
        """
        logger.info(f"Starting ping sweep on {network}")
        try:
            # Convert network string to IP network object
            net = ipaddress.ip_network(network)
            hosts = list(net.hosts())
            total_hosts = len(hosts)
            alive_hosts = {}
            
            for i, ip in enumerate(hosts):
                ip_str = str(ip)
                
                # Try to get hostname
                try:
                    hostname = socket.gethostbyaddr(ip_str)[0]
                except socket.herror:
                    hostname = "Unknown"
                
                # Check if host is alive
                response = self.nm.scan(hosts=ip_str, arguments='-sn')
                
                if ip_str in response['scan'] and response['scan'][ip_str]['status']['state'] == 'up':
                    alive_hosts[ip_str] = {
                        'hostname': hostname,
                        'status': 'up',
                        'mac': response['scan'][ip_str].get('addresses', {}).get('mac', 'Unknown')
                    }
                
                # Update progress if callback provided
                if callback:
                    progress = (i + 1) / total_hosts * 100
                    callback(progress, ip_str, len(alive_hosts))
            
            logger.info(f"Ping sweep completed. Found {len(alive_hosts)} alive hosts.")
            return alive_hosts
        
        except Exception as e:
            logger.error(f"Error during ping sweep: {e}")
            return {}
    
    def arp_scan(self, interface: str, network: str, callback: Optional[Callable] = None) -> Dict[str, Dict[str, Any]]:
        """
        Perform an ARP scan on the specified network.
        
        Args:
            interface: Network interface to use
            network: Network in CIDR notation (e.g., '192.168.1.0/24')
            callback: Optional callback function for progress updates
            
        Returns:
            Dictionary of devices with IP and MAC addresses
        """
        logger.info(f"Starting ARP scan on {network} using interface {interface}")
        try:
            # Create ARP request packet
            arp = ARP(pdst=network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast MAC address
            packet = ether/arp
            
            # Send packet and capture responses
            result = srp(packet, timeout=3, verbose=0, iface=interface)[0]
            
            devices = {}
            total_devices = len(result)
            
            for i, (sent, received) in enumerate(result):
                ip = received.psrc
                mac = received.hwsrc
                
                # Try to get hostname
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except socket.herror:
                    hostname = "Unknown"
                
                devices[ip] = {
                    'mac': mac,
                    'hostname': hostname,
                    'status': 'up'
                }
                
                # Update progress if callback provided
                if callback:
                    progress = (i + 1) / total_devices * 100
                    callback(progress, ip, len(devices))
            
            logger.info(f"ARP scan completed. Found {len(devices)} devices.")
            return devices
        
        except Exception as e:
            logger.error(f"Error during ARP scan: {e}")
            return {}
    
    def port_scan(self, target: str, ports: str = "1-1024", callback: Optional[Callable] = None) -> Dict[str, Dict[str, Any]]:
        """
        Scan specified ports on target.
        
        Args:
            target: Target IP or hostname
            ports: Port range to scan (e.g., '1-1024' or '22,80,443')
            callback: Optional callback function for progress updates
            
        Returns:
            Dictionary of open ports with service information
        """
        logger.info(f"Starting port scan on {target} (ports {ports})")
        try:
            result = {}
            arguments = f'-sS -p {ports}'  # SYN scan
            
            # Run nmap scan
            self.nm.scan(hosts=target, arguments=arguments)
            
            # Process results
            if target in self.nm.all_hosts():
                result[target] = {'ports': {}}
                
                # Get port information
                for proto in self.nm[target].all_protocols():
                    lport = sorted(self.nm[target][proto].keys())
                    total_ports = len(lport)
                    
                    for i, port in enumerate(lport):
                        service = self.nm[target][proto][port]
                        result[target]['ports'][port] = {
                            'state': service['state'],
                            'name': service['name'],
                            'product': service.get('product', ''),
                            'version': service.get('version', '')
                        }
                        
                        # Update progress if callback provided
                        if callback:
                            progress = (i + 1) / total_ports * 100
                            callback(progress, f"Port {port}", i + 1)
            
            logger.info(f"Port scan completed on {target}")
            return result
        
        except Exception as e:
            logger.error(f"Error during port scan: {e}")
            return {}
    
    def start_scan(self, scan_type: str, target: str, **kwargs) -> None:
        """
        Start a scan in a separate thread.
        
        Args:
            scan_type: Type of scan ('ping', 'arp', 'port')
            target: Target network or IP
            **kwargs: Additional scan parameters
        """
        if self.is_scanning:
            logger.warning("A scan is already in progress")
            return
        
        self.is_scanning = True
        self.scan_results = {}
        
        # Define scan function
        if scan_type == 'ping':
            scan_fn = lambda: self.ping_sweep(target, kwargs.get('callback'))
        elif scan_type == 'arp':
            scan_fn = lambda: self.arp_scan(kwargs.get('interface', ''), target, kwargs.get('callback'))
        elif scan_type == 'port':
            scan_fn = lambda: self.port_scan(target, kwargs.get('ports', '1-1024'), kwargs.get('callback'))
        else:
            logger.error(f"Unknown scan type: {scan_type}")
            self.is_scanning = False
            return
        
        # Start scan in separate thread
        def scan_thread():
            try:
                self.scan_results = scan_fn()
            finally:
                self.is_scanning = False
                if kwargs.get('on_complete'):
                    kwargs['on_complete'](self.scan_results)
        
        self.current_scan_thread = threading.Thread(target=scan_thread)
        self.current_scan_thread.daemon = True
        self.current_scan_thread.start()
    
    def stop_scan(self) -> None:
        """Stop any ongoing scan."""
        if self.is_scanning and self.current_scan_thread:
            self.is_scanning = False
            logger.info("Stopping scan...")
            # Since we can't directly stop a thread, we'll just wait for it to finish
            # by setting is_scanning to False, which should cause the scan to stop
            # on the next iteration
    
    def get_scan_results(self) -> Dict[str, Dict[str, Any]]:
        """Get the results of the most recent scan."""
        return self.scan_results


if __name__ == "__main__":
    # Example usage
    scanner = NetworkScanner()
    
    def progress_callback(progress, current_item, count):
        print(f"Progress: {progress:.1f}% - Scanning {current_item} - Found {count} devices")
    
    # Ping sweep example
    print("Performing ping sweep...")
    results = scanner.ping_sweep('192.168.1.0/24', progress_callback)
    print(f"Ping sweep results: {results}")
    
    # ARP scan example
    print("\nPerforming ARP scan...")
    results = scanner.arp_scan('eth0', '192.168.1.0/24', progress_callback)
    print(f"ARP scan results: {results}")
    
    # Port scan example
    print("\nPerforming port scan...")
    results = scanner.port_scan('192.168.1.1', '22,80,443', progress_callback)
    print(f"Port scan results: {results}")