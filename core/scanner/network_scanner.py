"""
Network scanner module for discovering devices on local network
"""
import socket
import logging
import threading
import time
import ipaddress
import subprocess
from typing import Dict, List, Callable, Optional
import platform
from datetime import datetime

logger = logging.getLogger(__name__)

class NetworkScanner:
    """Scanner for discovering devices on a network"""
    
    def __init__(self):
        self.scanning = False
        self.devices = {}
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        
    def scan(self, target: str = None, callback: Optional[Callable] = None) -> Dict:
        """
        Scan the network for devices
        
        Args:
            target: Target network to scan (e.g. '192.168.1.0/24')
                   If None, scans the local subnet
            callback: Function to call with each discovered device
            
        Returns:
            Dictionary of discovered devices
        """
        if self.scanning:
            logger.warning("Scan already in progress")
            return self.devices
            
        self.scanning = True
        self.stop_event.clear()
        self.devices = {}
        
        try:
            if not target:
                # Get local subnet to scan
                local_ip = self._get_local_ip()
                if not local_ip:
                    logger.error("Could not determine local IP")
                    self.scanning = False
                    return {}
                    
                # Create target based on local IP (assuming /24 subnet)
                ip_parts = local_ip.split('.')
                target = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
                
            logger.info(f"Starting network scan for {target}")
            start_time = time.time()
            
            # Parse IP network
            try:
                network = ipaddress.IPv4Network(target)
            except ValueError as e:
                try:
                    # Try as a single IP
                    network = ipaddress.IPv4Network(f"{target}/32")
                except:
                    logger.error(f"Invalid target format: {target}")
                    self.scanning = False
                    return {}
            
            # Scan all IPs in network (excluding network and broadcast address)
            thread_list = []
            for ip in network.hosts():
                if self.stop_event.is_set():
                    logger.info("Scan stopped by user")
                    break
                    
                t = threading.Thread(
                    target=self._scan_ip, 
                    args=(str(ip), callback)
                )
                t.daemon = True
                thread_list.append(t)
                t.start()
                
                # Limit number of concurrent threads
                while threading.active_count() > 100:
                    time.sleep(0.01)
                    
            # Wait for all threads to complete (or timeout)
            scan_timeout = 20  # seconds
            start_wait = time.time()
            running_threads = [t for t in thread_list if t.is_alive()]
            
            while running_threads and time.time() - start_wait < scan_timeout:
                time.sleep(0.5)
                running_threads = [t for t in thread_list if t.is_alive()]
                
            if running_threads:
                logger.warning(f"{len(running_threads)} scanner threads did not complete")
            
            scan_time = time.time() - start_time
            logger.info(f"Scan completed in {scan_time:.2f} seconds. Found {len(self.devices)} devices")
            
        except Exception as e:
            logger.error(f"Error during network scan: {e}")
            
        finally:
            self.scanning = False
            
        return self.devices
            
    def stop_scan(self):
        """Stop an ongoing scan"""
        if self.scanning:
            logger.info("Stopping network scan")
            self.stop_event.set()
            self.scanning = False
    
    def _scan_ip(self, ip: str, callback: Optional[Callable] = None):
        """
        Scan a single IP address
        
        Args:
            ip: IP address to scan
            callback: Function to call if device is found
        """
        try:
            logger.debug(f"Scanning {ip}...")
            
            # Ping the device
            if not self._ping(ip):
                return
                
            # Get hostname
            try:
                hostname = socket.getfqdn(ip)
                if hostname == ip:  # getfqdn returns the IP if it can't resolve
                    hostname = "Unknown"
            except:
                hostname = "Unknown"
                
            # Get MAC address (platform dependent)
            mac_address = self._get_mac_address(ip)
            
            # Record timestamp
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Create device info
            device_info = {
                'ip': ip,
                'hostname': hostname,
                'mac': mac_address,
                'status': 'online',
                'last_seen': timestamp
            }
            
            # Add to devices dictionary
            with self.lock:
                self.devices[ip] = device_info
                
            # Call callback if provided
            if callback:
                callback(device_info)
                
            logger.debug(f"Device found: {ip} ({hostname})")
            
        except Exception as e:
            logger.debug(f"Error scanning {ip}: {e}")
    
    def _ping(self, ip: str) -> bool:
        """
        Ping an IP address to check if it's online
        
        Args:
            ip: IP address to ping
            
        Returns:
            True if ping was successful, False otherwise
        """
        # Platform-specific ping command
        if platform.system().lower() == "windows":
            command = ['ping', '-n', '1', '-w', '500', ip]
        else:
            command = ['ping', '-c', '1', '-W', '1', ip]
            
        try:
            result = subprocess.run(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=1
            )
            return result.returncode == 0
        except:
            return False
    
    def _get_mac_address(self, ip: str) -> str:
        """
        Get MAC address for an IP (platform dependent)
        
        Args:
            ip: IP address to get MAC for
            
        Returns:
            MAC address or empty string if not found
        """
        if platform.system().lower() == "windows":
            try:
                # Use ARP on Windows
                output = subprocess.check_output(f"arp -a {ip}", shell=True).decode('utf-8')
                lines = output.strip().split('\n')
                for line in lines:
                    if ip in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            mac = [p for p in parts if '-' in p or ':' in p]
                            if mac:
                                return mac[0]
            except:
                pass
        else:
            try:
                # Use ARP on Linux/Mac
                output = subprocess.check_output(f"arp -n {ip}", shell=True).decode('utf-8')
                lines = output.strip().split('\n')
                for line in lines[1:]:  # Skip header line
                    parts = line.split()
                    if len(parts) >= 3 and parts[0] == ip:
                        return parts[2]
            except:
                pass
                
        return "Unknown"
        
    def _get_local_ip(self) -> str:
        """
        Get the local IP address of this machine
        
        Returns:
            IP address as string or None if not found
        """
        try:
            # This gets a connection to an external host to determine local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            try:
                # Fallback: get hostname and resolve
                return socket.gethostbyname(socket.gethostname())
            except:
                return None