"""
FastScanService - Optimized network discovery techniques
Current Date: 2025-05-10 13:44:36
Author: AnoirELGUEDDAR
"""

import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import subprocess
import platform
import ipaddress
from PyQt5.QtCore import QObject, pyqtSignal, pyqtSlot

# Check if scapy is available - else provide fallback
try:
    from scapy.all import ARP, Ether, srp
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

class FastScanService(QObject):
    """Service for fast network device discovery"""
    
    # Signals for UI updates
    device_found = pyqtSignal(str, str, str)  # IP, MAC, hostname
    scan_progress = pyqtSignal(int, int)  # current, total
    scan_complete = pyqtSignal(list)  # list of found devices
    
    def __init__(self):
        super().__init__()
        self._running = False
        self._stop_requested = False
        self._devices = []
    
    @pyqtSlot(str)
    def start_fast_scan(self, ip_range):
        """Start a fast network scan using optimized techniques"""
        self._running = True
        self._stop_requested = False
        self._devices = []
        
        # Create a thread for the scan
        self._scan_thread = threading.Thread(
            target=self._run_fast_scan,
            args=(ip_range,)
        )
        self._scan_thread.daemon = True
        self._scan_thread.start()
    
    def stop_scan(self):
        """Stop an ongoing scan"""
        self._stop_requested = True
        
    def _run_fast_scan(self, ip_range):
        """Run the fast scan using multiple techniques"""
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            self._devices = []
            
            # METHOD 1: ARP SCAN (fastest for local network)
            if HAS_SCAPY and self._is_local_subnet(ip_range):
                arp_results = self._arp_scan(ip_range)
                if arp_results:
                    self._devices.extend(arp_results)
                    
            # METHOD 2: Broadcast ping (works on many networks)
            if not self._stop_requested:
                broadcast_found = self._broadcast_ping(ip_range)
                
                # Add unique devices from broadcast ping
                self._devices.extend([dev for dev in broadcast_found if dev['ip'] not in [d['ip'] for d in self._devices]])
            
            # METHOD 3: Parallel ping for remaining addresses
            if not self._stop_requested and len(self._devices) < len(list(network.hosts())):
                # Get IPs that weren't found yet
                found_ips = [d['ip'] for d in self._devices]
                remaining_ips = [str(ip) for ip in network.hosts() if str(ip) not in found_ips]
                
                # Scan common IP endings first (.1, .254, .100, etc.)
                remaining_ips = self._prioritize_common_ips(remaining_ips)
                
                # Only scan up to 50 IPs to keep it fast, focusing on common addresses
                limit = min(50, len(remaining_ips))
                remaining_ips = remaining_ips[:limit]
                
                # Do parallel ping with limited concurrency
                parallel_found = self._parallel_ping(remaining_ips, max_workers=20)
                self._devices.extend(parallel_found)
            
            if not self._stop_requested:
                self.scan_complete.emit(self._devices)
            
            self._running = False
            
        except Exception as e:
            print(f"Fast scan error: {e}")
            self._running = False
            self.scan_complete.emit(self._devices)
    
    def _is_local_subnet(self, ip_range):
        """Check if the range is on the local subnet"""
        try:
            # Get local IP address
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Connect to any external address to get our local address
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            # Get subnet from range
            subnet = ipaddress.ip_network(ip_range, strict=False)
            
            # Check if local IP is in subnet
            return ipaddress.ip_address(local_ip) in subnet
        except:
            # Fallback method if the above fails
            try:
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                subnet = ipaddress.ip_network(ip_range, strict=False)
                return ipaddress.ip_address(local_ip) in subnet
            except:
                return False
    
    def _arp_scan(self, ip_range):
        """Perform an ARP scan (fastest method, but local subnet only)"""
        if not HAS_SCAPY:
            return []
            
        try:
            devices = []
            
            # Create ARP packet
            arp = ARP(pdst=ip_range)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            
            # Send packet and get response
            result = srp(packet, timeout=2, verbose=0)[0]
            
            total = len(result)
            for i, (sent, received) in enumerate(result):
                if self._stop_requested:
                    break
                    
                ip = received.psrc
                mac = received.hwsrc
                
                # Try to get hostname
                try:
                    hostname = socket.getfqdn(ip)
                    if hostname == ip:  # No hostname resolution
                        hostname = ""
                except:
                    hostname = ""
                
                devices.append({
                    'ip': ip,
                    'mac': mac,
                    'hostname': hostname
                })
                
                # Signal update
                self.device_found.emit(ip, mac, hostname)
                self.scan_progress.emit(i+1, total)
            
            return devices
        except Exception as e:
            print(f"ARP scan error: {e}")
            return []
    
    def _broadcast_ping(self, ip_range):
        """Send a broadcast ping to discover devices quickly"""
        devices = []
        try:
            # Get broadcast address
            subnet = ipaddress.ip_network(ip_range, strict=False)
            broadcast = str(subnet.broadcast_address)
            
            if platform.system() == "Windows":
                # Windows doesn't support broadcast ping directly, use subnet-directed broadcast
                ping_args = ["ping", "-n", "1", "-w", "1000", broadcast]
                # Also ping common network IPs
                gateway_ip = str(list(subnet.hosts())[0])  # Usually .1
                subprocess.run(["ping", "-n", "1", "-w", "1000", gateway_ip], 
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                # Linux/Mac can use broadcast ping
                ping_args = ["ping", "-c", "1", "-b", "-W", "1", broadcast]
            
            subprocess.run(ping_args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Wait briefly for ARP cache to populate
            time.sleep(1)
            
            # Read ARP cache
            if platform.system() == "Windows":
                arp_output = subprocess.check_output(["arp", "-a"]).decode("utf-8", errors="ignore")
                for line in arp_output.splitlines():
                    if "dynamic" in line.lower():
                        parts = line.split()
                        if len(parts) >= 2:
                            ip = parts[0]
                            mac = parts[1]
                            # Check if IP is in our subnet
                            try:
                                if ipaddress.ip_address(ip) in subnet:
                                    hostname = ""
                                    try:
                                        hostname = socket.getfqdn(ip)
                                        if hostname == ip:
                                            hostname = ""
                                    except:
                                        pass
                                    
                                    devices.append({
                                        'ip': ip, 
                                        'mac': mac,
                                        'hostname': hostname
                                    })
                                    self.device_found.emit(ip, mac, hostname)
                            except:
                                pass  # Skip invalid IPs
            else:
                # Linux/Mac
                arp_output = subprocess.check_output(["arp", "-n"]).decode("utf-8", errors="ignore")
                for line in arp_output.splitlines():
                    if not line.startswith("Address"):
                        parts = line.split()
                        if len(parts) >= 3:
                            ip = parts[0]
                            mac = parts[2]
                            if mac != "00:00:00:00:00:00" and mac != "<incomplete>":
                                try:
                                    # Check if IP is in our subnet
                                    if ipaddress.ip_address(ip) in subnet:
                                        hostname = ""
                                        try:
                                            hostname = socket.getfqdn(ip)
                                            if hostname == ip:
                                                hostname = ""
                                        except:
                                            pass
                                        
                                        devices.append({
                                            'ip': ip, 
                                            'mac': mac,
                                            'hostname': hostname
                                        })
                                        self.device_found.emit(ip, mac, hostname)
                                except:
                                    pass
            
            self.scan_progress.emit(len(devices), len(devices) * 2)  # Rough progress estimate
            return devices
        except Exception as e:
            print(f"Broadcast ping error: {e}")
            return []
    
    def _parallel_ping(self, ip_list, max_workers=20):
        """Ping multiple IPs in parallel"""
        devices = []
        total = len(ip_list)
        processed = 0
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Create future for each IP
            future_to_ip = {executor.submit(self._ping_host, ip): ip for ip in ip_list}
            
            # Process results as they complete
            for future in future_to_ip:
                if self._stop_requested:
                    break
                
                result = future.result()
                processed += 1
                self.scan_progress.emit(processed, total)
                
                if result:
                    devices.append(result)
                    self.device_found.emit(result['ip'], result['mac'], result['hostname'])
        
        return devices
    
    def _ping_host(self, ip):
        """Ping a single host and return its information if available"""
        try:
            if platform.system() == "Windows":
                ping_args = ["ping", "-n", "1", "-w", "500", ip]
            else:
                ping_args = ["ping", "-c", "1", "-W", "1", ip]
                
            result = subprocess.run(ping_args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Check if ping was successful
            if result.returncode == 0:
                # Try to get MAC address
                mac = self._get_mac_address(ip)
                
                # Try to get hostname
                try:
                    hostname = socket.getfqdn(ip)
                    if hostname == ip:  # No hostname resolution
                        hostname = ""
                except:
                    hostname = ""
                
                return {
                    'ip': ip,
                    'mac': mac,
                    'hostname': hostname
                }
            
            return None
        except:
            return None
    
    def _get_mac_address(self, ip):
        """Get MAC address for an IP using ARP"""
        try:
            if platform.system() == "Windows":
                arp_output = subprocess.check_output(["arp", "-a", ip]).decode("utf-8", errors="ignore")
                for line in arp_output.splitlines():
                    if ip in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            return parts[1]
            else:
                # Linux/Mac
                arp_output = subprocess.check_output(["arp", "-n", ip]).decode("utf-8", errors="ignore")
                for line in arp_output.splitlines():
                    if ip in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            return parts[2]
            
            return ""
        except:
            return ""
    
    def _prioritize_common_ips(self, ip_list):
        """Sort IP list to check common IP addresses first"""
        common_endings = ['1', '100', '254', '253', '250', '200', '150', '2', '10']
        
        # Function to get ending number
        def get_ending(ip):
            return ip.split('.')[-1]
        
        # Sort by common endings first
        sorted_ips = sorted(ip_list, key=lambda ip: (
            0 if get_ending(ip) in common_endings else 1,
            common_endings.index(get_ending(ip)) if get_ending(ip) in common_endings else 999,
            int(get_ending(ip))
        ))
        
        return sorted_ips