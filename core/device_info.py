"""
Module for gathering detailed information about devices on the network.
"""

import socket
import subprocess
import platform
import re
from typing import Dict, Any, Optional
import netifaces
import psutil

from utils.logger import get_logger

logger = get_logger(__name__)


class DeviceInfoGatherer:
    """Class for gathering device information."""
    
    @staticmethod
    def get_local_info() -> Dict[str, Any]:
        """
        Get information about the local device.
        
        Returns:
            Dictionary containing device information
        """
        info = {
            'hostname': socket.gethostname(),
            'ip_addresses': {},
            'mac_addresses': {},
            'os': {
                'system': platform.system(),
                'release': platform.release(),
                'version': platform.version()
            },
            'cpu': {
                'cores': psutil.cpu_count(logical=False),
                'threads': psutil.cpu_count(logical=True),
                'usage': psutil.cpu_percent()
            },
            'memory': {
                'total': psutil.virtual_memory().total,
                'available': psutil.virtual_memory().available,
                'used': psutil.virtual_memory().used,
                'percent': psutil.virtual_memory().percent
            },
            'disk': {}
        }
        
        # Get network interfaces
        interfaces = netifaces.interfaces()
        for interface in interfaces:
            addrs = netifaces.ifaddresses(interface)
            
            # Get IPv4 addresses
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    info['ip_addresses'][interface] = addr['addr']
            
            # Get MAC addresses
            if netifaces.AF_LINK in addrs:
                for addr in addrs[netifaces.AF_LINK]:
                    info['mac_addresses'][interface] = addr['addr']
        
        # Get disk information
        for part in psutil.disk_partitions(all=False):
            if platform.system() == 'Windows' or part.fstype:
                usage = psutil.disk_usage(part.mountpoint)
                info['disk'][part.mountpoint] = {
                    'total': usage.total,
                    'used': usage.used,
                    'free': usage.free,
                    'percent': usage.percent,
                    'fstype': part.fstype
                }
        
        return info
    
    @staticmethod
    def get_remote_info(ip: str, timeout: int = 2) -> Dict[str, Any]:
        """
        Get information about a remote device using various methods.
        
        Args:
            ip: IP address of the remote device
            timeout: Timeout in seconds for network operations
            
        Returns:
            Dictionary containing device information
        """
        info = {
            'ip': ip,
            'hostname': 'Unknown',
            'mac': 'Unknown',
            'os': 'Unknown',
            'open_ports': [],
            'status': 'Unknown'
        }
        
        # Try to get hostname
        try:
            info['hostname'] = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.timeout):
            pass
        
        # Check if host is up using ping
        ping_result = DeviceInfoGatherer.ping(ip, count=1, timeout=timeout)
        info['status'] = 'up' if ping_result['success'] else 'down'
        
        if info['status'] == 'up':
            # Try to get OS info using nmap OS detection
            try:
                # This is a simplified approach. For production, use python-nmap library
                os_result = subprocess.run(['nmap', '-O', ip], 
                                         capture_output=True, text=True, timeout=timeout*3)
                
                # Parse OS info from output
                os_match = re.search(r'OS details: (.*)', os_result.stdout)
                if os_match:
                    info['os'] = os_match.group(1)
            except (subprocess.SubprocessError, FileNotFoundError):
                pass
            
            # Try to get MAC address using arp
            try:
                if platform.system() == 'Windows':
                    arp_result = subprocess.run(['arp', '-a', ip],
                                             capture_output=True, text=True, timeout=timeout)
                    mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', arp_result.stdout)
                    if mac_match:
                        info['mac'] = mac_match.group(0)
                else:  # Linux/Mac
                    arp_result = subprocess.run(['arp', '-n', ip],
                                             capture_output=True, text=True, timeout=timeout)
                    mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', arp_result.stdout)
                    if mac_match:
                        info['mac'] = mac_match.group(0)
            except (subprocess.SubprocessError, FileNotFoundError):
                pass
            
            # Scan common ports
            common_ports = [22, 80, 443, 3389, 445, 139]
            for port in common_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    info['open_ports'].append(port)
                sock.close()
        
        return info
    
    @staticmethod
    def ping(ip: str, count: int = 4, timeout: int = 2) -> Dict[str, Any]:
        """
        Ping a host and return results.
        
        Args:
            ip: IP address to ping
            count: Number of pings to send
            timeout: Timeout in seconds
            
        Returns:
            Dictionary containing ping results
        """
        result = {
            'success': False,
            'min_rtt': None,
            'avg_rtt': None,
            'max_rtt': None,
            'packet_loss': 100.0,
            'error': None
        }
        
        try:
            if platform.system().lower() == 'windows':
                args = ['ping', '-n', str(count), '-w', str(timeout * 1000), ip]
            else:  # Linux/Mac
                args = ['ping', '-c', str(count), '-W', str(timeout), ip]
            
            ping_result = subprocess.run(args, 
                                       capture_output=True, text=True, timeout=timeout * count + 5)
            
            if ping_result.returncode == 0:
                result['success'] = True
                
                # Parse RTT values
                if platform.system().lower() == 'windows':
                    rtt_match = re.search(
                        r'Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms',
                        ping_result.stdout
                    )
                    if rtt_match:
                        result['min_rtt'] = float(rtt_match.group(1))
                        result['max_rtt'] = float(rtt_match.group(2))
                        result['avg_rtt'] = float(rtt_match.group(3))
                else:  # Linux/Mac
                    rtt_match = re.search(
                        r'min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)',
                        ping_result.stdout
                    )
                    if rtt_match:
                        result['min_rtt'] = float(rtt_match.group(1))
                        result['avg_rtt'] = float(rtt_match.group(2))
                        result['max_rtt'] = float(rtt_match.group(3))
                
                # Parse packet loss
                loss_match = re.search(r'(\d+)%\spacket loss', ping_result.stdout)
                if loss_match:
                    result['packet_loss'] = float(loss_match.group(1))
            
        except subprocess.SubprocessError as e:
            result['error'] = str(e)
        
        return result


if __name__ == "__main__":
    # Example usage
    gatherer = DeviceInfoGatherer()
    
    # Get local info
    print("Local device information:")
    local_info = gatherer.get_local_info()
    print(f"Hostname: {local_info['hostname']}")
    print(f"IP addresses: {local_info['ip_addresses']}")
    print(f"OS: {local_info['os']['system']} {local_info['os']['release']}")
    print(f"CPU cores: {local_info['cpu']['cores']}")
    print(f"Memory: {local_info['memory']['total'] / (1024*1024*1024):.1f} GB")
    
    # Ping example
    ip_to_test = "8.8.8.8"  # Google's DNS
    print(f"\nPinging {ip_to_test}...")
    ping_result = gatherer.ping(ip_to_test)
    if ping_result['success']:
        print(f"Successful ping! Avg RTT: {ping_result['avg_rtt']} ms")
    else:
        print(f"Ping failed: {ping_result['error']}")
    
    # Get remote info example
    print(f"\nGathering information about {ip_to_test}...")
    remote_info = gatherer.get_remote_info(ip_to_test)
    print(f"Hostname: {remote_info['hostname']}")
    print(f"Status: {remote_info['status']}")
    print(f"OS: {remote_info['os']}")
    print(f"Open ports: {remote_info['open_ports']}")