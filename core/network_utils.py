"""
Network utility functions for Network Scanner application.
Provides functions for retrieving network interface information.
"""

import socket
import platform
import subprocess
from typing import Dict, List, Optional, Tuple

def get_network_interfaces() -> Dict[str, str]:
    """
    Get a dictionary of network interfaces with their IP addresses.
    
    Returns:
        Dictionary mapping interface names to their IPv4 addresses
    """
    interfaces = {}
    
    try:
        # Simplified approach without netifaces
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        interfaces["default"] = ip
        
        # On Windows, try to get more interfaces
        if platform.system() == "Windows":
            try:
                # Use ipconfig to get more interface info
                result = subprocess.run(
                    ["ipconfig"], 
                    capture_output=True, 
                    text=True, 
                    check=True
                )
                
                current_if = None
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    
                    # Look for adapter names
                    if line and line.endswith(':') and not line.startswith('   '):
                        current_if = line[:-1]
                    
                    # Look for IPv4 addresses
                    elif current_if and 'IPv4 Address' in line:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            ip_addr = parts[1].strip()
                            # Remove potential trailing parentheses
                            if '(' in ip_addr:
                                ip_addr = ip_addr[:ip_addr.find('(')].strip()
                            interfaces[current_if] = ip_addr
            except:
                # If that fails, we still have the default
                pass
    except:
        interfaces["localhost"] = "127.0.0.1"
    
    # If no interfaces found, add loopback
    if not interfaces:
        interfaces["lo"] = "127.0.0.1"
        
    return interfaces

def get_local_ip() -> str:
    """
    Get the local IP address of this machine.
    
    Returns:
        String containing the primary local IPv4 address
    """
    try:
        # Create a socket to connect to an external server
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # Google's DNS server
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        # Fallback if that doesn't work
        try:
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            return ip
        except:
            pass
    
    # If all else fails
    return "127.0.0.1"

def get_network_from_ip(ip: str) -> str:
    """
    Get the network address for the IP with a /24 subnet.
    
    Args:
        ip: IP address string
        
    Returns:
        Network address string with /24 subnet
    """
    try:
        # Parse the IP and create a network with /24 prefix
        parts = ip.split('.')
        if len(parts) == 4:
            network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            return network
    except:
        pass
        
    # Return a default if parsing fails
    return "192.168.1.0/24"

def ping(host: str, count: int = 1) -> bool:
    """
    Check if a host is reachable via ping.
    
    Args:
        host: IP address or hostname to ping
        count: Number of ping packets to send
        
    Returns:
        True if host responds to ping, False otherwise
    """
    # Platform-specific ping command
    if platform.system().lower() == "windows":
        ping_cmd = ["ping", "-n", str(count), "-w", "1000", host]
    else:
        ping_cmd = ["ping", "-c", str(count), "-W", "1", host]
    
    try:
        # Run the ping command
        subprocess.run(
            ping_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
            check=True
        )
        return True
    except (subprocess.SubprocessError, subprocess.TimeoutExpired):
        return False

def get_subnet_prefix() -> int:
    """
    Get the subnet prefix for the local network.
    Default is 24 (/24 or 255.255.255.0).
    
    Returns:
        Integer subnet prefix (e.g., 24 for /24)
    """
    # Without netifaces, we'll default to /24
    return 24