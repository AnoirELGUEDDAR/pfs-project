"""
Network utility functions
"""
import socket
import logging
import subprocess
import platform
import re

logger = logging.getLogger(__name__)

def get_local_ip():
    """
    Get the local IP address
    
    Returns:
        IP address as string or '127.0.0.1' if not found
    """
    try:
        # Create a socket and connect to an external server
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            # Fallback: get hostname and resolve
            hostname = socket.gethostname()
            return socket.gethostbyname(hostname)
        except Exception as e:
            logger.error(f"Could not determine local IP: {e}")
            return '127.0.0.1'

def get_default_gateway():
    """
    Get the default gateway
    
    Returns:
        Gateway IP as string or None if not found
    """
    if platform.system().lower() == "windows":
        try:
            # Use route print on Windows
            output = subprocess.check_output("route print 0.0.0.0", shell=True).decode('utf-8')
            lines = output.strip().split('\n')
            for line in lines:
                if '0.0.0.0' in line:
                    parts = line.strip().split()
                    for part in parts:
                        if re.match(r'\d+\.\d+\.\d+\.\d+', part):
                            return part
        except Exception as e:
            logger.error(f"Error getting default gateway on Windows: {e}")
    else:
        try:
            # Use ip route on Linux
            output = subprocess.check_output("ip route show default", shell=True).decode('utf-8')
            match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', output)
            if match:
                return match.group(1)
        except Exception as e:
            logger.error(f"Error getting default gateway on Linux: {e}")
    
    return None

def get_subnet_mask(ip=None):
    """
    Get the subnet mask for an IP address
    
    Args:
        ip: IP address to get subnet for. If None, uses local IP
        
    Returns:
        Subnet mask as string or '255.255.255.0' as default
    """
    if not ip:
        ip = get_local_ip()
        
    if platform.system().lower() == "windows":
        try:
            # Use ipconfig on Windows
            output = subprocess.check_output("ipconfig", shell=True).decode('utf-8')
            lines = output.strip().split('\n')
            found_ip = False
            for line in lines:
                if ip in line:
                    found_ip = True
                if found_ip and "Subnet Mask" in line:
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)$', line.strip())
                    if match:
                        return match.group(1)
        except Exception as e:
            logger.error(f"Error getting subnet mask on Windows: {e}")
    else:
        try:
            # Use ifconfig on Linux/Mac
            output = subprocess.check_output(f"ifconfig | grep -A1 {ip}", shell=True).decode('utf-8')
            match = re.search(r'netmask (\d+\.\d+\.\d+\.\d+)', output)
            if match:
                return match.group(1)
        except Exception as e:
            logger.error(f"Error getting subnet mask on Linux: {e}")
    
    return '255.255.255.0'  # Default

def ping(ip, timeout=1):
    """
    Ping an IP address
    
    Args:
        ip: IP address to ping
        timeout: Timeout in seconds
        
    Returns:
        True if ping successful, False otherwise
    """
    try:
        # Platform specific ping command
        if platform.system().lower() == "windows":
            command = ['ping', '-n', '1', '-w', str(timeout * 1000), ip]
        else:
            command = ['ping', '-c', '1', '-W', str(timeout), ip]
            
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 0.5
        )
        return result.returncode == 0
    except Exception:
        return False

def get_hostname(ip):
    """
    Get hostname for an IP address
    
    Args:
        ip: IP address to get hostname for
        
    Returns:
        Hostname as string or 'Unknown' if not resolved
    """
    try:
        hostname = socket.getfqdn(ip)
        if hostname == ip:  # getfqdn returns the IP if it can't resolve
            return "Unknown"
        return hostname
    except Exception:
        return "Unknown"