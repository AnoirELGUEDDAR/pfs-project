"""
Port scanner module for scanning network ports
"""
import socket
import logging
import threading
import time
from typing import List, Dict, Tuple, Callable, Optional

from config.constants import COMMON_PORTS

logger = logging.getLogger(__name__)

class PortScanner:
    """
    Scanner for checking open ports on network devices
    """
    
    def __init__(self):
        self.scanning = False
        self.threads = []
        self.open_ports = {}
        self.lock = threading.Lock()
        self.timeout = 1.0  # default timeout in seconds
        
    def scan_ports(self, 
                  target_ip: str, 
                  ports: List[int] = None, 
                  timeout: float = 1.0, 
                  max_threads: int = 100,
                  callback: Optional[Callable] = None) -> Dict[int, Dict]:
        """
        Scan ports on a target IP address
        
        Args:
            target_ip: IP address to scan
            ports: List of ports to scan. If None, scans common ports
            timeout: Socket timeout in seconds
            max_threads: Maximum number of concurrent scanning threads
            callback: Optional callback function for port results
            
        Returns:
            Dictionary of open ports with service information
        """
        if self.scanning:
            logger.warning("Port scan already in progress")
            return {}
            
        self.scanning = True
        self.open_ports = {}
        self.timeout = timeout
        
        # Use common ports if none specified
        if ports is None:
            # If COMMON_PORTS isn't defined in constants yet, use these defaults
            try:
                ports = list(COMMON_PORTS.keys())
            except (NameError, AttributeError):
                ports = [21, 22, 23, 25, 53, 80, 443, 445, 3389, 8080]
        
        logger.info(f"Starting port scan for {target_ip} ({len(ports)} ports)")
        start_time = time.time()
        
        try:
            # Create thread pool
            thread_pool = []
            port_chunks = self._chunk_list(ports, max_threads)
            
            for chunk in port_chunks:
                if not self.scanning:
                    break
                    
                # Create and start threads for this chunk
                for port in chunk:
                    if not self.scanning:
                        break
                        
                    t = threading.Thread(
                        target=self._scan_port, 
                        args=(target_ip, port, callback)
                    )
                    t.daemon = True
                    thread_pool.append(t)
                    t.start()
                
                # Wait for all threads in this chunk to complete
                for t in thread_pool:
                    t.join(self.timeout * 2)
                
                thread_pool = []
        
        except Exception as e:
            logger.error(f"Error during port scan: {e}")
        finally:
            self.scanning = False
            
        scan_time = time.time() - start_time
        logger.info(f"Port scan completed in {scan_time:.2f} seconds. Found {len(self.open_ports)} open ports")
        
        return self.open_ports
    
    def _scan_port(self, ip: str, port: int, callback: Optional[Callable]) -> None:
        """
        Scan a single port
        
        Args:
            ip: IP address to scan
            port: Port number to scan
            callback: Callback function for port results
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            result = sock.connect_ex((ip, port))
            service_info = {"port": port, "state": "closed", "service": "unknown"}
            
            if result == 0:
                # Port is open
                service_name = self._get_service_name(port)
                service_info = {
                    "port": port,
                    "state": "open",
                    "service": service_name,
                    "banner": self._get_banner(sock, port)
                }
                
                # Store the result
                with self.lock:
                    self.open_ports[port] = service_info
                    
                # Notify through callback
                if callback:
                    callback(port, service_info)
                
                logger.debug(f"Port {port} is open ({service_name})")
            
            sock.close()
            
        except Exception as e:
            logger.debug(f"Error scanning port {port}: {e}")
    
    def _get_banner(self, sock: socket.socket, port: int) -> str:
        """
        Try to get service banner
        
        Args:
            sock: Connected socket
            port: Port number
            
        Returns:
            Banner string or empty string if not available
        """
        banner = ""
        try:
            # For some common services, send an appropriate request
            if port == 80 or port == 8080:
                sock.send(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            elif port == 21 or port == 22 or port == 25 or port == 110:
                pass  # These services typically send a banner automatically
                
            # Set a short timeout for banner grabbing
            sock.settimeout(1.0)
            
            # Try to receive banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        except Exception:
            pass
            
        return banner
        
    def _get_service_name(self, port: int) -> str:
        """Get service name for a port number"""
        common_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            115: "SFTP",
            135: "MSRPC",
            137: "NetBIOS-NS",
            138: "NetBIOS-DGM",
            139: "NetBIOS-SSN",
            143: "IMAP",
            161: "SNMP",
            443: "HTTPS",
            445: "SMB",
            587: "SMTP-TLS",
            631: "IPP",
            993: "IMAPS",
            995: "POP3S",
            1433: "MSSQL",
            1434: "MSSQL-Browser",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            5985: "WinRM-HTTP",
            5986: "WinRM-HTTPS",
            6379: "Redis",
            8080: "HTTP-Proxy",
            8443: "HTTPS-Alt"
        }
        
        return common_ports.get(port, "unknown")
    
    def stop_scan(self) -> None:
        """Stop any ongoing scan"""
        self.scanning = False
    
    def _chunk_list(self, lst: List, chunk_size: int) -> List[List]:
        """
        Split a list into chunks
        
        Args:
            lst: List to split
            chunk_size: Maximum size of each chunk
            
        Returns:
            List of list chunks
        """
        for i in range(0, len(lst), chunk_size):
            yield lst[i:i + chunk_size]