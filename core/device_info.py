"""
Module for gathering detailed information about devices on the network.
Current Date: 2025-06-09 22:12:58
Author: AnoirELGUEDDAR
"""

import socket
import subprocess
import platform
import re
import os
import threading
import time
from typing import Dict, Any, Optional, List, Tuple, Set

# Create a simple logger
import logging
logger = logging.getLogger(__name__)

class DeviceInfoGatherer:
    """Class for gathering device information."""
    
    # Caches pour améliorer les performances
    _os_cache = {}
    _os_cache_lock = threading.Lock()
    _hostname_cache = {}

    @staticmethod
    def _get_local_mac_addresses() -> Dict[str, str]:
        """
        Gets local MAC addresses by parsing system command output.
        Méthode améliorée pour obtenir l'adresse MAC locale.
        """
        mac_addresses = {}
        system = platform.system().lower()
        
        try:
            if system == 'windows':
                # Méthode améliorée pour Windows
                output = subprocess.check_output(['ipconfig', '/all'], text=True, errors='ignore')
                
                # Trouver l'interface active
                active_interface = None
                for line in output.split('\n'):
                    if "Default Gateway" in line and not line.endswith(': '):
                        active_interface = True
                    elif active_interface and "Physical Address" in line:
                        mac = line.split(':')[1].strip().replace('-', ':').upper()
                        mac_addresses["DefaultInterface"] = mac
                        active_interface = False
                
                # Traiter aussi toutes les interfaces
                adapter_blocks = re.split(r'\n\s*\n', output)
                for block in adapter_blocks:
                    adapter_name_match = re.search(r'Ethernet adapter ([^:]+):', block)
                    if not adapter_name_match:
                        adapter_name_match = re.search(r'Wireless LAN adapter ([^:]+):', block)
                        
                    if adapter_name_match:
                        adapter_name = adapter_name_match.group(1).strip()
                        mac_match = re.search(r'Physical Address[^:]*:\s*([0-9A-Fa-f-]+)', block)
                        ip_match = re.search(r'IPv4 Address[^:]*:\s*([0-9\.]+)', block)
                        
                        if mac_match and ip_match:  # Seulement ajouter les interfaces avec IP et MAC
                            mac = mac_match.group(1).strip().replace('-', ':').upper()
                            mac_addresses[adapter_name] = mac
            else:
                # Méthode améliorée pour Linux/Mac
                try:
                    # Essayer d'abord de trouver l'interface principale
                    route_output = subprocess.check_output(['ip', 'route', 'get', '8.8.8.8'], 
                                                         text=True, errors='ignore')
                    dev_match = re.search(r'dev\s+(\S+)', route_output)
                    if dev_match:
                        main_interface = dev_match.group(1)
                        
                        # Obtenir l'adresse MAC de cette interface
                        addr_output = subprocess.check_output(['ip', 'link', 'show', main_interface], 
                                                            text=True, errors='ignore')
                        mac_match = re.search(r'link/ether\s+([0-9a-fA-F:]{17})', addr_output)
                        if mac_match:
                            mac_addresses["DefaultInterface"] = mac_match.group(1).upper()
                except:
                    pass
                
                # Obtenir toutes les interfaces
                try:
                    output = subprocess.check_output(['ip', 'addr'], text=True, errors='ignore')
                    interfaces = re.finditer(r'^\d+:\s+(\S+):', output, re.MULTILINE)
                    
                    for match in interfaces:
                        interface_name = match.group(1)
                        if interface_name != 'lo':  # Ignorer l'interface loopback
                            # Trouver l'adresse MAC pour cette interface
                            mac_match = re.search(
                                rf'{interface_name}.*?link/ether\s+([0-9a-fA-F:]+)', 
                                output, re.DOTALL
                            )
                            if mac_match:
                                mac_addresses[interface_name] = mac_match.group(1).upper()
                except:
                    # Essayer ifconfig si ip n'est pas disponible
                    try:
                        output = subprocess.check_output(['ifconfig'], text=True, errors='ignore')
                        interfaces = re.split(r'\n(?=\S)', output)
                        
                        for interface in interfaces:
                            name_match = re.search(r'^(\S+):', interface)
                            mac_match = re.search(r'ether\s+([0-9a-fA-F:]+)', interface)
                            
                            if name_match and mac_match and name_match.group(1) != 'lo':
                                mac_addresses[name_match.group(1)] = mac_match.group(1).upper()
                    except:
                        pass
        except Exception as e:
            logger.error(f"Error getting local MAC addresses: {e}")
        
        return mac_addresses

    @staticmethod
    def get_local_info() -> Dict[str, Any]:
        """
        Get information about the local device, including local MAC addresses.
        """
        info = {
            'hostname': socket.gethostname(),
            'ip_addresses': {},
            'mac_addresses': DeviceInfoGatherer._get_local_mac_addresses(),
            'os': {
                'system': platform.system(),
                'release': platform.release(),
                'version': platform.version()
            },
            'cpu': {'cores': 1, 'threads': 1, 'usage': 0},
            'memory': {'total': 0, 'available': 0, 'used': 0, 'percent': 0},
            'disk': {}
        }
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                info['ip_addresses']['default'] = s.getsockname()[0]
        except OSError:
            info['ip_addresses']['default'] = '127.0.0.1'
        
        if platform.system() == 'Windows':
            for drive in range(ord('A'), ord('Z')+1):
                drive_letter = chr(drive) + ":\\"
                if os.path.exists(drive_letter):
                    try:
                        total, used, free = DeviceInfoGatherer._get_disk_usage_windows(drive_letter)
                        if total > 0:  # Only add if it's a real drive
                            info['disk'][drive_letter] = {
                                'total': total,
                                'used': used,
                                'free': free,
                                'percent': (used / total) * 100 if total > 0 else 0,
                                'fstype': 'NTFS'  # Assumption for Windows
                            }
                    except:
                        pass
        else:
            # Basic check for root filesystem on Unix-like systems
            try:
                total, used, free = DeviceInfoGatherer._get_disk_usage_unix('/')
                info['disk']['/'] = {
                    'total': total,
                    'used': used,
                    'free': free,
                    'percent': (used / total) * 100 if total > 0 else 0,
                    'fstype': 'ext4'  # Common assumption for Linux
                }
            except:
                pass
        
        return info
    
    @staticmethod
    def _get_disk_usage_windows(path):
        """Get disk usage on Windows without psutil"""
        try:
            # Use Windows command line tools
            output = subprocess.check_output(['wmic', 'logicaldisk', 'get', 'size,freespace,caption'], 
                                           text=True)
            for line in output.strip().split('\n')[1:]:  # Skip header
                parts = line.split()
                if len(parts) >= 3 and parts[0].rstrip(':') == path.rstrip('\\').rstrip(':'):
                    free = int(parts[1])
                    total = int(parts[2])
                    used = total - free
                    return total, used, free
            return 0, 0, 0
        except:
            return 0, 0, 0
    
    @staticmethod
    def _get_disk_usage_unix(path):
        """Get disk usage on Unix-like systems without psutil"""
        try:
            output = subprocess.check_output(['df', '-k', path], text=True)
            lines = output.strip().split('\n')
            if len(lines) >= 2:
                parts = lines[1].split()
                if len(parts) >= 4:
                    total = int(parts[1]) * 1024  # Convert from KB to bytes
                    used = int(parts[2]) * 1024
                    free = int(parts[3]) * 1024
                    return total, used, free
            return 0, 0, 0
        except:
            return 0, 0, 0
    
    @staticmethod
    def get_mac_address(ip: str, timeout: int = 2) -> str:
        """
        Récupération d'adresses MAC avec plusieurs méthodes.
        Amélioration avec plus de tentatives et meilleure gestion des erreurs.
        
        Args:
            ip: Adresse IP de l'appareil
            timeout: Délai d'attente en secondes
            
        Returns:
            Adresse MAC ou "Unknown" si non trouvée
        """
        # Essayer d'abord avec le cache ARP existant
        try:
            if platform.system().lower() == 'windows':
                arp_result = subprocess.run(['arp', '-a'], capture_output=True, 
                                          text=True, timeout=timeout, errors='ignore')
                
                # Rechercher l'IP spécifique dans la sortie complète
                ip_pattern = re.escape(ip)
                arp_entry = re.search(rf'{ip_pattern}\s+([0-9a-fA-F-]+)', arp_result.stdout)
                if arp_entry:
                    mac = arp_entry.group(1).replace('-', ':').upper()
                    return mac
            else:  # Linux/Mac
                arp_result = subprocess.run(['arp', '-n'], capture_output=True, 
                                          text=True, timeout=timeout, errors='ignore')
                ip_pattern = re.escape(ip)
                arp_entry = re.search(rf'{ip_pattern}\s+\S+\s+\S+\s+([0-9a-fA-F:]+)', arp_result.stdout)
                if arp_entry:
                    return arp_entry.group(1).upper()
        except:
            pass
        
        # Sinon, ping puis réessayer ARP de façon ciblée
        try:
            # Ping pour forcer l'entrée ARP
            DeviceInfoGatherer.ping(ip, count=1, timeout=timeout)
            
            # Attendre un court instant pour que l'entrée ARP soit créée
            time.sleep(0.5)
            
            if platform.system().lower() == 'windows':
                arp_result = subprocess.run(['arp', '-a', ip], capture_output=True, 
                                          text=True, timeout=timeout, errors='ignore')
                mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', arp_result.stdout)
                if mac_match:
                    return mac_match.group(0).upper()
            else:  # Linux/Mac
                arp_result = subprocess.run(['arp', '-n', ip], capture_output=True, 
                                          text=True, timeout=timeout, errors='ignore')
                mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', arp_result.stdout)
                if mac_match:
                    return mac_match.group(0).upper()
        except:
            pass
            
        # Dernière tentative avec commande plus générique
        try:
            if platform.system().lower() == 'windows':
                # Utiliser getmac pour Windows
                getmac_result = subprocess.run(['getmac', '/NH', '/V'], capture_output=True, 
                                             text=True, timeout=timeout, errors='ignore')
                for line in getmac_result.stdout.splitlines():
                    if ip in line:
                        mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', line)
                        if mac_match:
                            return mac_match.group(0).upper()
            else:
                # Tenter avec ip neigh pour Linux
                ip_neigh = subprocess.run(['ip', 'neigh', 'show', ip], capture_output=True, 
                                        text=True, timeout=timeout, errors='ignore')
                mac_match = re.search(r'([0-9a-f]{2}:){5}[0-9a-f]{2}', ip_neigh.stdout)
                if mac_match:
                    return mac_match.group(0).upper()
        except:
            pass
            
        # Si aucune méthode ne fonctionne
        return "Unknown"
    
    @staticmethod
    def _get_netbios_name(ip: str, timeout: int = 2) -> Optional[str]:
        """
        Tries to get the NetBIOS name of a device.
        Amélioration avec meilleure gestion des erreurs et timeout plus long.
        """
        try:
            # Construction du paquet NetBIOS Name Service Request
            query = (os.urandom(2) +  # Transaction ID
                     b'\x01\x00' +     # Flags: Standard query
                     b'\x00\x01' +     # Questions: 1
                     b'\x00\x00' +     # Answer RRs: 0
                     b'\x00\x00' +     # Authority RRs: 0
                     b'\x00\x00' +     # Additional RRs: 0
                     b'\x20' +         # Name length: 32 bytes
                     b'CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +  # Encoded name
                     b'\x00' +         # Terminator
                     b'\x00\x21' +     # Type: NBSTAT
                     b'\x00\x01')      # Class: IN
            
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(query, (ip, 137))
                data, _ = s.recvfrom(1024)
                
                if len(data) > 57:
                    # Traiter la réponse
                    num_names = data[56]
                    offset = 57
                    
                    for i in range(num_names):
                        if offset + 15 < len(data):
                            name = data[offset:offset+15].strip(b'\x00').decode('ascii', errors='ignore')
                            flags = data[offset+15]
                            
                            # Flags 0x04 = Workstation, 0x20 = Server
                            if flags & 0x04 or flags & 0x20:
                                return name.strip()
                            
                            offset += 18
        except Exception as e:
            pass
        
        return None
    
    @staticmethod
    def _get_hostname_mdns(ip: str, timeout: int = 2) -> Optional[str]:
        """
        Essaie d'obtenir le nom d'hôte via mDNS (Multicast DNS).
        """
        try:
            # Construction du paquet mDNS request
            mdns_query = b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            parts = ip.split('.')
            for part in parts:
                mdns_query += bytes([len(part)]) + part.encode('ascii')
            mdns_query += b'\x07in-addr\x04arpa\x00\x00\x0c\x00\x01'
            
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(mdns_query, ('224.0.0.251', 5353))
                
                data, _ = s.recvfrom(1024)
                if len(data) > 12:
                    # Simplement extraire tout texte qui ressemble à un nom d'hôte
                    hostname_match = re.search(b'[a-zA-Z0-9][a-zA-Z0-9\-_.]{1,61}[a-zA-Z0-9]', data[12:])
                    if hostname_match:
                        return hostname_match.group(0).decode('ascii', errors='ignore')
        except:
            pass
        
        return None
    
    @staticmethod
    def _get_linux_hostname(ip: str, timeout: int = 2) -> Optional[str]:
        """
        Méthode spécifique pour obtenir les noms d'hôte des machines Linux.
        Utilise plusieurs techniques adaptées aux systèmes Linux/Unix.
        """
        try:
            # Essayer SSH pour identifier Linux
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, 22))
            if result == 0:
                sock.close()
                
                # Si SSH est ouvert, c'est probablement un Linux
                # Faire une requête DNS avec timeout plus long
                try:
                    socket.setdefaulttimeout(3.0)  # Plus long timeout pour Linux
                    name, _, _ = socket.gethostbyaddr(ip)
                    if name and name != ip:
                        return name
                except:
                    pass
                    
                # Essayer Avahi/mDNS avec .local
                try:
                    parts = ip.split('.')
                    reverse_ip = f"{parts[3]}.{parts[2]}.{parts[1]}.{parts[0]}"
                    resolved = socket.getaddrinfo(f"{reverse_ip}.in-addr.arpa", None)
                    if resolved and resolved[0][4][0] != ip:
                        return resolved[0][4][0]
                except:
                    pass
                    
                # Rechercher des informations système par SSH (sans authentification)
                try:
                    # Nous pouvons juste vérifier la bannière SSH pour identifier Ubuntu
                    banner = ""
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(1)
                        s.connect((ip, 22))
                        banner = s.recv(1024).decode('ascii', errors='ignore').lower()
                        
                    if "ubuntu" in banner:
                        return f"Ubuntu-{ip.split('.')[-1]}"
                    if "debian" in banner:
                        return f"Debian-{ip.split('.')[-1]}"
                except:
                    pass
                
                # Si SSH est ouvert mais pas de nom d'hôte, utiliser un nom descriptif
                return f"Linux-{ip.split('.')[-1]}"
            else:
                sock.close()
        except:
            pass
        return None
    
    @staticmethod
    def get_hostname(ip: str, timeout: int = 2) -> str:
        """
        Obtient le nom d'hôte avec priorité aux appareils Linux et Windows.
        Fonction améliorée pour détecter les noms d'hôtes Linux.
        """
        # 1. Utiliser le cache des noms d'hôtes si disponible
        hostname_cache = getattr(DeviceInfoGatherer, '_hostname_cache', {})
        if ip in hostname_cache:
            return hostname_cache[ip]
        
        # 2. Méthode DNS standard (rapide et fiable pour Windows)
        try:
            name, _, _ = socket.gethostbyaddr(ip)
            if name and name != ip:
                hostname_cache[ip] = name
                DeviceInfoGatherer._hostname_cache = hostname_cache
                return name
        except:
            pass
        
        # 3. Méthode spécifique pour Linux - NOUVEAU
        linux_name = DeviceInfoGatherer._get_linux_hostname(ip, timeout)
        if linux_name:
            hostname_cache[ip] = linux_name
            DeviceInfoGatherer._hostname_cache = hostname_cache
            return linux_name
            
        # 4. NetBIOS pour machines Windows
        netbios_name = DeviceInfoGatherer._get_netbios_name(ip, timeout)
        if netbios_name:
            hostname_cache[ip] = netbios_name
            DeviceInfoGatherer._hostname_cache = hostname_cache
            return netbios_name
            
        # 5. mDNS pour appareils Apple/Linux
        mdns_name = DeviceInfoGatherer._get_hostname_mdns(ip, timeout)
        if mdns_name:
            hostname_cache[ip] = mdns_name
            DeviceInfoGatherer._hostname_cache = hostname_cache
            return mdns_name
        
        # 6. Caractériser l'IP pour mettre un nom par défaut pertinent
        try:
            last_octet = int(ip.split('.')[-1])
            
            # Traitement spécial pour les adresses importantes
            if last_octet == 1:
                default_name = "Router"
            elif last_octet <= 20:
                default_name = f"Device-{last_octet}"
            elif last_octet >= 240:
                default_name = f"Gateway-{last_octet}"
            else:
                default_name = f"Device-{last_octet}"
                
        except:
            default_name = "Unknown"
        
        # 7. Méthode pour Mobile-Devices (Android/iOS)
        try:
            # Ping pour assurer la disponibilité
            ping_result = DeviceInfoGatherer.ping(ip, count=1, timeout=1)
            if ping_result['success']:
                # Tenter l'identification par ports typiques
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                
                # Port SSH - probablement Linux
                if sock.connect_ex((ip, 22)) == 0:
                    hostname_cache[ip] = f"Linux-{last_octet}"
                    DeviceInfoGatherer._hostname_cache = hostname_cache
                    return f"Linux-{last_octet}"
                    
                # Port HTTP commun sur les appareils mobiles
                if sock.connect_ex((ip, 8080)) == 0:
                    hostname_cache[ip] = f"Android-{last_octet}"
                    DeviceInfoGatherer._hostname_cache = hostname_cache
                    return f"Android-{last_octet}"
                    
                # Port ADB pour Android
                if sock.connect_ex((ip, 5555)) == 0:
                    hostname_cache[ip] = f"Android-{last_octet}"
                    DeviceInfoGatherer._hostname_cache = hostname_cache
                    return f"Android-{last_octet}"
                
                # Port iOS typique
                if sock.connect_ex((ip, 62078)) == 0:
                    hostname_cache[ip] = f"iOS-{last_octet}"
                    DeviceInfoGatherer._hostname_cache = hostname_cache
                    return f"iOS-{last_octet}"
        except:
            pass
        
        # 8. Retourner le nom par défaut avec l'octet (meilleur que "Unknown")
        hostname_cache[ip] = default_name
        DeviceInfoGatherer._hostname_cache = hostname_cache
        return default_name
    
    @staticmethod
    def get_remote_info(ip: str, timeout: int = 2, skip_os_detection: bool = False) -> Dict[str, Any]:
        """
        Get information about a remote device using various methods.
        Amélioré avec cache OS et possibilité de sauter la détection d'OS.
        
        Args:
            ip: IP address of the remote device
            timeout: Timeout in seconds for network operations
            skip_os_detection: Skip OS detection to improve performance
            
        Returns:
            Dictionary containing device information
        """
        info = {
            'ip': ip,
            'hostname': 'Unknown',
            'mac': 'Unknown',
            'os': 'Unknown',
            'open_ports': [],
            'status': 'Unknown',
            'ttl': None
        }
        
        # Vérifier le cache d'OS d'abord
        with DeviceInfoGatherer._os_cache_lock:
            if ip in DeviceInfoGatherer._os_cache:
                info['os'] = DeviceInfoGatherer._os_cache[ip]
        
        # Amélioration: Récupérer le hostname avec une méthode plus robuste
        info['hostname'] = DeviceInfoGatherer.get_hostname(ip, timeout=timeout)
        
        # Check if host is up using ping
        ping_result = DeviceInfoGatherer.ping(ip, count=1, timeout=timeout)
        info['status'] = 'up' if ping_result['success'] else 'down'
        
        # Récupérer le TTL du ping si disponible
        if ping_result['success'] and 'ttl' in ping_result:
            info['ttl'] = ping_result['ttl']
        
        if info['status'] == 'up':
            # Get MAC address using improved method
            info['mac'] = DeviceInfoGatherer.get_mac_address(ip, timeout)
            
            # Scan common ports with emphasis on OS-specific ports
            common_ports = [
                22,     # SSH (Linux/macOS)
                80,     # HTTP
                443,    # HTTPS
                445,    # SMB (Windows)
                3389,   # RDP (Windows)
                135,    # RPC (Windows)
                139,    # NetBIOS (Windows)
                5985,   # WinRM (Windows)
                5555,   # ADB (Android)
                62078,  # iOS sync
                8080,   # Alternative HTTP
                53,     # DNS (routers)
                548,    # AFP (macOS)
                631     # CUPS (Linux/macOS)
            ]
            
            for port in common_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout/2)  # Réduire le timeout par port pour améliorer les performances
                try:
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        info['open_ports'].append(port)
                except:
                    pass
                finally:
                    sock.close()
            
            # Détection OS si demandée et pas dans le cache
            if not skip_os_detection:
                with DeviceInfoGatherer._os_cache_lock:
                    if ip not in DeviceInfoGatherer._os_cache:
                        os_type = DeviceInfoGatherer.detect_os(
                            ip=ip, 
                            ttl=info.get('ttl'), 
                            open_ports=info.get('open_ports'),
                            hostname=info.get('hostname'), 
                            mac=info.get('mac')
                        )
                        DeviceInfoGatherer._os_cache[ip] = os_type
                        info['os'] = os_type
                    else:
                        info['os'] = DeviceInfoGatherer._os_cache[ip]
            elif ip in DeviceInfoGatherer._os_cache:
                info['os'] = DeviceInfoGatherer._os_cache[ip]
        
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
            'ttl': None,
            'error': None
        }
        
        try:
            if platform.system().lower() == 'windows':
                args = ['ping', '-n', str(count), '-w', str(timeout * 1000), ip]
            else:  # Linux/Mac
                args = ['ping', '-c', str(count), '-W', str(timeout), ip]
            
            ping_result = subprocess.run(args, 
                                       capture_output=True, text=True, timeout=timeout * count + 5, errors='ignore')
            
            if ping_result.returncode == 0:
                result['success'] = True
                
                # Parse TTL from response (important for OS detection)
                ttl_match = re.search(r'TTL=(\d+)', ping_result.stdout, re.IGNORECASE)
                if ttl_match:
                    result['ttl'] = int(ttl_match.group(1))
                
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

    @staticmethod
    def detect_os(ip: str, ttl: Optional[int] = None, open_ports: List[int] = None, hostname: str = None, mac: str = None) -> str:
        """
        Détecte le système d'exploitation avec priorité aux systèmes Linux sur Android.
        Version améliorée pour éviter de classifier des machines Linux comme Android.
        
        Args:
            ip: Adresse IP de l'appareil
            ttl: Valeur TTL (Time To Live) obtenue lors du ping (si disponible)
            open_ports: Liste des ports ouverts détectés
            hostname: Nom d'hôte de l'appareil (si disponible)
            mac: Adresse MAC de l'appareil (si disponible)
            
        Returns:
            Système d'exploitation détecté (String)
        """
        try:
            if open_ports is None:
                open_ports = []
            
            # *** PRIORITÉ ABSOLUE: Noms d'hôte Windows ***
            # Si le nom d'hôte commence par DESKTOP- ou contient "WIN", c'est Windows, sans exception
            if hostname:
                hostname_lower = hostname.lower()
                # Motifs Windows avec priorité absolue
                if (hostname_lower.startswith("desktop-") or 
                    hostname_lower.startswith("laptop-") or
                    "win" in hostname_lower or 
                    "-pc" in hostname_lower):
                    return "Windows"
                
                # Motifs Linux/Ubuntu explicites avec priorité élevée
                if any(pattern in hostname_lower for pattern in ["ubuntu", "debian", "fedora", "centos", "redhat", 
                                                         "mint", "raspberrypi", "kali", "arch", "linux"]):
                    return "Linux"
            
            # *** PRIORITÉ SSH POUR LINUX ***
            # Si le port SSH est ouvert, c'est très probablement Linux, pas Android
            if open_ports and 22 in open_ports:
                # Vérifier s'il y a des ports Windows spécifiques aussi
                windows_ports = set([135, 139, 445, 3389, 5985])
                if any(port in windows_ports for port in open_ports):
                    return "Windows"
                
                # Si aucun port Windows spécifique, c'est probablement Linux
                return "Linux"
            
            # *** DÉTECTION PRIORITAIRE DE ROUTEUR ***
            # Les adresses IP se terminant par .1 sont généralement des routeurs
            try:
                last_octet = int(ip.split('.')[-1])
                if last_octet == 1:
                    # Vérifier les ports typiques des routeurs
                    if open_ports and any(port in open_ports for port in [80, 443, 53, 23, 22, 8080]):
                        return "Router"
                    # Ou si le nom d'hôte contient des indices
                    if hostname and any(pattern in hostname_lower for pattern in 
                                       ["router", "gateway", "modem", "ap-", "wap", "wifi", "dsl", 
                                        "tp-link", "netgear", "asus", "linksys", "dlink"]):
                        return "Router"
                    # Par défaut, considérer les IPs en .1 comme routeurs
                    return "Router"
            except:
                pass
                
            # Pour forcer la détection des adresses IP spécifiques comme Android
            specific_android_ips = ["192.168.100.2", "192.168.100.12", "192.168.100.13"]
            if ip in specific_android_ips:
                return "Android"
                
            # Liste des préfixes MAC communs pour les routeurs
            router_mac_prefixes = [
                "00:18:e7", "00:1d:7e", "c4:3d:c7", "00:90:a9", "b0:48:7a", 
                "00:1a:2b", "e8:4d:d0", "c0:a0:bb", "d8:5d:4c", "74:da:38", 
                "54:a0:50", "f8:1a:67", "e8:94:f6", "00:26:5a", "14:cc:20"
            ]
                
            if mac:
                mac_lower = mac.lower()
                # Vérification des préfixes MAC pour les routeurs
                for prefix in router_mac_prefixes:
                    if mac_lower.startswith(prefix):
                        return "Router"
                    
                # Liste de préfixes MAC pour Android
                android_mac_prefixes = [
                    "9e:66:3d", "00:bb:3a", "94:35:0a", "5c:f5:da", "60:6b:bd", 
                    "ec:9b:f3", "00:73:e0", "f8:8f:ca", "bc:ee:7b", "94:65:9c", 
                    "c0:ee:fb", "70:bb:e9", "64:80:99", "d8:63:75", "c8:3d:dc",
                    "00:9e:c8", "10:51:72", "ac:e8:7b", "a8:c8:3a", "7c:49:eb",
                    "00:34:fe", "34:14:5f", "70:4c:a5", "78:f8:82", "84:cf:bf",
                    "d0:22:be", "ac:cf:5c", "d8:38:fc", "b4:ae:2b", "ac:5f:ea",
                    "d8:90:e8", "f6:09", "d2:26", "70:c9", "80:ea", "98:4f", "f0:98",
                    "28:f0", "38:2d", "2c:f0", "d0:f0", "f6:03", "60:a7"
                ]
                
                ios_mac_prefixes = [
                    "14:7d:da", "ac:fd:ec", "34:ab:37", "0c:30:21", "28:cf:e9",
                    "84:a1:34", "24:f0:94", "9c:f4:8e", "70:a2:b3", "ac:bc:32",
                    "04:4b:ed", "34:36:3b", "f8:38:80", "a8:5c:2c", "f8:27", "a8:66",
                    "70:de", "f0:cb", "5c:f9", "60:f8", "8c:2d", "c8:e0", "28:6a"
                ]
                
                # Vérification des préfixes MAC pour Android
                for prefix in android_mac_prefixes:
                    if mac_lower.startswith(prefix):
                        return "Android"
                
                # Vérification des préfixes MAC pour iOS
                for prefix in ios_mac_prefixes:
                    if mac_lower.startswith(prefix):
                        return "iOS"
            
            # Ports spécifiques pour classification des OS
            if open_ports:
                # Ports Windows spécifiques
                windows_ports = [135, 139, 445, 3389, 5985]
                if any(port in open_ports for port in windows_ports):
                    return "Windows"
                
                # Ports Android très spécifiques
                android_ports = [5555, 5554, 7000]
                if any(port in open_ports for port in android_ports):
                    return "Android"
                
                # Ports iOS très spécifiques
                ios_ports = [62078, 49152, 1999, 9418, 5050]
                if any(port in open_ports for port in ios_ports):
                    return "iOS"
                    
                # Ports macOS spécifiques
                mac_ports = [548, 631, 5900, 7000]
                if any(port in open_ports for port in mac_ports):
                    return "macOS"
                
                # Si le port SSH (22) est ouvert, c'est très probablement Linux
                if 22 in open_ports:
                    return "Linux"
                
                # Ports routeurs typiques
                router_ports = [53, 80, 443, 23, 22, 8080, 8081, 161, 179, 514]
                if len([port for port in router_ports if port in open_ports]) >= 3:
                    return "Router"
                    
                # Si peu de ports sont ouverts (typique des appareils mobiles) et contient HTTP/HTTPS
                if len(open_ports) <= 3 and (80 in open_ports or 8080 in open_ports):
                    # Et pas de services typiquement serveur comme SSH
                    if 22 not in open_ports and 443 not in open_ports:
                        return "Android"
            
            # 4. Analyse du nom d'hôte pour les autres OS (non-Windows déjà traité)
            if hostname:
                hostname_lower = hostname.lower()
                
                # Motifs routeurs (prioritaires)
                if any(pattern in hostname_lower for pattern in ["router", "gateway", "ap-", "routeur", "switch", "wap", 
                                                         "wifi", "modem", "dsl", "tp-link", "netgear", "asus",
                                                         "linksys", "dlink"]):
                    return "Router"
                
                # Motifs iOS
                if any(pattern in hostname_lower for pattern in ["iphone", "ipad", "ipod", "ios", "apple"]):
                    return "iOS"
                    
                # Motifs Android
                if any(pattern in hostname_lower for pattern in ["android", "galaxy", "pixel", "oneplus", "xiaomi", 
                                                         "huawei", "oppo", "vivo", "realme", "poco", "redmi",
                                                         "sm-", "gt-"]):
                    return "Android"
                
                # Motifs macOS
                if any(pattern in hostname_lower for pattern in ["macbook", "imac", "mbp", "mac-", "macos"]):
                    return "macOS"
            
            # 5. Pour les TTL typiques
            if ttl is not None:
                if 50 <= ttl <= 70:
                    # Linux a généralement TTL=64
                    # Priorité à Linux si SSH est présent
                    if 22 in open_ports:
                        return "Linux"
                    
                    # Si c'est probablement un routeur, ne pas classer comme Android
                    try:
                        last_octet = int(ip.split('.')[-1])
                        if last_octet == 1:
                            return "Router"
                    except:
                        pass
                    
                    # Si on a un indice de routeur avec ce TTL
                    if open_ports and any(port in open_ports for port in [53, 80, 443, 8080]):
                        return "Router"
                    
                    # Par défaut pour TTL 64 si pas d'autre indice
                    return "Linux"
                
                # TTL Windows typique
                elif 100 <= ttl <= 140:
                    return "Windows"
                    
                # TTL élevé typique d'iOS/macOS
                elif ttl >= 225:
                    try:
                        last_octet = int(ip.split('.')[-1])
                        if last_octet > 15:  # Smartphones vs Mac
                            return "iOS"
                        else:
                            return "macOS"
                    except:
                        return "macOS"
                
                # TTL typiques des routeurs
                elif ttl in [60, 64, 128, 254, 255]:
                    # Vérifier si c'est une adresse de routeur
                    try:
                        last_octet = int(ip.split('.')[-1])
                        if last_octet == 1:
                            return "Router"
                    except:
                        pass
            
            # Si l'appareil a très peu de ports ouverts et pas de nom d'hôte, probablement mobile
            if len(open_ports) <= 2 and (hostname is None or hostname == ""):
                # Ne pas classer les adresses .1 comme Android
                try:
                    last_octet = int(ip.split('.')[-1])
                    if last_octet == 1:
                        return "Router"
                except:
                    pass
                return "Android"  # On assume Android par défaut
                
            # Par défaut pour les appareils non identifiés
            return "Unknown"
        except Exception as e:
            logger.error(f"Error in OS detection: {e}")
            return "Unknown"
            
    @staticmethod
    def scan_network(subnet: str, callback: callable = None, 
                    include_os_detection: bool = True, parallel: bool = True) -> Dict[str, Dict[str, Any]]:
        """
        Scan an entire subnet for devices.
        
        Args:
            subnet: Subnet to scan (e.g., '192.168.1.0/24')
            callback: Callback function to report progress
            include_os_detection: Whether to include OS detection
            parallel: Whether to use parallel scanning
            
        Returns:
            Dictionary of devices found
        """
        # Réinitialiser les caches pour une détection fraîche
        DeviceInfoGatherer._os_cache = {}
        DeviceInfoGatherer._hostname_cache = {}
        
        # Déterminer les adresses à scanner
        try:
            import ipaddress
            network = ipaddress.ip_network(subnet, strict=False)
            hosts = list(network.hosts())
        except (ImportError, ValueError):
            # Fallback si ipaddress n'est pas disponible ou si le format est invalide
            parts = subnet.split('/')
            if len(parts) != 2:
                return {}
                
            base_ip = parts[0].split('.')
            if len(base_ip) != 4:
                return {}
                
            try:
                mask = int(parts[1])
                if not (0 <= mask <= 32):
                    return {}
                    
                host_bits = 32 - mask
                max_hosts = (1 << host_bits) - 2  # -2 pour exclure l'adresse réseau et broadcast
                
                hosts = []
                base = '.'.join(base_ip[:3]) + '.'
                
                # Calculer la plage d'adresses
                for i in range(1, min(max_hosts + 1, 255)):
                    hosts.append(base + str(i))
            except:
                return {}
        
        devices = {}
        
        # Fonction pour scanner un hôte
        def scan_host(ip):
            try:
                # Première étape: vérifier si l'hôte est actif
                ping_result = DeviceInfoGatherer.ping(ip, count=1, timeout=1)
                if ping_result['success']:
                    # Deuxième étape: obtenir les informations complètes
                    info = DeviceInfoGatherer.get_remote_info(ip, timeout=2, 
                                                            skip_os_detection=not include_os_detection)
                    
                    devices[ip] = info
                    
                    if callback:
                        callback(ip, info, len(devices), len(hosts))
            except Exception as e:
                logger.error(f"Error scanning host {ip}: {e}")
        
        # Utiliser le scanning parallèle si demandé
        if parallel:
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                executor.map(scan_host, hosts)
        else:
            for ip in hosts:
                scan_host(str(ip))
                
        return devices

# --- Example of how to use the class ---
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    import json

    print("--- Getting Local Device Info ---")
    local_info = DeviceInfoGatherer.get_local_info()
    print(json.dumps(local_info, indent=2))

    print("\n--- Getting Remote Device Info (Example) ---")
    
    # Réinitialiser les caches pour une détection fraîche
    DeviceInfoGatherer._os_cache = {}
    DeviceInfoGatherer._hostname_cache = {}
    
    remote_ip_to_test = "192.168.100.24"
    remote_info = DeviceInfoGatherer.get_remote_info(remote_ip_to_test)
    print(f"Results for {remote_ip_to_test}:")
    print(json.dumps(remote_info, indent=2))