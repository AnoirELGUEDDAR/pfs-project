"""
Onglet de scan réseau pour l'application Network Scanner
"""
import logging
import socket
import threading
import ipaddress
import json
import csv
import time
import sys
import traceback
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

# Tentative d'importation de netifaces, mais rendu optionnel
try:
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    NETIFACES_AVAILABLE = False
    print("Module netifaces non disponible. Certaines fonctionnalités seront limitées.")

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTableWidget, QProgressBar,
    QTableWidgetItem, QHeaderView, QLabel, QComboBox, QSpinBox, QCheckBox,
    QLineEdit, QMessageBox, QFileDialog, QGroupBox, QFormLayout, QDialog, QMenu
)
from PyQt5.QtCore import Qt, pyqtSignal, QThread, QTimer

# Importer les modules personnalisés
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

logger = logging.getLogger(__name__)

class ScanThread(QThread):
    """Thread pour effectuer le scan réseau en arrière-plan"""
    
    # Signaux
    progress_updated = pyqtSignal(int)
    status_updated = pyqtSignal(str)
    device_discovered = pyqtSignal(dict)
    scan_finished = pyqtSignal(bool)  # True si succès, False si erreur ou arrêt
    
    def __init__(self, ip_range: str, scan_type: str = "ping", timeout: int = 1, 
                scan_ports: List[int] = None, port_scan_type: str = "common"):
        super().__init__()
        self.ip_range = ip_range
        self.scan_type = scan_type
        self.timeout = timeout
        self.scan_ports = scan_ports or []
        self.port_scan_type = port_scan_type
        self._stop_requested = False
        
    def run(self):
        """Exécuter le scan avec une meilleure gestion des erreurs"""
        try:
            if self.scan_type == "single_ip":
                self._scan_single_ip(self.ip_range)
            elif self.scan_type == "ping":
                self._scan_ping(self.ip_range)
            elif self.scan_type == "arp":
                try:
                    # Vérifier si scapy est disponible
                    from scapy.all import ARP
                    self._scan_arp(self.ip_range)
                except ImportError:
                    self.status_updated.emit("Module scapy non disponible. Utilisation du scan ping à la place.")
                    self._scan_ping(self.ip_range)
            elif self.scan_type == "nmap" and NMAP_AVAILABLE:
                self._scan_nmap(self.ip_range)
            else:
                # Méthode par défaut (ping)
                self._scan_ping(self.ip_range)
                
            self.scan_finished.emit(True)
        except Exception as e:
            # Capture et affiche l'erreur complète
            error_details = traceback.format_exc()
            logger.exception(f"Erreur lors du scan: {e}\n{error_details}")
            self.status_updated.emit(f"Erreur: {str(e)} - Vérifiez les paramètres de scan")
            self.scan_finished.emit(False)
            
    def stop(self):
        """Demander l'arrêt du scan"""
        self._stop_requested = True
        self.status_updated.emit("Arrêt du scan en cours...")
        
    def _scan_ping(self, ip_range: str):
        """Scan par ping ICMP"""
        try:
            # Convertir la plage IP en liste d'adresses
            ip_network = ipaddress.ip_network(ip_range)
            total_ips = ip_network.num_addresses
            
            # Ignorer l'adresse réseau et l'adresse de broadcast
            if total_ips > 2:
                ips_to_scan = [str(ip) for ip in ip_network][1:-1]
                total_ips -= 2
            else:
                ips_to_scan = [str(ip) for ip in ip_network]
            
            self.status_updated.emit(f"Scan de {total_ips} adresses IP par ping...")
            
            # Scan de chaque adresse IP
            for i, ip in enumerate(ips_to_scan):
                if self._stop_requested:
                    return
                    
                # Mettre à jour la progression
                progress = int((i / total_ips) * 100)
                self.progress_updated.emit(progress)
                self.status_updated.emit(f"Scan en cours: {ip} ({i+1}/{total_ips})")
                
                # Effectuer le ping
                if self._is_host_active(ip):
                    # Récupérer des informations sur l'hôte
                    hostname = self._get_hostname(ip)
                    mac = self._get_mac_address(ip)
                    vendor = self._get_mac_vendor(mac) if mac else ""
                    
                    # Scan des ports si demandé
                    open_ports = []
                    if self.scan_ports:
                        open_ports = self._scan_ports(ip, self.scan_ports)
                    
                    # Émettre le signal de découverte
                    self.device_discovered.emit({
                        'ip': ip,
                        'hostname': hostname,
                        'mac': mac,
                        'vendor': vendor,
                        'open_ports': open_ports,
                        'status': 'online'
                    })
                    
            self.progress_updated.emit(100)
            self.status_updated.emit(f"Scan terminé: {ip_range}")
            
        except Exception as e:
            logger.exception(f"Erreur lors du scan ping: {e}")
            self.status_updated.emit(f"Erreur lors du scan ping: {str(e)}")
            raise
            
    def _scan_arp(self, ip_range: str):
        """Scan ARP pour les machines locales"""
        try:
            try:
                from scapy.all import ARP, Ether, srp
            except ImportError:
                self.status_updated.emit("Module scapy non disponible. Impossible d'utiliser le scan ARP.")
                return
                
            # Créer une requête ARP
            arp = ARP(pdst=ip_range)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            
            self.status_updated.emit(f"Envoi des requêtes ARP pour {ip_range}...")
            
            # Envoyer les paquets et récupérer les réponses
            result = srp(packet, timeout=self.timeout, verbose=0)[0]
            
            total = len(result)
            self.status_updated.emit(f"Réponses ARP reçues: {total}")
            
            # Traiter les réponses
            for i, (sent, received) in enumerate(result):
                if self._stop_requested:
                    return
                    
                # Extraire les informations
                ip = received.psrc
                mac = received.hwsrc
                hostname = self._get_hostname(ip)
                vendor = self._get_mac_vendor(mac)
                
                # Mettre à jour la progression
                progress = int(((i+1) / total) * 100) if total > 0 else 100
                self.progress_updated.emit(progress)
                self.status_updated.emit(f"Traitement: {ip} ({i+1}/{total})")
                
                # Scan des ports si demandé
                open_ports = []
                if self.scan_ports:
                    open_ports = self._scan_ports(ip, self.scan_ports)
                
                # Émettre le signal de découverte
                self.device_discovered.emit({
                    'ip': ip,
                    'hostname': hostname,
                    'mac': mac,
                    'vendor': vendor,
                    'open_ports': open_ports,
                    'status': 'online'
                })
                
            self.progress_updated.emit(100)
            self.status_updated.emit(f"Scan ARP terminé: {ip_range}")
            
        except Exception as e:
            logger.exception(f"Erreur lors du scan ARP: {e}")
            self.status_updated.emit(f"Erreur lors du scan ARP: {str(e)}")
            raise
            
    def _scan_nmap(self, ip_range: str):
        """Scan avec Nmap"""
        try:
            if not NMAP_AVAILABLE:
                self.status_updated.emit("Nmap non disponible. Installez python-nmap.")
                return
                
            nm = nmap.PortScanner()
            self.status_updated.emit(f"Démarrage du scan Nmap sur {ip_range}...")
            
            # Définir les options de scan
            arguments = "-sn"  # Scan ping, pas de scan de ports
            if self.scan_ports:
                if self.port_scan_type == "common":
                    arguments = "-sS -F"  # Scan SYN des ports courants
                elif self.port_scan_type == "all":
                    arguments = "-sS"  # Scan SYN de tous les ports
                elif self.port_scan_type == "specific":
                    port_list = ",".join(map(str, self.scan_ports))
                    arguments = f"-sS -p {port_list}"  # Scan SYN des ports spécifiés
            
            # Exécuter le scan
            nm.scan(hosts=ip_range, arguments=arguments)
            
            # Traiter les résultats
            total_hosts = len(nm.all_hosts())
            self.status_updated.emit(f"Traitement des résultats Nmap: {total_hosts} hôtes")
            
            for i, ip in enumerate(nm.all_hosts()):
                if self._stop_requested:
                    return
                    
                # Mettre à jour la progression
                progress = int(((i+1) / total_hosts) * 100) if total_hosts > 0 else 100
                self.progress_updated.emit(progress)
                self.status_updated.emit(f"Traitement: {ip} ({i+1}/{total_hosts})")
                
                host_info = nm[ip]
                
                # Vérifier si l'hôte est actif
                if host_info['status']['state'] == 'up':
                    # Extraire les informations
                    hostname = host_info.hostname() if hasattr(host_info, 'hostname') else ""
                    mac = ""
                    vendor = ""
                    
                    # Tenter de récupérer l'adresse MAC
                    if 'addresses' in host_info and 'mac' in host_info['addresses']:
                        mac = host_info['addresses']['mac']
                        if 'vendor' in host_info and mac in host_info['vendor']:
                            vendor = host_info['vendor'][mac]
                    
                    # Récupérer les ports ouverts
                    open_ports = []
                    if 'tcp' in host_info:
                        for port, port_info in host_info['tcp'].items():
                            if port_info['state'] == 'open':
                                open_ports.append(int(port))
                    
                    # Émettre le signal de découverte
                    self.device_discovered.emit({
                        'ip': ip,
                        'hostname': hostname,
                        'mac': mac,
                        'vendor': vendor,
                        'open_ports': open_ports,
                        'status': 'online'
                    })
                    
            self.progress_updated.emit(100)
            self.status_updated.emit(f"Scan Nmap terminé: {ip_range}")
            
        except Exception as e:
            logger.exception(f"Erreur lors du scan Nmap: {e}")
            self.status_updated.emit(f"Erreur lors du scan Nmap: {str(e)}")
            raise
            
    def _scan_single_ip(self, ip: str):
        """Scan d'une seule adresse IP"""
        try:
            self.status_updated.emit(f"Scan de l'adresse IP {ip}...")
            self.progress_updated.emit(10)
            
            # Vérifier si l'hôte est actif
            if self._is_host_active(ip):
                # Extraire les informations
                self.progress_updated.emit(30)
                hostname = self._get_hostname(ip)
                
                self.progress_updated.emit(50)
                mac = self._get_mac_address(ip)
                vendor = self._get_mac_vendor(mac) if mac else ""
                
                # Scan des ports si demandé
                open_ports = []
                if self.scan_ports:
                    self.status_updated.emit(f"Scan des ports sur {ip}...")
                    self.progress_updated.emit(70)
                    open_ports = self._scan_ports(ip, self.scan_ports)
                
                self.progress_updated.emit(90)
                
                # Émettre le signal de découverte
                self.device_discovered.emit({
                    'ip': ip,
                    'hostname': hostname,
                    'mac': mac,
                    'vendor': vendor,
                    'open_ports': open_ports,
                    'status': 'online'
                })
                
                self.status_updated.emit(f"Hôte {ip} actif et analysé")
            else:
                self.status_updated.emit(f"Hôte {ip} non accessible")
            
            self.progress_updated.emit(100)
            
        except Exception as e:
            logger.exception(f"Erreur lors du scan d'une IP: {e}")
            self.status_updated.emit(f"Erreur lors du scan de {ip}: {str(e)}")
            raise
            
    def _is_host_active(self, ip: str) -> bool:
        """Vérifier si un hôte est actif avec une méthode plus fiable"""
        try:
            # Méthode plus fiable: vérifier plusieurs ports et exiger au moins une réponse positive
            success_count = 0
            
            # Test avec ping TCP sur plusieurs ports
            common_ports = [80, 443, 22, 445, 135, 3389]
            for port in common_ports:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(self.timeout)
                    result = s.connect_ex((ip, port))
                    if result == 0:
                        success_count += 1
                        if success_count >= 1:  # Exiger au moins une réponse positive
                            return True
                            
            # Si aucun port n'a répondu, essayer ICMP ping avec subprocess
            try:
                import subprocess
                
                # Commande ping selon la plateforme
                if 'win' in sys.platform:
                    # Windows - un seul ping avec timeout court
                    ping_cmd = ['ping', '-n', '1', '-w', str(int(self.timeout * 1000)), ip]
                else:
                    # Linux/Mac - un seul ping avec timeout court
                    ping_cmd = ['ping', '-c', '1', '-W', str(self.timeout), ip]
                    
                # Exécuter la commande et vérifier le résultat
                result = subprocess.run(ping_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if result.returncode == 0:
                    return True
            except:
                pass
                
            # Si tout échoue, l'hôte n'est pas actif
            return False
        except:
            return False
            
    def _get_hostname(self, ip: str) -> str:
        """Obtenir le nom d'hôte à partir de l'adresse IP"""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except socket.herror:
            return ""
            
    def _get_mac_address(self, ip: str) -> str:
        """Obtenir l'adresse MAC d'une adresse IP (ARP)"""
        try:
            # Méthode 1: Table ARP (Windows/Linux)
            import subprocess
            import re
            
            # Essayer la commande arp selon le système
            try:
                if 'win' in sys.platform:
                    # Windows
                    result = subprocess.check_output(['arp', '-a', ip], universal_newlines=True)
                else:
                    # Linux / Mac
                    result = subprocess.check_output(['arp', '-n', ip], universal_newlines=True)
                
                # Extraire l'adresse MAC
                mac_matches = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', result)
                if mac_matches:
                    return mac_matches.group(0)
            except:
                pass
            
            # Méthode 2: Utiliser Scapy si disponible
            try:
                from scapy.all import ARP, Ether, srp
                arp = ARP(pdst=ip)
                ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                packet = ether/arp
                result = srp(packet, timeout=self.timeout, verbose=0)[0]
                if result:
                    return result[0][1].hwsrc
            except:
                pass
                
            return ""
        except:
            return ""
            
    def _get_mac_vendor(self, mac: str) -> str:
        """Obtenir le fabricant à partir de l'adresse MAC"""
        if not mac:
            return ""
            
        # Base de données locale simple des préfixes OUI
        oui_prefixes = {
            "00:00:0C": "Cisco",
            "00:1A:11": "Google",
            "00:1D:BA": "Sony",
            "00:50:56": "VMware",
            "00:14:22": "Dell",
            "00:21:19": "Samsung",
            "E4:E0:C5": "Samsung",
            "3C:97:0E": "Wistron",
            "F8:CA:B8": "Dell",
            "00:25:90": "Gobi",
            "00:15:E9": "D-Link",
            "00:18:E7": "Cameo Communications",
            "00:16:01": "Buffalo",
            "00:0D:B3": "SDO Communication",
            "00:05:1B": "Magic Control Technology",
            "00:0A:5E": "3COM",
            "B4:2E:99": "Gionee",
            "00:24:36": "Apple",
            "FC:A1:83": "Amazon",
            "00:17:88": "Philips"
        }
        
        # Normaliser l'adresse MAC
        mac_norm = mac.upper().replace("-", ":")
        
        # Vérifier les 3 premiers octets
        oui = mac_norm[:8]
        return oui_prefixes.get(oui, "")
            
    def _scan_ports(self, ip: str, ports: List[int]) -> List[int]:
        """Scanner les ports spécifiés sur une adresse IP"""
        open_ports = []
        
        for port in ports:
            if self._stop_requested:
                break
                
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(self.timeout)
                    result = s.connect_ex((ip, port))
                    if result == 0:
                        open_ports.append(port)
            except:
                pass
                
        return open_ports

class PortScanThread(QThread):
    """Thread dédié au scan de ports"""
    
    # Signaux
    progress_updated = pyqtSignal(int)
    status_updated = pyqtSignal(str)
    ports_found = pyqtSignal(list)
    scan_finished = pyqtSignal(bool)
    
    def __init__(self, ip: str, ports: List[int], timeout: float = 1.0):
        super().__init__()
        self.ip = ip
        self.ports = ports
        self.timeout = timeout
        self._stop_requested = False
        
    def run(self):
        """Exécuter le scan de ports"""
        try:
            total_ports = len(self.ports)
            self.status_updated.emit(f"Scan de {total_ports} ports sur {self.ip}...")
            
            open_ports = []
            for i, port in enumerate(self.ports):
                if self._stop_requested:
                    break
                    
                # Mettre à jour la progression
                progress = int(((i+1) / total_ports) * 100)
                self.progress_updated.emit(progress)
                self.status_updated.emit(f"Scan du port {port} ({i+1}/{total_ports})")
                
                # Tester si le port est ouvert
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(self.timeout)
                        result = s.connect_ex((self.ip, port))
                        if result == 0:
                            open_ports.append(port)
                except:
                    pass
                    
            # Émettre le signal avec les ports ouverts
            self.ports_found.emit(open_ports)
            
            self.progress_updated.emit(100)
            open_count = len(open_ports)
            self.status_updated.emit(f"Scan terminé: {open_count} port{'s' if open_count != 1 else ''} ouvert{'s' if open_count != 1 else ''}")
            self.scan_finished.emit(True)
            
        except Exception as e:
            logger.exception(f"Erreur lors du scan de ports: {e}")
            self.status_updated.emit(f"Erreur: {str(e)}")
            self.scan_finished.emit(False)
            
    def stop(self):
        """Arrêter le scan"""
        self._stop_requested = True

class PortScanDialog(QDialog):
    """Dialogue pour le scan de ports"""
    
    def __init__(self, ip: str, parent=None):
        super().__init__(parent)
        self.ip = ip
        self.ports = []
        self.scan_thread = None
        
        self.setWindowTitle(f"Scan de ports - {ip}")
        self.resize(400, 300)
        
        self._setup_ui()
        
    def _setup_ui(self):
        """Configurer l'interface utilisateur"""
        layout = QVBoxLayout(self)
        
        # Options de scan
        options_group = QGroupBox("Options de scan")
        options_layout = QFormLayout(options_group)
        
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems(["Ports courants", "Ports spécifiques", "Plage de ports"])
        self.scan_type_combo.currentIndexChanged.connect(self._update_port_options)
        options_layout.addRow("Type de scan:", self.scan_type_combo)
        
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("Ex: 80, 443, 22, 3389")
        options_layout.addRow("Ports:", self.port_input)
        
        self.start_port_spin = QSpinBox()
        self.start_port_spin.setRange(1, 65535)
        self.start_port_spin.setValue(1)
        self.start_port_spin.hide()
        options_layout.addRow("Port de début:", self.start_port_spin)
        
        self.end_port_spin = QSpinBox()
        self.end_port_spin.setRange(1, 65535)
        self.end_port_spin.setValue(1024)
        self.end_port_spin.hide()
        options_layout.addRow("Port de fin:", self.end_port_spin)
        
        self.timeout_spin = QDoubleSpinBox()
        self.timeout_spin.setRange(0.1, 10.0)
        self.timeout_spin.setValue(1.0)
        self.timeout_spin.setSingleStep(0.1)
        options_layout.addRow("Timeout (s):", self.timeout_spin)
        
        layout.addWidget(options_group)
        
        # Barre de progression
        self.progress_bar = QProgressBar()
        layout.addWidget(self.progress_bar)
        
        # Zone de statut
        self.status_label = QLabel("Prêt")
        layout.addWidget(self.status_label)
        
        # Résultats
        results_layout = QHBoxLayout()
        
        self.results_label = QLabel("Ports trouvés:")
        results_layout.addWidget(self.results_label)
        
        self.results_text = QLineEdit()
        self.results_text.setReadOnly(True)
        results_layout.addWidget(self.results_text, 1)
        
        layout.addLayout(results_layout)
        
        # Boutons
        buttons_layout = QHBoxLayout()
        
        self.start_button = QPushButton("Démarrer")
        self.start_button.clicked.connect(self._start_scan)
        buttons_layout.addWidget(self.start_button)
        
        self.stop_button = QPushButton("Arrêter")
        self.stop_button.clicked.connect(self._stop_scan)
        self.stop_button.setEnabled(False)
        buttons_layout.addWidget(self.stop_button)
        
        self.close_button = QPushButton("Fermer")
        self.close_button.clicked.connect(self.reject)
        buttons_layout.addWidget(self.close_button)
        
        layout.addLayout(buttons_layout)
        
    def _update_port_options(self):
        """Mettre à jour les options de port selon le type de scan"""
        scan_type = self.scan_type_combo.currentText()
        
        if scan_type == "Ports courants":
            self.port_input.setEnabled(False)
            self.port_input.setText("21, 22, 23, 25, 80, 443, 445, 3389, 8080, 8443")
            self.start_port_spin.hide()
            self.end_port_spin.hide()
        elif scan_type == "Ports spécifiques":
            self.port_input.setEnabled(True)
            self.port_input.setText("")
            self.port_input.setPlaceholderText("Ex: 80, 443, 22, 3389")
            self.start_port_spin.hide()
            self.end_port_spin.hide()
        elif scan_type == "Plage de ports":
            self.port_input.setEnabled(False)
            self.port_input.setText("")
            self.start_port_spin.show()
            self.end_port_spin.show()
            
    def _start_scan(self):
        """Démarrer le scan de ports"""
        ports = []
        
        # Récupérer la liste des ports selon le type de scan
        scan_type = self.scan_type_combo.currentText()
        
        if scan_type == "Ports courants":
            # Ports courants prédéfinis
            ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443]
        elif scan_type == "Ports spécifiques":
            # Ports spécifiques entrés par l'utilisateur
            try:
                port_str = self.port_input.text().strip()
                if port_str:
                    # Extraire les ports (peut être séparés par des virgules ou des espaces)
                    port_list = [p.strip() for p in port_str.replace(',', ' ').split()]
                    ports = [int(p) for p in port_list if p.isdigit() and 1 <= int(p) <= 65535]
                    
                if not ports:
                    QMessageBox.warning(self, "Erreur", "Veuillez entrer des numéros de ports valides (1-65535)")
                    return
            except Exception as e:
                QMessageBox.warning(self, "Erreur", f"Format de ports invalide: {str(e)}")
                return
        elif scan_type == "Plage de ports":
            # Plage de ports
            start = self.start_port_spin.value()
            end = self.end_port_spin.value()
            
            if start > end:
                QMessageBox.warning(self, "Erreur", "Le port de début doit être inférieur au port de fin")
                return
                
            if end - start > 1000:
                reply = QMessageBox.question(
                    self,
                    "Confirmation",
                    f"Vous allez scanner {end-start+1} ports, ce qui peut prendre du temps. Continuer?",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No
                )
                
                if reply == QMessageBox.No:
                    return
                
            ports = list(range(start, end + 1))
            
        # Vérifier qu'il y a des ports à scanner
        if not ports:
            QMessageBox.warning(self, "Erreur", "Aucun port spécifié pour le scan")
            return
            
        # Timeout
        timeout = self.timeout_spin.value()
        
        # Démarrer le scan dans un thread dédié
        self.scan_thread = PortScanThread(self.ip, ports, timeout)
        
        # Connecter les signaux
        self.scan_thread.progress_updated.connect(self.progress_bar.setValue)
        self.scan_thread.status_updated.connect(self.status_label.setText)
        self.scan_thread.ports_found.connect(self._display_ports)
        self.scan_thread.scan_finished.connect(self._scan_complete)
        
        # Démarrer le scan
        self.scan_thread.start()
        
        # Mettre à jour l'interface
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.close_button.setEnabled(False)
        self.scan_type_combo.setEnabled(False)
        self.port_input.setEnabled(False)
        self.start_port_spin.setEnabled(False)
        self.end_port_spin.setEnabled(False)
        self.timeout_spin.setEnabled(False)
        
    def _stop_scan(self):
        """Arrêter le scan en cours"""
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.stop()
            self.status_label.setText("Arrêt du scan en cours...")
            
    def _scan_complete(self, success):
        """Traitement à la fin du scan"""
        # Rétablir l'interface
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.close_button.setEnabled(True)
        self.scan_type_combo.setEnabled(True)
        self._update_port_options()  # Rétablir l'état des champs de ports
        self.timeout_spin.setEnabled(True)
        
    def _display_ports(self, ports):
        """Afficher les ports découverts"""
        self.ports = ports
        
        if ports:
            ports_str = ", ".join(map(str, sorted(ports)))
            self.results_text.setText(ports_str)
        else:
            self.results_text.setText("Aucun port ouvert trouvé")
            
    def get_ports(self):
        """Récupérer la liste des ports découverts"""
        return self.ports

class ScannerTab(QWidget):
    """Onglet de scan réseau"""
    
    # Signal pour notifier la découverte d'un appareil
    device_discovered = pyqtSignal(dict)
    
    def __init__(self):
        super().__init__()
        
        # Variables d'état
        self.scan_thread = None
        self.port_scan_thread = None
        self.discovered_devices = {}
        self.scan_time = 0
        
        # Configurer l'interface
        self._setup_ui()
        
        # Timer pour mise à jour périodique
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self._update_scan_time)
        
        logger.info("Onglet Scanner initialisé")
        
    def _setup_ui(self):
        """Configurer l'interface utilisateur"""
        layout = QVBoxLayout(self)
        
        # Groupe d'options de scan
        options_group = QGroupBox("Options de scan")
        options_layout = QFormLayout(options_group)
        
        # Sélection de l'interface réseau
        self.interface_combo = QComboBox()
        self._populate_interfaces()
        options_layout.addRow("Interface réseau:", self.interface_combo)
        self.interface_combo.currentIndexChanged.connect(self._update_ip_range)
        
        # Plage IP
        self.ip_range_input = QLineEdit()
        self._update_ip_range()
        options_layout.addRow("Plage IP:", self.ip_range_input)
        
        # Type de scan
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems(["Ping", "ARP", "Nmap"])
        if not NMAP_AVAILABLE:
            # Désactiver l'option Nmap si non disponible
            index = self.scan_type_combo.findText("Nmap")
            if index >= 0:
                self.scan_type_combo.model().item(index).setEnabled(False)
        options_layout.addRow("Méthode de scan:", self.scan_type_combo)
        
        # Options avancées
        advanced_layout = QHBoxLayout()
        
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 10)
        self.timeout_spin.setValue(1)
        self.timeout_spin.setSuffix(" s")
        advanced_layout.addWidget(QLabel("Timeout:"))
        advanced_layout.addWidget(self.timeout_spin)
        
        self.port_scan_check = QCheckBox("Scanner les ports")
        advanced_layout.addWidget(self.port_scan_check)
        
        self.port_scan_input = QLineEdit()
        self.port_scan_input.setPlaceholderText("80, 443, 22...")
        self.port_scan_input.setEnabled(False)
        advanced_layout.addWidget(self.port_scan_input)
        self.port_scan_check.toggled.connect(self.port_scan_input.setEnabled)
        
        options_layout.addRow("Options avancées:", advanced_layout)
        
        layout.addWidget(options_group)
        
        # Barre de progression et statut
        progress_layout = QHBoxLayout()
        
        self.progress_bar = QProgressBar()
        progress_layout.addWidget(self.progress_bar, 1)
        
        self.scan_time_label = QLabel("00:00")
        progress_layout.addWidget(self.scan_time_label)
        
        layout.addLayout(progress_layout)
        
        # Boutons de contrôle
        control_layout = QHBoxLayout()
        
        self.start_button = QPushButton("Démarrer le scan")
        self.start_button.clicked.connect(self.start_scan)
        control_layout.addWidget(self.start_button)
        
        self.stop_button = QPushButton("Arrêter")
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        control_layout.addWidget(self.stop_button)
        
        # Bouton de débogage ajouté
        self.debug_button = QPushButton("Déboguer le scan")
        self.debug_button.clicked.connect(self._debug_scan)
        control_layout.addWidget(self.debug_button)
        
        layout.addLayout(control_layout)
        
        # Label de statut
        self.status_label = QLabel("Prêt")
        layout.addWidget(self.status_label)
        
        # Tableau des résultats
        self.results_table = QTableWidget(0, 6)
        self.results_table.setHorizontalHeaderLabels(["IP", "Nom d'hôte", "MAC", "Fabricant", "Ports ouverts", "Statut"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.results_table.horizontalHeader().setStretchLastSection(True)
        self.results_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.results_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.results_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.results_table.customContextMenuRequested.connect(self._show_context_menu)
        
        layout.addWidget(self.results_table, 1)  # 1 = stretch factor
        
        # Boutons d'action pour les résultats
        actions_layout = QHBoxLayout()
        
        self.clear_button = QPushButton("Effacer les résultats")
        self.clear_button.clicked.connect(self._clear_results)
        actions_layout.addWidget(self.clear_button)
        
        self.export_button = QPushButton("Exporter les résultats")
        self.export_button.clicked.connect(self._export_results)
        actions_layout.addWidget(self.export_button)
        
        self.scan_ports_button = QPushButton("Scanner les ports")
        self.scan_ports_button.clicked.connect(self._scan_ports_of_selected)
        actions_layout.addWidget(self.scan_ports_button)
        
        # Bouton de suppression de tous les appareils
        self.delete_all_button = QPushButton("Supprimer tous les appareils")
        self.delete_all_button.clicked.connect(self._delete_all_devices)
        actions_layout.addWidget(self.delete_all_button)
        
        actions_layout.addStretch(1)
        
        self.devices_count_label = QLabel("0 appareil(s) trouvé(s)")
        actions_layout.addWidget(self.devices_count_label)
        
        layout.addLayout(actions_layout)
    
    def _debug_scan(self):
        """Fonction de débogage pour le scan"""
        # Vérifier que la plage IP est valide
        ip_range = self.ip_range_input.text().strip()
        
        try:
            import ipaddress
            network = ipaddress.ip_network(ip_range)
            
            # Afficher des informations de débogage
            debug_info = f"Informations de débogage:\n\n"
            debug_info += f"Plage IP: {ip_range}\n"
            debug_info += f"Nombre d'adresses: {network.num_addresses}\n"
            debug_info += f"Interface sélectionnée: {self.interface_combo.currentText()}\n"
            debug_info += f"Méthode de scan: {self.scan_type_combo.currentText()}\n"
            debug_info += f"Timeout: {self.timeout_spin.value()} secondes\n"
            
            # Tester une connexion simple
            import socket
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                s.close()
                debug_info += f"IP locale: {local_ip}\n"
            except:
                debug_info += "Impossible d'obtenir l'IP locale\n"
            
            # Vérifier les privilèges administrateur
            is_admin = False
            try:
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            except:
                pass
            debug_info += f"Exécuté en tant qu'administrateur: {'Oui' if is_admin else 'Non'}\n"
            
            QMessageBox.information(self, "Debug", debug_info)
            
        except Exception as e:
            QMessageBox.warning(self, "Erreur", f"Erreur lors du débogage: {str(e)}")
        
    def _delete_all_devices(self):
        """Supprimer tous les appareils enregistrés"""
        if not self.discovered_devices:
            QMessageBox.information(self, "Information", "Aucun appareil à supprimer")
            return
            
        reply = QMessageBox.question(
            self,
            "Confirmation",
            f"Êtes-vous sûr de vouloir supprimer TOUS les appareils ({len(self.discovered_devices)}) ?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # Effacer le dictionnaire
            self.discovered_devices.clear()
            
            # Mettre à jour l'interface
            self.results_table.setRowCount(0)
            self.devices_count_label.setText("0 appareil(s) trouvé(s)")
            QMessageBox.information(self, "Succès", "Tous les appareils ont été supprimés")
        
    def _populate_interfaces(self):
        """Remplir la liste des interfaces réseau disponibles"""
        self.interface_combo.clear()
        self.interface_combo.addItem("Toutes", "all")
        
        if not NETIFACES_AVAILABLE:
            self.interface_combo.addItem("Interface réseau par défaut (netifaces non installé)", None)
            return
            
        try:
            interfaces = netifaces.interfaces()
            
            for iface in interfaces:
                try:
                    # Récupérer les adresses de l'interface
                    addrs = netifaces.ifaddresses(iface)
                    
                    # Vérifier si l'interface a une adresse IPv4
                    if netifaces.AF_INET in addrs:
                        for addr in addrs[netifaces.AF_INET]:
                            ip = addr.get('addr')
                            netmask = addr.get('netmask')
                            
                            if ip and netmask and not ip.startswith('127.'):
                                # Ajouter l'interface à la liste
                                self.interface_combo.addItem(f"{iface} ({ip})", {
                                    'name': iface,
                                    'ip': ip,
                                    'netmask': netmask
                                })
                except Exception as e:
                    logger.warning(f"Erreur lors de la récupération des adresses de l'interface {iface}: {e}")
        except Exception as e:
            logger.exception(f"Erreur lors de la récupération des interfaces réseau: {e}")
            self.interface_combo.addItem("Erreur", None)
            
    def _update_ip_range(self):
        """Mettre à jour la plage IP en fonction de l'interface sélectionnée"""
        current_data = self.interface_combo.currentData()
        
        # Si "Toutes" est sélectionné ou si une erreur s'est produite
        if current_data == "all" or current_data is None:
            # Utiliser une plage locale par défaut
            self.ip_range_input.setText("192.168.1.0/24")
            return
            
        try:
            # Calculer la plage IP à partir de l'adresse IP et du masque réseau
            ip = current_data.get('ip')
            netmask = current_data.get('netmask')
            
            if ip and netmask:
                # Convertir l'adresse IP et le masque en entiers
                ip_int = int.from_bytes(socket.inet_aton(ip), byteorder='big')
                mask_int = int.from_bytes(socket.inet_aton(netmask), byteorder='big')
                
                # Calculer l'adresse réseau
                network_int = ip_int & mask_int
                network_ip = socket.inet_ntoa(network_int.to_bytes(4, byteorder='big'))
                
                # Calculer le préfixe du masque réseau (CIDR)
                cidr = bin(mask_int).count('1')
                
                # Mettre à jour le champ de plage IP
                self.ip_range_input.setText(f"{network_ip}/{cidr}")
        except Exception as e:
            logger.exception(f"Erreur lors du calcul de la plage IP: {e}")
            self.ip_range_input.setText("192.168.1.0/24")
            
    def start_scan(self):
        """Démarrer le scan réseau"""
        # Récupérer les paramètres
        ip_range = self.ip_range_input.text().strip()
        scan_type = self.scan_type_combo.currentText().lower()
        timeout = self.timeout_spin.value()
        
        # Vérifier si un scan de ports est demandé
        scan_ports = []
        if self.port_scan_check.isChecked():
            port_str = self.port_scan_input.text().strip()
            if port_str:
                try:
                    # Extraire les ports (peut être séparés par des virgules ou des espaces)
                    port_list = [p.strip() for p in port_str.replace(',', ' ').split()]
                    scan_ports = [int(p) for p in port_list if p.isdigit() and 1 <= int(p) <= 65535]
                except Exception as e:
                    logger.warning(f"Format de ports invalide: {e}")
                    QMessageBox.warning(self, "Erreur", f"Format de ports invalide: {str(e)}")
                    return
            else:
                # Ports communs par défaut
                scan_ports = [21, 22, 23, 25, 80, 443, 445, 3389, 8080, 8443]
        
        try:
            # Vérifier que la plage IP est valide
            ipaddress.ip_network(ip_range)
        except ValueError as e:
            logger.warning(f"Plage IP invalide: {e}")
            QMessageBox.warning(self, "Erreur", f"Plage IP invalide: {str(e)}")
            return
            
        # Réinitialiser l'interface
        self.progress_bar.setValue(0)
        self.scan_time = 0
        self.scan_time_label.setText("00:00")
        self.update_timer.start(1000)  # Mettre à jour chaque seconde
        
        # Créer et démarrer le thread de scan
        self.scan_thread = ScanThread(ip_range, scan_type, timeout, scan_ports)
        
        # Connecter les signaux
        self.scan_thread.progress_updated.connect(self.progress_bar.setValue)
        self.scan_thread.status_updated.connect(self.status_label.setText)
        self.scan_thread.device_discovered.connect(self._on_device_discovered)
        self.scan_thread.scan_finished.connect(self._on_scan_finished)
        
        # Démarrer le scan
        self.scan_thread.start()
        
        # Mettre à jour l'interface
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.interface_combo.setEnabled(False)
        self.ip_range_input.setEnabled(False)
        self.scan_type_combo.setEnabled(False)
        self.timeout_spin.setEnabled(False)
        self.port_scan_check.setEnabled(False)
        self.port_scan_input.setEnabled(False)
        
        logger.info(f"Scan démarré: {ip_range}, type={scan_type}, timeout={timeout}s")
        
    def stop_scan(self):
        """Arrêter le scan en cours"""
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.stop()
            self.status_label.setText("Arrêt du scan en cours...")
            
    def _on_device_discovered(self, device_data):
        """Traitement lors de la découverte d'un appareil"""
        ip = device_data.get('ip')
        if not ip:
            return
            
        # Mettre à jour ou ajouter l'appareil dans le dictionnaire
        self.discovered_devices[ip] = device_data
        
        # Mettre à jour le tableau
        self._update_results_table()
        
        # Mettre à jour le compteur
        self.devices_count_label.setText(f"{len(self.discovered_devices)} appareil(s) trouvé(s)")
        
        # Émettre le signal de découverte pour les autres onglets
        self.device_discovered.emit(device_data)
        
    def _on_scan_finished(self, success):
        """Traitement à la fin du scan"""
        # Arrêter le timer
        self.update_timer.stop()
        
        # Mettre à jour l'interface
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.interface_combo.setEnabled(True)
        self.ip_range_input.setEnabled(True)
        self.scan_type_combo.setEnabled(True)
        self.timeout_spin.setEnabled(True)
        self.port_scan_check.setEnabled(True)
        self.port_scan_input.setEnabled(self.port_scan_check.isChecked())
        
        # Mettre à jour le statut final
        if success:
            self.status_label.setText(f"Scan terminé: {len(self.discovered_devices)} appareil(s) trouvé(s)")
        else:
            self.status_label.setText("Scan arrêté ou erreur")
            
        logger.info(f"Scan terminé: {len(self.discovered_devices)} appareils trouvés")
        
    def _update_scan_time(self):
        """Mettre à jour le temps de scan affiché"""
        self.scan_time = self.scan_time + 1
        minutes = self.scan_time // 60
        seconds = self.scan_time % 60
        self.scan_time_label.setText(f"{minutes:02d}:{seconds:02d}")
        
    def _update_results_table(self):
        """Mettre à jour le tableau des résultats"""
        # Effacer le tableau
        self.results_table.setRowCount(0)
        
        # Remplir avec les appareils découverts
        for ip, device in self.discovered_devices.items():
            row = self.results_table.rowCount()
            self.results_table.insertRow(row)
            
            # IP
            self.results_table.setItem(row, 0, QTableWidgetItem(ip))
            
            # Hostname
            hostname = device.get('hostname', '')
            self.results_table.setItem(row, 1, QTableWidgetItem(hostname))
            
            # MAC
            mac = device.get('mac', '')
            self.results_table.setItem(row, 2, QTableWidgetItem(mac))
            
            # Fabricant
            vendor = device.get('vendor', '')
            self.results_table.setItem(row, 3, QTableWidgetItem(vendor))
            
            # Ports ouverts
            open_ports = device.get('open_ports', [])
            ports_str = ", ".join(map(str, open_ports))
            self.results_table.setItem(row, 4, QTableWidgetItem(ports_str))
            
            # Statut
            status = device.get('status', '')
            self.results_table.setItem(row, 5, QTableWidgetItem(status))
            
        # Ajuster les colonnes
        self.results_table.resizeColumnsToContents()
        
    def _clear_results(self):
        """Effacer les résultats du scan"""
        reply = QMessageBox.question(
            self,
            "Confirmation",
            "Voulez-vous vraiment effacer tous les résultats?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.discovered_devices.clear()
            self.results_table.setRowCount(0)
            self.devices_count_label.setText("0 appareil(s) trouvé(s)")
            self.status_label.setText("Résultats effacés")
            
    def _export_results(self):
        """Exporter les résultats du scan"""
        if not self.discovered_devices:
            QMessageBox.information(self, "Export", "Aucun résultat à exporter")
            return
            
        # Demander le format d'export
        formats = ["CSV", "JSON"]
        format_index = QMessageBox.question(
            self,
            "Format d'export",
            "Dans quel format souhaitez-vous exporter les résultats?",
            *formats
        )
        
        if format_index < 0:
            return
            
        selected_format = formats[format_index]
        
        # Demander le nom du fichier
        file_filter = "Fichiers CSV (*.csv)" if selected_format == "CSV" else "Fichiers JSON (*.json)"
        file_name, _ = QFileDialog.getSaveFileName(
            self,
            "Exporter les résultats",
            "",
            file_filter
        )
        
        if not file_name:
            return
            
        try:
            if selected_format == "CSV":
                self._export_to_csv(file_name)
            else:
                self._export_to_json(file_name)
                
            QMessageBox.information(
                self,
                "Export réussi",
                f"Les résultats ont été exportés vers {file_name}"
            )
        except Exception as e:
            logger.exception(f"Erreur lors de l'export: {e}")
            QMessageBox.critical(
                self,
                "Erreur d'export",
                f"Une erreur s'est produite lors de l'export: {str(e)}"
            )
            
    def _export_to_csv(self, file_name):
        """Exporter les résultats au format CSV"""
        with open(file_name, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # En-têtes
            writer.writerow(["IP", "Nom d'hôte", "MAC", "Fabricant", "Ports ouverts", "Statut"])
            
            # Données
            for ip, device in self.discovered_devices.items():
                open_ports = device.get('open_ports', [])
                ports_str = ", ".join(map(str, open_ports))
                
                writer.writerow([
                    ip,
                    device.get('hostname', ''),
                    device.get('mac', ''),
                    device.get('vendor', ''),
                    ports_str,
                    device.get('status', '')
                ])
                
    def _export_to_json(self, file_name):
        """Exporter les résultats au format JSON"""
        with open(file_name, 'w', encoding='utf-8') as f:
            json.dump(self.discovered_devices, f, indent=4)
            
    def _show_context_menu(self, position):
        """Afficher un menu contextuel pour le tableau de résultats"""
        selected_rows = self.results_table.selectionModel().selectedRows()
        if not selected_rows:
            return
            
        # Créer le menu
        context_menu = QMenu()
        
        # Actions
        ping_action = context_menu.addAction("Ping")
        ping_action.triggered.connect(lambda: self._ping_selected())
        
        scan_ports_action = context_menu.addAction("Scanner les ports")
        scan_ports_action.triggered.connect(lambda: self._scan_ports_of_selected())
        
        # Sous-menu de copie
        copy_menu = context_menu.addMenu("Copier")
        
        copy_ip_action = copy_menu.addAction("IP")
        copy_ip_action.triggered.connect(lambda: self._copy_to_clipboard(column=0))
        
        copy_mac_action = copy_menu.addAction("MAC")
        copy_mac_action.triggered.connect(lambda: self._copy_to_clipboard(column=2))
        
        # Exécuter le menu
        context_menu.exec_(self.results_table.viewport().mapToGlobal(position))
        
    def _ping_selected(self):
        """Ping l'adresse IP sélectionnée"""
        selected_rows = self.results_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.information(self, "Sélection", "Sélectionnez d'abord un appareil")
            return
            
        row = selected_rows[0].row()
        ip = self.results_table.item(row, 0).text()
        
        # Créer et démarrer un thread de scan pour cette IP
        self.scan_thread = ScanThread(ip, "single_ip", self.timeout_spin.value())
        
        # Connecter les signaux
        self.scan_thread.progress_updated.connect(self.progress_bar.setValue)
        self.scan_thread.status_updated.connect(self.status_label.setText)
        self.scan_thread.device_discovered.connect(self._on_device_discovered)
        self.scan_thread.scan_finished.connect(self._on_scan_finished)
        
        # Démarrer le scan
        self.scan_thread.start()
        
        # Mettre à jour l'interface
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        
        logger.info(f"Ping de l'adresse {ip}")
        
    def _scan_ports_of_selected(self):
        """Scanner les ports de l'adresse IP sélectionnée"""
        selected_rows = self.results_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.information(self, "Sélection", "Sélectionnez d'abord un appareil")
            return
            
        row = selected_rows[0].row()
        ip = self.results_table.item(row, 0).text()
        
        # Afficher la boîte de dialogue de scan de ports
        dialog = PortScanDialog(ip, self)
        if dialog.exec_() == QDialog.Accepted:
            # Récupérer les ports trouvés
            open_ports = dialog.get_ports()
            
            # Mettre à jour les informations de l'appareil
            if ip in self.discovered_devices:
                self.discovered_devices[ip]['open_ports'] = open_ports
                
                # Mettre à jour le tableau
                self.results_table.setItem(row, 4, QTableWidgetItem(", ".join(map(str, open_ports))))
                
    def _copy_to_clipboard(self, column):
        """Copier la valeur d'une cellule dans le presse-papiers"""
        selected_rows = self.results_table.selectionModel().selectedRows()
        if not selected_rows:
            return
            
        row = selected_rows[0].row()
        text = self.results_table.item(row, column).text()
        
        # Copier dans le presse-papiers
        from PyQt5.QtWidgets import QApplication
        QApplication.clipboard().setText(text)
        
    def save_results(self):
        """Exporter les résultats (appelé depuis l'extérieur)"""
        self._export_results()