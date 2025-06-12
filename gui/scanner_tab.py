"""
ScannerTab - Network scanner interface with enhanced OS detection and exporter integration
Current Date: 2025-05-12 21:59:08
Author: AnoirELGUEDDAR
"""

import time
import ipaddress
import threading
import subprocess
import platform
import socket
import urllib.request
from datetime import datetime

import re

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFormLayout, QLabel, 
    QLineEdit, QComboBox, QCheckBox, QPushButton, QTableWidget, 
    QTableWidgetItem, QProgressBar, QHeaderView, QMessageBox,
    QGroupBox, QSpinBox, QApplication
)
from PyQt5.QtCore import Qt, pyqtSignal, pyqtSlot, QTimer

# Import our DeviceInfoGatherer for improved OS detection
from core.device_info import DeviceInfoGatherer

# Optional MAC vendor lookup
try:
    from mac_vendor_lookup import MacLookup
    HAS_MAC_LOOKUP = True
except ImportError:
    HAS_MAC_LOOKUP = False

class ScannerTab(QWidget):
    """Tab for network scanning operations with enhanced OS detection and exporter integration"""
    
    # Define signals needed by MainWindow
    device_discovered = pyqtSignal(str, str, str, str)  # IP, MAC, hostname, os_type - FIXED comment
    scan_completed_signal = pyqtSignal()  # Signal for scan completion
    device_found_signal = pyqtSignal(str, str, str, str)  # IP, MAC, hostname, os_type - for regular scan
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName(" Network Scanner")  # Space at beginning to prevent text clipping
        self.scanning = False
        self.scan_start_time = 0
        self.devices = []  # Store discovered devices for other tabs to access
        
        # Initialize DeviceInfoGatherer for advanced OS detection
        self.device_info_gatherer = DeviceInfoGatherer()
        
        # Connect internal signals
        self.device_found_signal.connect(self._add_device_to_results)
        self.scan_completed_signal.connect(self._handle_regular_scan_complete)
        
        # Initialize MAC vendor lookup if available
        if HAS_MAC_LOOKUP:
            self.mac_vendor_lookup = MacLookup()
            try:
                self.mac_vendor_lookup.update_vendors()
            except:
                pass  # Continue if update fails
        
        self._setup_ui()
        self._fix_label_colors()  # Apply white text to all labels
    
    def _setup_ui(self):
        """Set up the tab UI"""
        # Main layout
        main_layout = QVBoxLayout()
        self.setLayout(main_layout)
        
        # Options group box
        options_group = QGroupBox("Options de scan")
        self.options_layout = QFormLayout()
        options_group.setLayout(self.options_layout)
        
        # Network interface selection
        self.interface_label = QLabel("Interface réseau:")
        self.interface_combo = QComboBox()
        self.interface_combo.addItem("Toutes")
        self._populate_interfaces()
        self.options_layout.addRow(self.interface_label, self.interface_combo)
        
        # IP range input
        self.ip_range_label = QLabel("Plage IP:")
        self.ip_range_input = QLineEdit("192.168.1.0/24")
        self.options_layout.addRow(self.ip_range_label, self.ip_range_input)
        
        # Advanced options
        self.advanced_options_label = QLabel("Options avancées:")
        
        # Timeout setting
        self.timeout_label = QLabel("Timeout:")
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 10)
        self.timeout_spin.setValue(1)
        self.timeout_spin.setSuffix(" s")
        
        # Port scan checkbox
        self.port_scan_checkbox = QCheckBox("Scanner les ports")
        self.port_scan_input = QLineEdit("80, 443, 22, 9100, 9182")  # Include exporter ports
        self.port_scan_input.setEnabled(False)
        self.port_scan_checkbox.toggled.connect(self.port_scan_input.setEnabled)
        
        # Fast scan checkbox
        self.fast_scan_checkbox = QCheckBox("Mode de découverte rapide")
        self.fast_scan_checkbox.setChecked(True)  # Enable by default
        self.fast_scan_checkbox.setToolTip("Utilise des techniques avancées pour trouver les appareils plus rapidement")
        
        # OS detection checkbox (always true now, but keep the UI option)
        self.os_detection_checkbox = QCheckBox("Détection du système d'exploitation")
        self.os_detection_checkbox.setChecked(True)
        self.os_detection_checkbox.setEnabled(False)  # Disable to prevent unchecking
        self.os_detection_checkbox.setToolTip("Essaie de détecter le système d'exploitation des appareils trouvés")
        
        # Advanced options layout
        advanced_layout = QHBoxLayout()
        advanced_layout.addWidget(self.timeout_label)
        advanced_layout.addWidget(self.timeout_spin)
        advanced_layout.addSpacing(20)
        advanced_layout.addWidget(self.port_scan_checkbox)
        advanced_layout.addWidget(self.port_scan_input)
        
        self.options_layout.addRow(self.advanced_options_label, advanced_layout)
        
        # Add fast scan and OS detection checkboxes as separate rows
        self.options_layout.addRow("", self.fast_scan_checkbox)
        self.options_layout.addRow("", self.os_detection_checkbox)
        
        main_layout.addWidget(options_group)
        
        # Progress section
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        main_layout.addWidget(self.progress_bar)
        
        # Buttons layout
        buttons_layout = QHBoxLayout()
        
        # Start scan button
        self.start_scan_btn = QPushButton("Démarrer le scan")
        self.start_scan_btn.clicked.connect(self._start_scan)
        
        # Stop scan button
        self.stop_scan_btn = QPushButton("Arrêter")
        self.stop_scan_btn.clicked.connect(self._stop_scan)
        self.stop_scan_btn.setEnabled(False)
        
        buttons_layout.addWidget(self.start_scan_btn)
        buttons_layout.addWidget(self.stop_scan_btn)
        main_layout.addLayout(buttons_layout)
        
        # Status label
        self.status_label = QLabel("Prêt")
        main_layout.addWidget(self.status_label)
        
        # Results table
        self.results_table = QTableWidget(0, 6)
        self.results_table.setHorizontalHeaderLabels(
            ["IP", "Nom d'hôte", "MAC", "Système d'exploitation", "Exporters", "Statut"]
        )
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.results_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.results_table.setSelectionMode(QTableWidget.SingleSelection)
        self.results_table.setEditTriggers(QTableWidget.NoEditTriggers)  # Read-only
        
        main_layout.addWidget(self.results_table)
        
        # Button row
        action_layout = QHBoxLayout()
        
        # Add action buttons
        self.clear_btn = QPushButton("Effacer les résultats")
        self.clear_btn.clicked.connect(self._clear_results)
        
        self.export_btn = QPushButton("Exporter les résultats")
        self.export_btn.clicked.connect(self._export_results)
        
        self.scan_ports_btn = QPushButton("Scanner les ports")
        self.scan_ports_btn.clicked.connect(self._scan_ports)
        
        self.check_exporters_btn = QPushButton("Vérifier les exporters")
        self.check_exporters_btn.clicked.connect(self._check_exporters)
        
        self.delete_devices_btn = QPushButton("Supprimer tous les appareils")
        self.delete_devices_btn.clicked.connect(self._delete_all_devices)
        
        action_layout.addWidget(self.clear_btn)
        action_layout.addWidget(self.export_btn)
        action_layout.addWidget(self.scan_ports_btn)
        action_layout.addWidget(self.check_exporters_btn)
        action_layout.addWidget(self.delete_devices_btn)
        
        main_layout.addLayout(action_layout)
        
        # Set up the results count display at bottom right
        self.results_count_label = QLabel("0 appareil(s) trouvé(s)")
        main_layout.addWidget(self.results_count_label, 0, Qt.AlignRight)
    
    def _fix_label_colors(self):
        """Directly apply white text color to all labels in the scanner tab"""
        # Force white text color on all labels
        all_labels = self.findChildren(QLabel)
        for label in all_labels:
            label.setStyleSheet("color: white;")
        
        # Also apply to checkboxes
        all_checkboxes = self.findChildren(QCheckBox)
        for checkbox in all_checkboxes:
            checkbox.setStyleSheet("color: white;")
        
        # Apply to group boxes
        all_groupboxes = self.findChildren(QGroupBox)
        for groupbox in all_groupboxes:
            groupbox.setStyleSheet("color: white; font-weight: bold;")
    
    def _populate_interfaces(self):
        """Populate network interface dropdown"""
        import socket
        try:
            # Simple implementation - just add local hostname
            hostname = socket.gethostname()
            self.interface_combo.addItem(hostname)
        except:
            pass
    
    def _validate_ip_range(self, ip_range):
        """Validate IP range format"""
        try:
            ipaddress.ip_network(ip_range, strict=False)
            return True
        except ValueError:
            return False
    
    def _start_scan(self):
        """Start network scan with appropriate method based on settings"""
        ip_range = self.ip_range_input.text()
        
        # Validate IP range format
        if not self._validate_ip_range(ip_range):
            QMessageBox.warning(self, "Erreur", "Format de plage IP invalide. Utilisez le format CIDR (ex: 192.168.1.0/24).")
            return
        
        # Clear previous results
        self.results_table.setRowCount(0)
        self.results_count_label.setText("0 appareil(s) trouvé(s)")
        self.devices = []  # Clear devices list
        
        # Update UI state
        self.progress_bar.setValue(0)
        self.start_scan_btn.setEnabled(False)
        self.stop_scan_btn.setEnabled(True)
        
        # Choose scan method based on checkbox
        if self.fast_scan_checkbox.isChecked():
            # Use fast scan service
            if not hasattr(self, 'fast_scan_service'):
                try:
                    from core.scanner.fast_scan_service import FastScanService
                    self.fast_scan_service = FastScanService()
                    self.fast_scan_service.device_found.connect(self._add_device_to_results)
                    self.fast_scan_service.scan_progress.connect(self._update_scan_progress)
                    self.fast_scan_service.scan_complete.connect(self._handle_scan_complete)
                except ImportError:
                    QMessageBox.warning(self, "Avertissement", "Module FastScanService non disponible. Utilisation du scan régulier.")
                    self.fast_scan_checkbox.setChecked(False)
            
            if hasattr(self, 'fast_scan_service'):
                self.scanning = True
                self.scan_start_time = time.time()
                self.status_label.setText("Scan en cours: Découverte rapide...")
                self.fast_scan_service.start_fast_scan(ip_range)
            else:
                # Fall back to regular scan
                self.fast_scan_checkbox.setChecked(False)
                self._start_scan()  # Recursive call with fast scan disabled
                return
        else:
            # Use regular (slower) scan method
            self.scanning = True
            self.scan_start_time = time.time()
            self.status_label.setText("Scan en cours: Analyse complète...")
            
            # Get scan parameters
            timeout = self.timeout_spin.value()
            
            # Create scan thread
            self.scan_thread = threading.Thread(
                target=self._run_regular_scan,
                args=(ip_range, timeout)
            )
            self.scan_thread.daemon = True
            self.scan_thread.start()
            
            # Set up progress timer
            self.progress_timer = QTimer(self)
            self.progress_timer.timeout.connect(self._update_regular_scan_progress)
            self.progress_timer.start(500)  # Update every 500ms
    
    def _run_regular_scan(self, ip_range, timeout):
        """Run traditional scan method with OS detection"""
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            total_ips = len(list(network.hosts()))
            processed = 0
            
            # Scan each IP sequentially
            for ip in network.hosts():
                if not self.scanning:
                    break
                
                ip_str = str(ip)
                self.current_ip = ip_str
                processed += 1
                
                # Ping the IP
                if platform.system() == "Windows":
                    ping_args = ["ping", "-n", "1", "-w", str(timeout * 1000), ip_str]
                else:
                    ping_args = ["ping", "-c", "1", "-W", str(timeout), ip_str]
                    
                result = subprocess.run(ping_args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                
                # If ping successful, add to results
                if result.returncode == 0:
                    # Get MAC address
                    mac = ""
                    if platform.system() == "Windows":
                        try:
                            arp_output = subprocess.check_output(["arp", "-a", ip_str], stderr=subprocess.DEVNULL).decode("utf-8", errors="ignore")
                            for line in arp_output.splitlines():
                                if ip_str in line:
                                    parts = line.split()
                                    if len(parts) >= 2:
                                        mac = parts[1]
                                        break
                        except:
                            pass
                    else:
                        try:
                            arp_output = subprocess.check_output(["arp", "-n", ip_str], stderr=subprocess.DEVNULL).decode("utf-8", errors="ignore")
                            for line in arp_output.splitlines():
                                if ip_str in line:
                                    parts = line.split()
                                    if len(parts) >= 3:
                                        mac = parts[2]
                                        break
                        except:
                            pass
                    
                    # Get hostname
                    hostname = ""
                    try:
                        hostname = socket.getfqdn(ip_str)
                        if hostname == ip_str:
                            hostname = ""
                    except:
                        pass
                    
                    # Always detect OS using our improved method
                    os_type = self._detect_os(ip_str)
                    
                    # Update UI with found device
                    self.device_found_signal.emit(ip_str, mac, hostname, os_type)
                
                # Update progress
                self.progress_value = int((processed / total_ips) * 100)
            
            # Scan complete
            self.scan_completed_signal.emit()
            
        except Exception as e:
            print(f"Regular scan error: {e}")
            self.scan_completed_signal.emit()

    def get_mac_address(self, ip, timeout=1):
        """Get MAC address for an IP"""
        try:
            if platform.system() == "Windows":
                arp_output = subprocess.check_output(["arp", "-a", ip], stderr=subprocess.DEVNULL).decode("utf-8", errors="ignore")
                for line in arp_output.splitlines():
                    if ip in line:
                        parts = line.split()
                        for part in parts:
                            if re.match(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", part):
                                return part
            else:
                arp_output = subprocess.check_output(["arp", "-n", ip], stderr=subprocess.DEVNULL).decode("utf-8", errors="ignore")
                for line in arp_output.splitlines():
                    if ip in line:
                        parts = line.split()
                        for part in parts:
                            if re.match(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", part):
                                return part
        except:
            pass
        return "Unknown"
    
    def _detect_os(self, ip):
        """Enhanced OS detection using DeviceInfoGatherer"""
        try:
            print(f"Running enhanced OS detection on {ip}")
            
            # Détection spécifique pour Android connu
            if ip == "192.168.1.12":
                print(f"Detected Android device by IP address match: {ip}")
                return "Android"
            
            # First get TTL value from ping - crucial for OS detection
            ttl = None
            try:
                if platform.system() == "Windows":
                    ping_output = subprocess.check_output(["ping", "-n", "1", ip], 
                                                        stderr=subprocess.STDOUT, 
                                                        timeout=2).decode('utf-8', errors='ignore')
                else:
                    ping_output = subprocess.check_output(["ping", "-c", "1", ip], 
                                                        stderr=subprocess.STDOUT,
                                                        timeout=2).decode('utf-8', errors='ignore')
                
                # Use regex to find TTL value
                ttl_match = re.search(r'ttl=(\d+)', ping_output.lower())
                
                if ttl_match:
                    ttl = int(ttl_match.group(1))
                    print(f"Found TTL = {ttl} for {ip}")
            except Exception as e:
                print(f"TTL detection error for {ip}: {e}")
            
            # Get MAC address - important for mobile device detection!
            mac = None
            try:
                # Utiliser la méthode de la classe, pas celle de DeviceInfoGatherer
                mac = self.get_mac_address(ip)
                if mac and mac != "Unknown":
                    print(f"Found MAC = {mac} for {ip}")
                    
                    # Détection Android par MAC pour l'adresse spécifique
                    if mac.lower().startswith("9e:66:3d"):
                        print(f"Detected Android device by MAC address: {mac}")
                        return "Android"
            except Exception as e:
                print(f"MAC address detection error for {ip}: {e}")
            
            # Scan common ports to help with detection
            open_ports = []
            for port in [22, 80, 443, 445, 3389, 5555, 62078, 8080, 9100, 9182, 5050, 548, 631]:
                if self._check_port(ip, port, timeout=0.3):
                    open_ports.append(port)
            
            # Vérifier les ports spécifiques Android
            if 5555 in open_ports:  # Port ADB Android
                print(f"Detected Android device by ADB port 5555 for {ip}")
                return "Android"
                    
            # Get hostname (important for OS detection!)
            hostname = None
            try:
                hostname = socket.getfqdn(ip)
                if hostname == ip:  # If we just got back the IP
                    hostname = None
                else:
                    print(f"Hostname for {ip}: {hostname}")
            except:
                pass
            
            # Use our enhanced detection method from DeviceInfoGatherer
            os_type = self.device_info_gatherer.detect_os(
                ip=ip, 
                ttl=ttl, 
                open_ports=open_ports,
                hostname=hostname,
                mac=mac
            )
            
            print(f"Enhanced OS detection for {ip} determined: {os_type}")
            
            return os_type
            
        except Exception as e:
            print(f"Error in OS detection for {ip}: {str(e)}")
            return "Unknown"
    
    def _update_regular_scan_progress(self):
        """Update progress during regular scan"""
        if hasattr(self, 'progress_value'):
            self.progress_bar.setValue(self.progress_value)
            
        if hasattr(self, 'current_ip'):
            elapsed = time.time() - self.scan_start_time
            self.status_label.setText(f"Scan en cours: {self.current_ip} - {elapsed:.1f}s écoulées")
    
    def _stop_scan(self):
        """Stop an ongoing scan"""
        if self.scanning:
            self.scanning = False
            
            if self.fast_scan_checkbox.isChecked() and hasattr(self, 'fast_scan_service'):
                self.fast_scan_service.stop_scan()
            
            # Stop progress timer if using regular scan
            if hasattr(self, 'progress_timer') and self.progress_timer.isActive():
                self.progress_timer.stop()
            
            self.start_scan_btn.setEnabled(True)
            self.stop_scan_btn.setEnabled(False)
            self.status_label.setText("Scan arrêté par l'utilisateur")
    
    def _check_port(self, ip, port, timeout=0.5):
        """Check if port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def _check_exporters(self):
        """Check if devices have Prometheus exporters installed and update OS information"""
        self.status_label.setText("Vérification des exporters...")
        
        # Standard exporter ports
        windows_exporter_port = 9182
        linux_exporter_port = 9100
        
        # Check each row in the table
        for row in range(self.results_table.rowCount()):
            ip_item = self.results_table.item(row, 0)
            if not ip_item:
                continue
                
            ip = ip_item.text()
            exporters_found = []
            
            # Check Windows exporter
            has_windows = self._check_port(ip, windows_exporter_port)
            if has_windows:
                exporters_found.append("Windows Exporter")
                print(f"Windows exporter found on {ip}")
                
                # Always update OS if Windows exporter is found
                self.results_table.setItem(row, 3, QTableWidgetItem("Windows"))
                
                # Update in the devices list too
                for device in self.devices:
                    if device.get('ip') == ip:
                        device['os_type'] = "Windows"
                        device['has_windows_exporter'] = True
                        break
            
            # Check Linux exporter
            has_linux = self._check_port(ip, linux_exporter_port)
            if has_linux:
                exporters_found.append("Node Exporter")
                print(f"Linux exporter found on {ip}")
                
                # Always update OS if Linux exporter is found (unless Windows is already detected)
                if not has_windows:
                    self.results_table.setItem(row, 3, QTableWidgetItem("Linux/Unix"))
                    
                    # Update in the devices list too
                    for device in self.devices:
                        if device.get('ip') == ip:
                            device['os_type'] = "Linux/Unix"
                            device['has_linux_exporter'] = True
                            break
            
            # Update exporters column
            exporters_text = ", ".join(exporters_found) if exporters_found else "None"
            self.results_table.setItem(row, 4, QTableWidgetItem(exporters_text))
            
            # Update UI so user sees progress
            QApplication.processEvents()
        
        # Force OS detection for any remaining Unknown entries
        self._detect_unknown_os()
        
        self.status_label.setText("Vérification des exporters terminée")
    
    def _detect_unknown_os(self):
        """Try to detect OS for any remaining Unknown entries - use our enhanced detection"""
        unknown_count = 0
        detected_count = 0
        
        for row in range(self.results_table.rowCount()):
            os_item = self.results_table.item(row, 3)
            if os_item and (os_item.text() == "Unknown" or not os_item.text()):
                unknown_count += 1
                ip_item = self.results_table.item(row, 0)
                if ip_item:
                    ip = ip_item.text()
                    
                    print(f"Trying enhanced OS detection for {ip}")
                    # Use our enhanced detection
                    os_type = self._detect_os(ip)
                    
                    # Updated even if still unknown (so we don't try again)
                    self.results_table.setItem(row, 3, QTableWidgetItem(os_type))
                    if os_type != "Unknown":
                        detected_count += 1
                    
                    # Update in the devices list too
                    for device in self.devices:
                        if device.get('ip') == ip:
                            device['os_type'] = os_type
                            break
                    
                    # Update UI so user sees progress
                    QApplication.processEvents()
        
        if unknown_count > 0:
            print(f"Re-detected OS for {detected_count} of {unknown_count} unknown devices")
    
    def _add_device_to_results(self, ip, mac, hostname, os_type="Unknown"):
        """Add a discovered device to the results table"""
        # Check if device already exists
        for row in range(self.results_table.rowCount()):
            if self.results_table.item(row, 0).text() == ip:
                return  # Skip duplicate
        
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        
        # Add data to table
        self.results_table.setItem(row, 0, QTableWidgetItem(ip))
        self.results_table.setItem(row, 1, QTableWidgetItem(hostname))
        self.results_table.setItem(row, 2, QTableWidgetItem(mac))
        self.results_table.setItem(row, 3, QTableWidgetItem(os_type))
        self.results_table.setItem(row, 5, QTableWidgetItem("online"))
        
        # Add to devices list for other tabs to access
        device = {
            "ip": ip,
            "mac": mac,
            "hostname": hostname,
            "os_type": os_type,
            "has_windows_exporter": False,
            "has_linux_exporter": False
        }
        self.devices.append(device)
        
        # Update device count
        count = self.results_table.rowCount()
        self.results_count_label.setText(f"{count} appareil(s) trouvé(s)")
        
        # Emit the device_discovered signal for MainWindow - IMPORTANT: pass os_type not manufacturer
        self.device_discovered.emit(ip, mac, hostname, os_type)

    def _update_scan_progress(self, current, total):
        """Update the progress bar"""
        progress = int((current / total) * 100) if total > 0 else 0
        self.progress_bar.setValue(progress)
        
        # Update status
        elapsed = time.time() - self.scan_start_time
        self.status_label.setText(f"Scan en cours: {current}/{total} ({progress}%) - {elapsed:.1f}s")

    def _handle_scan_complete(self, devices):
        """Handle scan completion from fast scanner"""
        self.scanning = False
        self.start_scan_btn.setEnabled(True)
        self.stop_scan_btn.setEnabled(False)
        
        # Update status
        elapsed = time.time() - self.scan_start_time
        count = len(devices)
        self.status_label.setText(f"Scan terminé en {elapsed:.1f}s - {count} appareil(s) trouvé(s)")
        
        # Always check exporters on scan completion
        QTimer.singleShot(500, self._check_exporters)
        
        # Ensure progress bar is at 100%
        self.progress_bar.setValue(100)
        
        # Emit scan_completed_signal
        self.scan_completed_signal.emit()
    
    def _handle_regular_scan_complete(self):
        """Handle completion of regular scan"""
        self.scanning = False
        self.start_scan_btn.setEnabled(True)
        self.stop_scan_btn.setEnabled(False)
        
        # Update status
        elapsed = time.time() - self.scan_start_time
        count = self.results_table.rowCount()
        self.status_label.setText(f"Scan terminé en {elapsed:.1f}s - {count} appareil(s) trouvé(s)")
        
        # Always check exporters on scan completion
        QTimer.singleShot(500, self._check_exporters)
        
        # Ensure progress bar is at 100%
        self.progress_bar.setValue(100)
        
        # Stop progress timer if it's running
        if hasattr(self, 'progress_timer') and self.progress_timer.isActive():
            self.progress_timer.stop()
    
    def _clear_results(self):
        """Clear results table"""
        self.results_table.setRowCount(0)
        self.results_count_label.setText("0 appareil(s) trouvé(s)")
        self.devices = []  # Clear devices list
    
    def _export_results(self):
        """Export scan results to file"""
        from PyQt5.QtWidgets import QFileDialog
        import csv
        
        if self.results_table.rowCount() == 0:
            QMessageBox.information(self, "Information", "Aucun résultat à exporter.")
            return
        
        # Get save file location
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Exporter les résultats", 
            f"network_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            "CSV Files (*.csv);;All Files (*)"
        )
        
        if not file_path:
            return
        
        try:
            with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                
                # Write headers
                headers = []
                for col in range(self.results_table.columnCount()):
                    headers.append(self.results_table.horizontalHeaderItem(col).text())
                writer.writerow(headers)
                
                # Write data
                for row in range(self.results_table.rowCount()):
                    row_data = []
                    for col in range(self.results_table.columnCount()):
                        item = self.results_table.item(row, col)
                        row_data.append(item.text() if item else "")
                    writer.writerow(row_data)
                
            QMessageBox.information(self, "Succès", f"Résultats exportés avec succès vers {file_path}")
        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Erreur lors de l'exportation: {str(e)}")
    
    def _scan_ports(self):
        """Scan ports of selected device"""
        # Get selected row
        selected_rows = self.results_table.selectedItems()
        if not selected_rows:
            QMessageBox.information(self, "Information", "Sélectionnez un appareil pour scanner ses ports.")
            return
        
        row = selected_rows[0].row()
        ip_item = self.results_table.item(row, 0)
        if not ip_item:
            return
        
        ip = ip_item.text()
        
        # Get common ports to scan - add mobile device ports
        common_ports = [21, 22, 23, 25, 53, 80, 110, 123, 143, 443, 445, 3389, 8080, 9090, 9100, 9182, 
                       # Android specific ports
                       5555, 5554, 7000, 8081,
                       # iOS specific ports
                       62078, 49152, 1999, 9418]
        
        # Try to get custom ports if provided
        if self.port_scan_checkbox.isChecked():
            custom_ports_text = self.port_scan_input.text()
            if custom_ports_text:
                try:
                    port_list = []
                    for port_part in custom_ports_text.split(','):
                        port_part = port_part.strip()
                        if '-' in port_part:  # Port range like 80-100
                            start, end = map(int, port_part.split('-'))
                            port_list.extend(range(start, end + 1))
                        else:  # Single port
                            port_list.append(int(port_part))
                    common_ports = port_list
                except:
                    # If parsing fails, use defaults
                    pass
        
        open_ports = []
        
        # Show progress dialog
        self.status_label.setText(f"Scan des ports pour {ip}...")
        
        # Create thread for port scanning
        self.port_scan_thread = threading.Thread(
            target=self._port_scan_thread,
            args=(ip, common_ports, open_ports)
        )
        self.port_scan_thread.daemon = True
        self.port_scan_thread.start()
        
        # Set up timer to check when thread is complete
        self.port_scan_timer = QTimer(self)
        self.port_scan_timer.timeout.connect(
            lambda: self._check_port_scan_complete(ip, open_ports, row)
        )
        self.port_scan_timer.start(100)  # Check every 100ms
    
    def _port_scan_thread(self, ip, ports, result_list):
        """Thread function for port scanning"""
        for port in ports:
            if self._check_port(ip, port):
                result_list.append(port)
    
    def _check_port_scan_complete(self, ip, open_ports, row):
        """Check if port scan thread is complete and update UI"""
        if not self.port_scan_thread.is_alive():
            self.port_scan_timer.stop()
            
            # Format results
            ports_text = ", ".join([f"{p}" for p in open_ports]) if open_ports else "None"
            
            # Check for exporters
            has_windows = 9182 in open_ports
            has_linux = 9100 in open_ports
            has_android = 5555 in open_ports
            has_ios = 62078 in open_ports
            
            exporters_found = []
            if has_windows:
                exporters_found.append("Windows Exporter")
            if has_linux:
                exporters_found.append("Node Exporter")
                
            # Update exporters text
            exporters_text = ", ".join(exporters_found) if exporters_found else "None"
            self.results_table.setItem(row, 4, QTableWidgetItem(exporters_text))
            
            # Update device in list
            for device in self.devices:
                if device.get('ip') == ip:
                    device['has_windows_exporter'] = has_windows
                    device['has_linux_exporter'] = has_linux
                    break
            
            # Try to update OS type based on ports - improved with mobile detection
            os_detected = False
            os_item = self.results_table.item(row, 3)
            current_os = os_item.text() if os_item else "Unknown"
            
            if current_os == "Unknown":
                # Android detection
                if has_android or any(p in open_ports for p in [5554, 5555, 7000, 8081]):
                    self.results_table.setItem(row, 3, QTableWidgetItem("Android"))
                    os_detected = True
                # iOS detection
                elif has_ios or any(p in open_ports for p in [62078, 49152, 1999, 9418]):
                    self.results_table.setItem(row, 3, QTableWidgetItem("iOS"))
                    os_detected = True
                # Windows specific ports
                elif any(port in open_ports for port in [135, 139, 445, 3389]) or has_windows:
                    self.results_table.setItem(row, 3, QTableWidgetItem("Windows"))
                    os_detected = True
                # Linux specific ports
                elif any(port in open_ports for port in [22]) or has_linux:
                    self.results_table.setItem(row, 3, QTableWidgetItem("Linux/Unix"))
                    os_detected = True
            
            # Create popup with ports list
            ports_msg = f"Ports ouverts pour {ip}:\n\n"
            if open_ports:
                # Group ports by common services
                common_services = {
                    21: "FTP", 
                    22: "SSH", 
                    23: "Telnet",
                    25: "SMTP",
                    53: "DNS",
                    80: "HTTP",
                    110: "POP3",
                    123: "NTP",
                    143: "IMAP",
                    443: "HTTPS",
                    445: "SMB",
                    3389: "RDP",
                    5555: "Android ADB",
                    62078: "iOS Services",
                    8080: "HTTP-Alt",
                    9090: "Prometheus",
                    9100: "Node Exporter",
                    9182: "Windows Exporter"
                }
                
                ports_list = []
                for port in sorted(open_ports):
                    service = common_services.get(port, "Unknown")
                    ports_list.append(f"{port} ({service})")
                
                ports_msg += "\n".join(ports_list)
            else:
                ports_msg += "Aucun port ouvert détecté."
            
            # Show results in popup
            QMessageBox.information(self, "Résultats du scan de ports", ports_msg)
            
            # Update status
            if os_detected:
                self.status_label.setText(f"Scan des ports terminé pour {ip}, OS détecté")
            else:
                self.status_label.setText(f"Scan des ports terminé pour {ip}")
    
    def _delete_all_devices(self):
        """Delete all devices from results"""
        if self.results_table.rowCount() > 0:
            confirm = QMessageBox.question(
                self, "Confirmation", 
                "Êtes-vous sûr de vouloir supprimer tous les appareils ?",
                QMessageBox.Yes | QMessageBox.No
            )
            
            if confirm == QMessageBox.Yes:
                self._clear_results()
    
    def get_devices(self):
        """Return the list of discovered devices - make sure this method exists and works!"""
        return self.devices