"""
Scanner tab module for Network Scanner application.
Manages the UI for network scanning operations and results display.
"""

import os
import json
import ipaddress
import threading
import time
from datetime import datetime
from typing import Dict, List, Any, Optional

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, 
                           QLabel, QLineEdit, QPushButton, QComboBox, 
                           QTableWidget, QTableWidgetItem, QHeaderView, 
                           QProgressBar, QGroupBox, QCheckBox, QSpinBox,
                           QTabWidget, QTextEdit, QSplitter, QDialog,
                           QMessageBox, QMenu, QAction, QFileDialog,
                           QRadioButton, QButtonGroup, QDialogButtonBox,
                           QFormLayout)
from PyQt5.QtCore import Qt, pyqtSignal, QTimer, QThread, QSize
from PyQt5.QtGui import QColor, QIcon

from core.network_scanner import NetworkScanner
from core.network_utils import get_network_interfaces, get_local_ip
from core.device_info import DeviceInfoGatherer
from core.messaging.message_manager import MessageManager
from gui.messaging_tab import NewMessageDialog
from core.remote.device_manager import DeviceManager
from utils.logger import get_logger

logger = get_logger(__name__)

# Status colors
COLOR_ONLINE = QColor(200, 255, 200)    # Light green
COLOR_OFFLINE = QColor(255, 200, 200)   # Light red
COLOR_UNKNOWN = QColor(200, 200, 200)   # Light gray
COLOR_SCANNING = QColor(200, 200, 255)  # Light blue

class ScanWorker(QThread):
    """Worker thread for network scanning."""
    
    progress_updated = pyqtSignal(float, str, int)
    scan_complete = pyqtSignal(dict)
    scan_error = pyqtSignal(str)
    
    def __init__(self, scan_type, target, options=None):
        super().__init__()
        self.scan_type = scan_type
        self.target = target
        self.options = options or {}
        self.scanner = NetworkScanner()
        self.running = False
    
    def run(self):
        """Run the scan in a separate thread."""
        self.running = True
        result = {}
        
        try:
            if self.scan_type == 'ping':
                result = self.scanner.ping_sweep(
                    self.target, 
                    callback=self.progress_callback
                )
            elif self.scan_type == 'arp':
                result = self.scanner.arp_scan(
                    self.options.get('interface', ''), 
                    self.target,
                    callback=self.progress_callback
                )
            elif self.scan_type == 'port':
                result = self.scanner.port_scan(
                    self.target,
                    self.options.get('ports', '1-1024'),
                    callback=self.progress_callback
                )
            
            if self.running:  # Check if scan wasn't cancelled
                self.scan_complete.emit(result)
        
        except Exception as e:
            logger.error(f"Scan error: {e}")
            self.scan_error.emit(str(e))
    
    def progress_callback(self, progress, current_item, count):
        """Callback function for scan progress updates."""
        if self.running:
            self.progress_updated.emit(progress, current_item, count)
    
    def stop(self):
        """Stop the scan."""
        self.running = False
        if hasattr(self.scanner, 'stop_scan'):
            self.scanner.stop_scan()


class CustomScanDialog(QDialog):
    """Dialog for configuring a custom scan."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Custom Scan Configuration")
        self.resize(500, 400)
        self.setup_ui()
    
    def setup_ui(self):
        """Set up the dialog UI."""
        layout = QVBoxLayout(self)
        
        # Scan type selection
        type_group = QGroupBox("Scan Type")
        type_layout = QVBoxLayout(type_group)
        
        self.type_radio_group = QButtonGroup(self)
        self.ping_radio = QRadioButton("Ping Sweep")
        self.arp_radio = QRadioButton("ARP Scan")
        self.port_radio = QRadioButton("Port Scan")
        self.custom_radio = QRadioButton("Custom Scan")
        
        self.type_radio_group.addButton(self.ping_radio, 0)
        self.type_radio_group.addButton(self.arp_radio, 1)
        self.type_radio_group.addButton(self.port_radio, 2)
        self.type_radio_group.addButton(self.custom_radio, 3)
        
        type_layout.addWidget(self.ping_radio)
        type_layout.addWidget(self.arp_radio)
        type_layout.addWidget(self.port_radio)
        type_layout.addWidget(self.custom_radio)
        
        self.ping_radio.setChecked(True)
        layout.addWidget(type_group)
        
        # Target configuration
        target_group = QGroupBox("Target")
        target_layout = QFormLayout(target_group)
        
        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText("192.168.1.0/24")
        target_layout.addRow("Network/IP:", self.target_edit)
        
        self.interface_combo = QComboBox()
        target_layout.addRow("Interface:", self.interface_combo)
        
        # Fill interface combo
        interfaces = get_network_interfaces()
        for iface, ip in interfaces.items():
            self.interface_combo.addItem(f"{iface} ({ip})", iface)
        
        layout.addWidget(target_group)
        
        # Port scan options
        port_group = QGroupBox("Port Scan Options")
        port_layout = QFormLayout(port_group)
        
        self.ports_edit = QLineEdit()
        self.ports_edit.setPlaceholderText("1-1024,3389,8080")
        port_layout.addRow("Ports:", self.ports_edit)
        
        self.scan_mode_combo = QComboBox()
        self.scan_mode_combo.addItems(["SYN Scan", "Connect Scan", "UDP Scan"])
        port_layout.addRow("Scan Mode:", self.scan_mode_combo)
        
        layout.addWidget(port_group)
        
        # Advanced options
        advanced_group = QGroupBox("Advanced Options")
        advanced_layout = QFormLayout(advanced_group)
        
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setMinimum(1)
        self.timeout_spin.setMaximum(60)
        self.timeout_spin.setValue(5)
        advanced_layout.addRow("Timeout (s):", self.timeout_spin)
        
        self.threads_spin = QSpinBox()
        self.threads_spin.setMinimum(1)
        self.threads_spin.setMaximum(100)
        self.threads_spin.setValue(10)
        advanced_layout.addRow("Threads:", self.threads_spin)
        
        self.verbose_check = QCheckBox("Verbose Output")
        advanced_layout.addRow("", self.verbose_check)
        
        layout.addWidget(advanced_group)
        
        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        
        # Connect signals
        self.type_radio_group.buttonClicked.connect(self._update_ui)
        self._update_ui()
    
    def _update_ui(self):
        """Update UI based on selected scan type."""
        scan_type = self.type_radio_group.checkedId()
        
        # Enable/disable port options
        self.ports_edit.setEnabled(scan_type == 2)  # Port scan
        self.scan_mode_combo.setEnabled(scan_type == 2)  # Port scan
        
        # Enable/disable interface selection
        self.interface_combo.setEnabled(scan_type == 1)  # ARP scan
    
    def get_config(self):
        """Get the scan configuration."""
        scan_type = self.type_radio_group.checkedId()
        
        if scan_type == 0:
            scan_type_name = 'ping'
        elif scan_type == 1:
            scan_type_name = 'arp'
        elif scan_type == 2:
            scan_type_name = 'port'
        else:
            scan_type_name = 'custom'
        
        config = {
            'type': scan_type_name,
            'target': self.target_edit.text(),
            'interface': self.interface_combo.currentData(),
            'ports': self.ports_edit.text(),
            'timeout': self.timeout_spin.value(),
            'threads': self.threads_spin.value(),
            'verbose': self.verbose_check.isChecked(),
            'scan_mode': self.scan_mode_combo.currentText()
        }
        
        return config


class ScanTab(QWidget):
    """Tab for network scanning functionality."""
    
    scan_started = pyqtSignal()
    scan_completed = pyqtSignal(dict)
    scan_error = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        
        # Initialize variables
        self.scanner = NetworkScanner()
        self.scan_worker = None
        self.scan_results = {}
        self.selected_device = None
        
        # Set up UI
        self._setup_ui()
    
    def _setup_ui(self):
        """Set up the tab UI."""
        main_layout = QVBoxLayout(self)
        
        # Top section - Scan controls
        control_group = QGroupBox("Scan Configuration")
        control_layout = QGridLayout(control_group)
        
        # Row 1
        control_layout.addWidget(QLabel("Target:"), 0, 0)
        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText("192.168.1.0/24")
        control_layout.addWidget(self.target_edit, 0, 1, 1, 2)
        
        # Row 2
        control_layout.addWidget(QLabel("Scan Type:"), 1, 0)
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems(["Ping Sweep", "ARP Scan", "Port Scan", "Custom Scan"])
        self.scan_type_combo.currentIndexChanged.connect(self._on_scan_type_changed)
        control_layout.addWidget(self.scan_type_combo, 1, 1)
        
        # Row 3
        self.options_label = QLabel("Interface:")
        control_layout.addWidget(self.options_label, 2, 0)
        
        self.interface_combo = QComboBox()
        self.port_edit = QLineEdit()
        self.port_edit.setPlaceholderText("1-1024,3389,8080")
        
        # Hide port edit initially
        self.port_edit.hide()
        
        # Fill interface combo
        interfaces = get_network_interfaces()
        for iface, ip in interfaces.items():
            self.interface_combo.addItem(f"{iface} ({ip})", iface)
        
        control_layout.addWidget(self.interface_combo, 2, 1)
        control_layout.addWidget(self.port_edit, 2, 1)
        
        # Scan controls
        self.start_scan_btn = QPushButton("Start Scan")
        self.start_scan_btn.clicked.connect(self.start_scan)
        control_layout.addWidget(self.start_scan_btn, 2, 2)
        
        self.stop_scan_btn = QPushButton("Stop")
        self.stop_scan_btn.clicked.connect(self.stop_scan)
        self.stop_scan_btn.setEnabled(False)
        control_layout.addWidget(self.stop_scan_btn, 1, 2)
        
        # Configuration button for custom scan
        self.config_btn = QPushButton("Configure...")
        self.config_btn.clicked.connect(self._show_custom_config)
        self.config_btn.hide()  # Hide initially
        control_layout.addWidget(self.config_btn, 0, 3)
        
        main_layout.addWidget(control_group)
        
        # Progress bar
        self.progress_group = QGroupBox("Progress")
        progress_layout = QVBoxLayout(self.progress_group)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        progress_layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("Ready")
        progress_layout.addWidget(self.status_label)
        
        main_layout.addWidget(self.progress_group)
        
        # Results section
        results_group = QGroupBox("Scan Results")
        results_layout = QVBoxLayout(results_group)
        
        self.results_table = QTableWidget(0, 5)
        self.results_table.setHorizontalHeaderLabels(["IP Address", "Hostname", "Status", "MAC Address", "Ports"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.results_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.results_table.setSelectionMode(QTableWidget.SingleSelection)
        self.results_table.itemDoubleClicked.connect(self._on_item_double_clicked)
        self.results_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.results_table.customContextMenuRequested.connect(self._show_context_menu)
        
        results_layout.addWidget(self.results_table)
        
        # Bottom buttons
        btn_layout = QHBoxLayout()
        
        self.export_btn = QPushButton("Export Results")
        self.export_btn.clicked.connect(self._export_results)
        btn_layout.addWidget(self.export_btn)
        
        self.clear_btn = QPushButton("Clear Results")
        self.clear_btn.clicked.connect(self._clear_results)
        btn_layout.addWidget(self.clear_btn)
        
        self.view_details_btn = QPushButton("View Details")
        self.view_details_btn.clicked.connect(self._view_device_details)
        btn_layout.addWidget(self.view_details_btn)
        
        self.message_btn = QPushButton("Send as Message")
        self.message_btn.clicked.connect(self._send_results_as_message)
        self.message_btn.setIcon(QIcon(os.path.join("resources", "icons", "message.png")))
        btn_layout.addWidget(self.message_btn)
        
        results_layout.addLayout(btn_layout)
        
        main_layout.addWidget(results_group)
        
        # Initial state setup
        self._on_scan_type_changed(0)
        
        # Calculate a good default target based on local IP
        local_ip = get_local_ip()
        if local_ip:
            try:
                # Convert IP to network with /24 subnet
                ip_parts = local_ip.split('.')
                network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
                self.target_edit.setText(network)
            except:
                pass
    
    def _on_scan_type_changed(self, index):
        """Handle scan type combo change."""
        if index == 0:  # Ping Sweep
            self.options_label.setText("Interface:")
            self.interface_combo.show()
            self.port_edit.hide()
            self.config_btn.hide()
        elif index == 1:  # ARP Scan
            self.options_label.setText("Interface:")
            self.interface_combo.show()
            self.port_edit.hide()
            self.config_btn.hide()
        elif index == 2:  # Port Scan
            self.options_label.setText("Ports:")
            self.interface_combo.hide()
            self.port_edit.show()
            self.config_btn.hide()
        elif index == 3:  # Custom Scan
            self.options_label.setText("Options:")
            self.interface_combo.hide()
            self.port_edit.hide()
            self.config_btn.show()
    
    def _show_custom_config(self):
        """Show custom scan configuration dialog."""
        dialog = CustomScanDialog(self)
        
        # Pre-fill with current values
        dialog.target_edit.setText(self.target_edit.text())
        
        if dialog.exec_() == QDialog.Accepted:
            # Get configuration and apply it
            config = dialog.get_config()
            self.target_edit.setText(config['target'])
            
            # Set scan type
            if config['type'] == 'ping':
                self.scan_type_combo.setCurrentIndex(0)
            elif config['type'] == 'arp':
                self.scan_type_combo.setCurrentIndex(1)
                # Find the interface in the combo box
                for i in range(self.interface_combo.count()):
                    if self.interface_combo.itemData(i) == config['interface']:
                        self.interface_combo.setCurrentIndex(i)
                        break
            elif config['type'] == 'port':
                self.scan_type_combo.setCurrentIndex(2)
                self.port_edit.setText(config['ports'])
            else:
                self.scan_type_combo.setCurrentIndex(3)
            
            # Store the full config for later
            self.custom_config = config
    
    def _show_context_menu(self, position):
        """Show context menu for results table."""
        menu = QMenu(self)
        
        view_action = QAction("View Details", self)
        view_action.triggered.connect(self._view_device_details)
        menu.addAction(view_action)
        
        ping_action = QAction("Ping Device", self)
        ping_action.triggered.connect(self._ping_selected_device)
        menu.addAction(ping_action)
        
        port_scan_action = QAction("Port Scan", self)
        port_scan_action.triggered.connect(self._port_scan_selected_device)
        menu.addAction(port_scan_action)
        
        menu.addSeparator()
        
        message_action = QAction("Send as Message", self)
        message_action.triggered.connect(self._send_results_as_message)
        menu.addAction(message_action)
        
        menu.addSeparator()
        
        add_remote_action = QAction("Add to Remote Devices", self)
        add_remote_action.triggered.connect(self._add_to_remote_devices)
        menu.addAction(add_remote_action)
        
        # Show the menu
        menu.exec_(self.results_table.mapToGlobal(position))
    
    def start_scan(self):
        """Start a network scan."""
        # Validate target
        target = self.target_edit.text().strip()
        if not target:
            QMessageBox.warning(self, "Invalid Target", "Please enter a valid target IP or network.")
            return
        
        # Get scan type
        scan_type_index = self.scan_type_combo.currentIndex()
        
        if scan_type_index == 0:  # Ping Sweep
            scan_type = 'ping'
            options = {}
        elif scan_type_index == 1:  # ARP Scan
            scan_type = 'arp'
            options = {'interface': self.interface_combo.currentData()}
        elif scan_type_index == 2:  # Port Scan
            scan_type = 'port'
            ports = self.port_edit.text().strip()
            options = {'ports': ports if ports else '1-1024'}
        elif scan_type_index == 3:  # Custom Scan
            if hasattr(self, 'custom_config'):
                scan_type = self.custom_config['type']
                options = self.custom_config
            else:
                QMessageBox.warning(self, "Configuration Required", 
                                   "Please configure the custom scan first.")
                return
        
        # Update UI
        self.start_scan_btn.setEnabled(False)
        self.stop_scan_btn.setEnabled(True)
        self.progress_bar.setValue(0)
        self.status_label.setText("Starting scan...")
        
        # Clear previous results
        self.results_table.setRowCount(0)
        
        # Emit signal that scan is starting
        self.scan_started.emit()
        
        # Create and start worker thread
        self.scan_worker = ScanWorker(scan_type, target, options)
        self.scan_worker.progress_updated.connect(self._update_progress)
        self.scan_worker.scan_complete.connect(self._scan_complete)
        self.scan_worker.scan_error.connect(self._scan_error)
        self.scan_worker.start()
    
    def stop_scan(self):
        """Stop an ongoing scan."""
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.stop()
            self.scan_worker.wait()
            self.status_label.setText("Scan stopped by user")
            self._update_ui_after_scan()
    
    def _update_progress(self, progress, current_item, count):
        """Update progress bar and status during scan."""
        self.progress_bar.setValue(int(progress))
        self.status_label.setText(f"Scanning {current_item}... Found {count} devices")
    
    def _scan_complete(self, results):
        """Handle scan completion."""
        self.scan_results = results
        self.status_label.setText(f"Scan completed. Found {len(results)} devices.")
        
        # Update UI
        self._update_ui_after_scan()
        
        # Display results
        self._display_results(results)
        
        # Emit signal with results
        self.scan_completed.emit(results)
    
    def _scan_error(self, error_message):
        """Handle scan error."""
        QMessageBox.critical(self, "Scan Error", f"An error occurred during the scan:\n{error_message}")
        self.status_label.setText(f"Scan failed: {error_message}")
        self._update_ui_after_scan()
    
    def _update_ui_after_scan(self):
        """Update UI elements after scan completes or is stopped."""
        self.start_scan_btn.setEnabled(True)
        self.stop_scan_btn.setEnabled(False)
    
    def _display_results(self, results):
        """Display scan results in the table."""
        self.results_table.setRowCount(0)
        
        if not results:
            return
        
        # Determine result type and display accordingly
        if isinstance(next(iter(results.values())), dict):
            # Display device results
            row = 0
            for ip, device in results.items():
                self.results_table.insertRow(row)
                
                # IP Address
                ip_item = QTableWidgetItem(ip)
                self.results_table.setItem(row, 0, ip_item)
                
                # Hostname
                hostname = device.get('hostname', 'Unknown')
                hostname_item = QTableWidgetItem(hostname)
                self.results_table.setItem(row, 1, hostname_item)
                
                # Status
                status = device.get('status', 'unknown')
                status_item = QTableWidgetItem(status)
                
                # Color based on status
                if status == 'up':
                    status_item.setBackground(COLOR_ONLINE)
                elif status == 'down':
                    status_item.setBackground(COLOR_OFFLINE)
                else:
                    status_item.setBackground(COLOR_UNKNOWN)
                
                self.results_table.setItem(row, 2, status_item)
                
                # MAC Address
                mac = device.get('mac', 'Unknown')
                mac_item = QTableWidgetItem(mac)
                self.results_table.setItem(row, 3, mac_item)
                
                # Ports
                ports = device.get('open_ports', [])
                ports_text = ', '.join(map(str, ports)) if ports else 'None'
                ports_item = QTableWidgetItem(ports_text)
                self.results_table.setItem(row, 4, ports_item)
                
                row += 1
                
        elif isinstance(next(iter(results.values())), list):
            # Handle port scan results
            self.results_table.setColumnCount(3)
            self.results_table.setHorizontalHeaderLabels(["IP Address", "Port", "Service"])
            
            row = 0
            for ip, ports in results.items():
                for port in ports:
                    self.results_table.insertRow(row)
                    
                    # IP Address
                    ip_item = QTableWidgetItem(ip)
                    self.results_table.setItem(row, 0, ip_item)
                    
                    # Port
                    port_item = QTableWidgetItem(str(port))
                    self.results_table.setItem(row, 1, port_item)
                    
                    # Service - placeholder
                    self.results_table.setItem(row, 2, QTableWidgetItem("Unknown"))
                    
                    row += 1
        
        # Resize columns to content
        self.results_table.resizeColumnsToContents()
    
    def _on_item_double_clicked(self, item):
        """Handle double click on result item."""
        row = item.row()
        ip_item = self.results_table.item(row, 0)
        if ip_item:
            ip = ip_item.text()
            self._view_device_details(ip)
    
    def _view_device_details(self, ip=None):
        """View details of selected device."""
        # If IP not provided, get from selected row
        if ip is None:
            selected_items = self.results_table.selectedItems()
            if not selected_items:
                QMessageBox.information(self, "No Selection", "Please select a device first.")
                return
            
            row = selected_items[0].row()
            ip_item = self.results_table.item(row, 0)
            if ip_item:
                ip = ip_item.text()
            else:
                QMessageBox.warning(self, "Error", "Could not determine IP address.")
                return
        
        # Get device info
        device_info = DeviceInfoGatherer.get_remote_info(ip)
        
        # Create dialog to display info
        dialog = QDialog(self)
        dialog.setWindowTitle(f"Device Details - {ip}")
        dialog.setMinimumSize(500, 400)
        
        layout = QVBoxLayout(dialog)
        
        # Tabs for different info categories
        tabs = QTabWidget()
        
        # Basic info tab
        basic_tab = QWidget()
        basic_layout = QFormLayout(basic_tab)
        
        basic_layout.addRow("IP Address:", QLabel(device_info['ip']))
        basic_layout.addRow("Hostname:", QLabel(device_info['hostname']))
        basic_layout.addRow("MAC Address:", QLabel(device_info['mac']))
        basic_layout.addRow("Operating System:", QLabel(device_info['os']))
        basic_layout.addRow("Status:", QLabel(device_info['status']))
        
        tabs.addTab(basic_tab, "Basic Info")
        
        # Ports tab
        ports_tab = QWidget()
        ports_layout = QVBoxLayout(ports_tab)
        
        ports_table = QTableWidget(0, 2)
        ports_table.setHorizontalHeaderLabels(["Port", "Service"])
        ports_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        if device_info['open_ports']:
            for i, port in enumerate(device_info['open_ports']):
                ports_table.insertRow(i)
                ports_table.setItem(i, 0, QTableWidgetItem(str(port)))
                ports_table.setItem(i, 1, QTableWidgetItem("Unknown"))
        
        ports_layout.addWidget(ports_table)
        tabs.addTab(ports_tab, "Open Ports")
        
        # Network tab with ping results
        network_tab = QWidget()
        network_layout = QVBoxLayout(network_tab)
        
        ping_btn = QPushButton("Ping Device")
        ping_btn.clicked.connect(lambda: self._ping_device_from_dialog(ip, network_layout))
        network_layout.addWidget(ping_btn)
        
        ping_results = QTextEdit()
        ping_results.setReadOnly(True)
        ping_results.setPlaceholderText("Click 'Ping Device' to test connectivity")
        network_layout.addWidget(ping_results)
        
        tabs.addTab(network_tab, "Network")
        
        layout.addWidget(tabs)
        
        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok)
        button_box.accepted.connect(dialog.accept)
        layout.addWidget(button_box)
        
        dialog.exec_()
    
    def _ping_device_from_dialog(self, ip, layout):
        """Ping device and display results in dialog."""
        # Find the text edit widget in the layout
        text_edit = None
        for i in range(layout.count()):
            widget = layout.itemAt(i).widget()
            if isinstance(widget, QTextEdit):
                text_edit = widget
                break
        
        if not text_edit:
            return
        
        text_edit.clear()
        text_edit.setPlainText("Pinging device, please wait...")
        
        # Create a separate thread for ping
        class PingThread(QThread):
            ping_complete = pyqtSignal(dict)
            
            def __init__(self, ip):
                super().__init__()
                self.ip = ip
            
            def run(self):
                result = DeviceInfoGatherer.ping(self.ip)
                self.ping_complete.emit(result)
        
        def on_ping_complete(result):
            text_edit.clear()
            
            if result['success']:
                text_edit.setPlainText(f"Ping successful!\n\n"
                                      f"Minimum RTT: {result['min_rtt']} ms\n"
                                      f"Average RTT: {result['avg_rtt']} ms\n"
                                      f"Maximum RTT: {result['max_rtt']} ms\n"
                                      f"Packet Loss: {result['packet_loss']}%")
            else:
                text_edit.setPlainText(f"Ping failed!\n\n"
                                      f"Error: {result['error']}")
        
        ping_thread = PingThread(ip)
        ping_thread.ping_complete.connect(on_ping_complete)
        ping_thread.start()
    
    def _ping_selected_device(self):
        """Ping the selected device."""
        selected_items = self.results_table.selectedItems()
        if not selected_items:
            QMessageBox.information(self, "No Selection", "Please select a device first.")
            return
        
        row = selected_items[0].row()
        ip_item = self.results_table.item(row, 0)
        if ip_item:
            ip = ip_item.text()
            
            # Create a dialog to show ping results
            dialog = QDialog(self)
            dialog.setWindowTitle(f"Ping {ip}")
            dialog.setMinimumSize(400, 300)
            
            layout = QVBoxLayout(dialog)
            
            # Display
            results_text = QTextEdit()
            results_text.setReadOnly(True)
            results_text.setPlainText(f"Pinging {ip}, please wait...")
            layout.addWidget(results_text)
            
            # Buttons
            button_box = QDialogButtonBox(QDialogButtonBox.Close)
            button_box.rejected.connect(dialog.reject)
            layout.addWidget(button_box)
            
            dialog.show()
            
            # Ping in a separate thread to avoid blocking UI
            class PingThread(QThread):
                ping_complete = pyqtSignal(dict)
                
                def __init__(self, ip):
                    super().__init__()
                    self.ip = ip
                
                def run(self):
                    result = DeviceInfoGatherer.ping(self.ip, count=4)
                    self.ping_complete.emit(result)
            
            def on_ping_complete(result):
                if result['success']:
                    results_text.setPlainText(f"Ping to {ip} successful!\n\n"
                                             f"Minimum RTT: {result['min_rtt']} ms\n"
                                             f"Average RTT: {result['avg_rtt']} ms\n"
                                             f"Maximum RTT: {result['max_rtt']} ms\n"
                                             f"Packet Loss: {result['packet_loss']}%")
                else:
                    results_text.setPlainText(f"Ping to {ip} failed!\n\n"
                                             f"Error: {result['error']}")
            
            ping_thread = PingThread(ip)
            ping_thread.ping_complete.connect(on_ping_complete)
            ping_thread.start()
    
    def _port_scan_selected_device(self):
        """Perform a port scan on the selected device."""
        selected_items = self.results_table.selectedItems()
        if not selected_items:
            QMessageBox.information(self, "No Selection", "Please select a device first.")
            return
        
        row = selected_items[0].row()
        ip_item = self.results_table.item(row, 0)
        if ip_item:
            ip = ip_item.text()
            
            # Ask for port range
            ports, ok = QInputDialog.getText(
                self, "Port Scan", "Enter port range (e.g., 1-1024,3389):",
                QLineEdit.Normal, "1-1024"
            )
            
            if not ok or not ports:
                return
            
            # Set up scan for the selected device with specified ports
            self.target_edit.setText(ip)
            self.scan_type_combo.setCurrentIndex(2)  # Port Scan
            self.port_edit.setText(ports)
            
            # Start the scan
            self.start_scan()
    
    def _add_to_remote_devices(self):
        """Add the selected device to remote management."""
        selected_items = self.results_table.selectedItems()
        if not selected_items:
            QMessageBox.information(self, "No Selection", "Please select a device first.")
            return
        
        row = selected_items[0].row()
        ip_item = self.results_table.item(row, 0)
        hostname_item = self.results_table.item(row, 1)
        
        if ip_item:
            ip = ip_item.text()
            hostname = hostname_item.text() if hostname_item else "Unknown"
            
            # Signal to parent to add this device
            # This would typically be handled by a signal/slot to the main window
            # or by accessing the remote tab directly
            parent = self.parent()
            if parent:
                # Try to find remote tab and call its add_device method
                remote_tab = None
                for tab_index in range(parent.tab_widget.count()):
                    tab = parent.tab_widget.widget(tab_index)
                    if hasattr(tab, 'add_device') and tab.__class__.__name__ == "RemoteTab":
                        remote_tab = tab
                        break
                
                if remote_tab:
                    # Switch to remote tab
                    parent.tab_widget.setCurrentWidget(remote_tab)
                    # Call with pre-filled info
                    remote_tab.add_device(ip=ip, name=hostname)
                    return
            
            # Fallback if we couldn't find the remote tab
            QMessageBox.information(
                self, "Device Information", 
                f"To add this device to remote management, go to the Remote tab and add:\n\n"
                f"IP: {ip}\nName: {hostname}"
            )
    
    def _export_results(self):
        """Export scan results to a file."""
        if not self.scan_results:
            QMessageBox.information(self, "No Results", "No scan results to export.")
            return
        
        # Ask for file location
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Scan Results", 
            f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            "JSON Files (*.json);;CSV Files (*.csv);;All Files (*)"
        )
        
        if not file_path:
            return
        
        # Export based on file extension
        try:
            file_ext = os.path.splitext(file_path)[1].lower()
            
            if file_ext == ".json":
                with open(file_path, 'w') as f:
                    json.dump(self.scan_results, f, indent=2)
            elif file_ext == ".csv":
                self._export_to_csv(file_path)
            else:
                # Default to JSON if extension not recognized
                with open(file_path, 'w') as f:
                    json.dump(self.scan_results, f, indent=2)
            
            QMessageBox.information(self, "Export Successful", f"Results exported to {file_path}")
            
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Failed to export results: {str(e)}")
            logger.error(f"Export error: {e}")
    
    def _export_to_csv(self, file_path):
        """Export results to CSV format."""
        import csv
        
        with open(file_path, 'w', newline='') as csvfile:
            # Determine fields based on result type
            if not self.scan_results:
                return
            
            sample_value = next(iter(self.scan_results.values()))
            
            if isinstance(sample_value, dict):
                # Device scan results
                fieldnames = ['ip', 'hostname', 'status', 'mac']
                if 'open_ports' in sample_value:
                    fieldnames.append('open_ports')
                
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for ip, device in self.scan_results.items():
                    row = {'ip': ip}
                    for field in fieldnames:
                        if field != 'ip':
                            if field == 'open_ports' and field in device:
                                row[field] = ', '.join(map(str, device[field]))
                            else:
                                row[field] = device.get(field, '')
                    writer.writerow(row)
            
            elif isinstance(sample_value, list):
                # Port scan results
                writer = csv.writer(csvfile)
                writer.writerow(['ip', 'port'])
                
                for ip, ports in self.scan_results.items():
                    for port in ports:
                        writer.writerow([ip, port])
    
    def _clear_results(self):
        """Clear the scan results."""
        self.scan_results = {}
        self.results_table.setRowCount(0)
        self.progress_bar.setValue(0)
        self.status_label.setText("Results cleared")
    
    def _send_results_as_message(self):
        """Send scan results as a message to a remote device."""
        # Check if we have results
        if not self.scan_results:
            QMessageBox.information(self, "No Results", "No scan results to send.")
            return
        
        # Get selected items or entire result set
        selected_items = self.results_table.selectedItems()
        if selected_items:
            # Format just the selected items
            message_content = self._format_results_for_message(selected_items)
        else:
            # Format all results
            message_content = self._format_all_results_for_message()
        
        # Get available devices from DeviceManager
        device_manager = DeviceManager()
        devices = []
        for device_id, device_data in device_manager.get_devices().items():
            devices.append({
                "name": device_data.get("name", device_id),
                "device_id": device_id,
                "status": device_data.get("status", "unknown")
            })
        
        # Check if we have any devices to send to
        if not devices:
            QMessageBox.warning(self, "No Devices", "No remote devices found to send messages to.\n"
                              "Please add devices in the Remote Management tab first.")
            return
        
        # Open message dialog
        dialog = NewMessageDialog(self, devices)
        dialog.content_edit.setPlainText(message_content)
        dialog.type_combo.setCurrentText("notification")
        
        if dialog.exec_() == QDialog.Accepted:
            values = dialog.get_values()
            
            # Validate
            if not values["device_id"]:
                QMessageBox.warning(self, "Error", "Please select a device")
                return
                
            if not values["content"]:
                QMessageBox.warning(self, "Error", "Message content cannot be empty")
                return
            
            # Send the message
            message_manager = MessageManager()
            success = message_manager.send_message(
                values["device_id"],
                values["message_type"],
                values["content"],
                {"source": "scan_results"}
            )
            
            if success:
                QMessageBox.information(self, "Success", "Scan results sent successfully")
            else:
                QMessageBox.warning(self, "Error", "Failed to send scan results")
    
    def _format_results_for_message(self, selected_items):
        """Format selected items for message content."""
        message = "SCAN RESULTS\n"
        message += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        # Get unique rows
        rows = set()
        for item in selected_items:
            rows.add(item.row())
        
        # For each row, get all column data
        for row in sorted(rows):
            # Check what kind of data we're displaying (device or port)
            if self.results_table.columnCount() >= 5:  # Device results
                ip = self.results_table.item(row, 0).text() if self.results_table.item(row, 0) else "Unknown"
                hostname = self.results_table.item(row, 1).text() if self.results_table.item(row, 1) else "Unknown"
                status = self.results_table.item(row, 2).text() if self.results_table.item(row, 2) else "Unknown"
                mac = self.results_table.item(row, 3).text() if self.results_table.item(row, 3) else "Unknown"
                ports = self.results_table.item(row, 4).text() if self.results_table.item(row, 4) else "None"
                
                message += f"Device: {ip}\n"
                message += f"  Hostname: {hostname}\n"
                message += f"  Status: {status}\n"
                message += f"  MAC: {mac}\n"
                message += f"  Open Ports: {ports}\n"
                message += "\n"
            else:  # Port scan results
                ip = self.results_table.item(row, 0).text() if self.results_table.item(row, 0) else "Unknown"
                port = self.results_table.item(row, 1).text() if self.results_table.item(row, 1) else "Unknown"
                service = self.results_table.item(row, 2).text() if self.results_table.item(row, 2) else "Unknown"
                
                message += f"Host: {ip}\n"
                message += f"  Port: {port}\n"
                message += f"  Service: {service}\n"
                message += "\n"
        
        return message
    
    def _format_all_results_for_message(self):
        """Format all scan results for message content."""
        message = "SCAN RESULTS\n"
        message += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        message += f"Total devices found: {len(self.scan_results)}\n\n"
        
        # Different formatting based on result type
        sample_value = next(iter(self.scan_results.values()), None)
        
        if isinstance(sample_value, dict):
            # Device scan
            for ip, device in self.scan_results.items():
                message += f"Device: {ip}\n"
                message += f"  Hostname: {device.get('hostname', 'Unknown')}\n"
                message += f"  Status: {device.get('status', 'Unknown')}\n"
                message += f"  MAC: {device.get('mac', 'Unknown')}\n"
                
                open_ports = device.get('open_ports', [])
                if open_ports:
                    message += f"  Open Ports: {', '.join(map(str, open_ports))}\n"
                else:
                    message += "  Open Ports: None\n"
                    
                message += "\n"
        
        elif isinstance(sample_value, list):
            # Port scan
            for ip, ports in self.scan_results.items():
                message += f"Host: {ip}\n"
                if ports:
                    message += f"  Open Ports: {', '.join(map(str, ports))}\n"
                else:
                    message += "  No open ports found\n"
                message += "\n"
        
        return message
    
    def get_scan_results(self):
        """Get the current scan results."""
        return self.scan_results
    
    def cleanup(self):
        """Clean up resources before closing."""
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.stop()
            self.scan_worker.wait()