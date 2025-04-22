"""
Main window for the Network Scanner & Management Tool
"""
import logging
import os
from datetime import datetime
from typing import Dict

from PyQt5.QtWidgets import (
    QMainWindow, QTabWidget, QVBoxLayout, QHBoxLayout,
    QWidget, QPushButton, QStatusBar, QAction, QMenu,
    QToolBar, QLabel, QMessageBox, QFileDialog
)
from PyQt5.QtCore import Qt, QSize
from PyQt5.QtGui import QIcon

from gui.scanner_tab import ScannerTab
from gui.devices_tab import DevicesTab
from gui.remote_tab import RemoteTab

logger = logging.getLogger(__name__)

class MainWindow(QMainWindow):
    """Main application window"""
    
    def __init__(self, settings: Dict = None):
        super().__init__()
        
        self.settings = settings or {}
        self.setWindowTitle("Network Scanner & Management Tool")
        self.setMinimumSize(1000, 700)
        
        # Setup UI
        self._setup_ui()
        
        logger.info("Main window initialized")
        self.status_bar.showMessage(f"Ready - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
    def _setup_ui(self):
        """Setup the user interface"""
        # Central widget
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        # Main layout
        self.main_layout = QVBoxLayout(self.central_widget)
        self.main_layout.setContentsMargins(5, 5, 5, 5) 
        
        # Tab widget
        self.tab_widget = QTabWidget()
        self.main_layout.addWidget(self.tab_widget)
        
        # Create tab instances
        self.scanner_tab = ScannerTab()
        self.devices_tab = DevicesTab()
        self.remote_tab = RemoteTab()
        
        # Add tabs to widget
        self.tab_widget.addTab(self.scanner_tab, "Network Scanner")
        self.tab_widget.addTab(self.devices_tab, "Devices")
        self.tab_widget.addTab(self.remote_tab, "Remote Management")
        
        # Create placeholder tabs for future implementation
        self.message_tab = QWidget()
        message_layout = QVBoxLayout(self.message_tab)
        message_layout.addWidget(QLabel("Messaging functionality will be implemented here"))
        
        self.files_tab = QWidget()
        files_layout = QVBoxLayout(self.files_tab)
        files_layout.addWidget(QLabel("File search functionality will be implemented here"))
        
        self.monitoring_tab = QWidget()
        monitoring_layout = QVBoxLayout(self.monitoring_tab)
        monitoring_layout.addWidget(QLabel("Network monitoring functionality will be implemented here"))
        
        # Add placeholder tabs
        self.tab_widget.addTab(self.message_tab, "Messaging")
        self.tab_widget.addTab(self.files_tab, "Files")
        self.tab_widget.addTab(self.monitoring_tab, "Monitoring")
        
        # Connect scanner tab signals to devices tab
        self.scanner_tab.device_discovered.connect(self.devices_tab.add_device_from_scan)
        
        # Connexion entre les onglets Device et Remote Management
        self.scanner_tab.device_discovered.connect(self._on_device_discovered)
        
        # Setup status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        # Setup menu bar
        self._setup_menu()
        
        # Setup toolbar
        self._setup_toolbar()
        
    def _on_device_discovered(self, device_info):
        """Gère un appareil découvert par le scan"""
        # Vous pourriez vouloir alerter l'utilisateur qu'un nouvel appareil 
        # peut être ajouté à la gestion à distance
        pass
        
    def _setup_menu(self):
        """Setup the application menu"""
        # File menu
        file_menu = self.menuBar().addMenu("&File")
        
        save_action = QAction("&Save Results", self)
        save_action.setStatusTip("Save scan results to file")
        save_action.triggered.connect(self._save_results)
        file_menu.addAction(save_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("E&xit", self)
        exit_action.setStatusTip("Exit the application")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Scan menu
        scan_menu = self.menuBar().addMenu("&Scan")
        
        start_scan_action = QAction("&Start Network Scan", self)
        start_scan_action.setStatusTip("Start scanning the network")
        start_scan_action.triggered.connect(self._start_scan)
        scan_menu.addAction(start_scan_action)
        
        stop_scan_action = QAction("S&top Scan", self)
        stop_scan_action.setStatusTip("Stop the current scan")
        stop_scan_action.triggered.connect(self._stop_scan)
        scan_menu.addAction(stop_scan_action)
        
        scan_menu.addSeparator()
        
        port_scan_action = QAction("&Port Scan Selected", self)
        port_scan_action.setStatusTip("Perform port scan on selected device")
        port_scan_action.triggered.connect(self._port_scan_selected)
        scan_menu.addAction(port_scan_action)
        
        # Remote management menu 
        remote_menu = self.menuBar().addMenu("&Remote")
        
        add_device_action = QAction("&Add Remote Device", self)
        add_device_action.setStatusTip("Add a new remote device to manage")
        add_device_action.triggered.connect(lambda: self.remote_tab._add_device())
        remote_menu.addAction(add_device_action)
        
        wol_action = QAction("&Wake-on-LAN", self)
        wol_action.setStatusTip("Send Wake-on-LAN packet")
        wol_action.triggered.connect(lambda: self.remote_tab._wake_on_lan())
        remote_menu.addAction(wol_action)
        
        remote_menu.addSeparator()
        
        refresh_action = QAction("&Refresh Status", self)
        refresh_action.setStatusTip("Refresh the status of all remote devices")
        refresh_action.triggered.connect(lambda: self.remote_tab._refresh_statuses())
        remote_menu.addAction(refresh_action)
        
        # Tools menu
        tools_menu = self.menuBar().addMenu("&Tools")
        
        settings_action = QAction("Se&ttings", self)
        settings_action.setStatusTip("Configure application settings")
        settings_action.triggered.connect(self._show_settings)
        tools_menu.addAction(settings_action)
        
        # Help menu
        help_menu = self.menuBar().addMenu("&Help")
        
        about_action = QAction("&About", self)
        about_action.setStatusTip("Show information about the application")
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)
        
    def _setup_toolbar(self):
        """Setup the application toolbar"""
        toolbar = QToolBar("Main Toolbar")
        toolbar.setIconSize(QSize(24, 24))
        self.addToolBar(toolbar)
        
        # Add scan button
        scan_action = QAction(QIcon("icons/scan.png") if os.path.exists("icons/scan.png") else "Scan", self)
        scan_action.setStatusTip("Start scanning the network")
        scan_action.triggered.connect(self._start_scan)
        toolbar.addAction(scan_action)
        
        # Add stop button
        stop_action = QAction(QIcon("icons/stop.png") if os.path.exists("icons/stop.png") else "Stop", self)
        stop_action.setStatusTip("Stop the current scan")
        stop_action.triggered.connect(self._stop_scan)
        toolbar.addAction(stop_action)
        
    def _save_results(self):
        """Save scan results to file"""
        if self.tab_widget.currentWidget() == self.scanner_tab:
            self.scanner_tab.save_results()
        elif self.tab_widget.currentWidget() == self.devices_tab:
            self.devices_tab.save_devices()
        else:
            QMessageBox.information(
                self,
                "Save Results",
                "Saving is only available for Network Scanner and Devices tabs."
            )
            
    def _start_scan(self):
        """Start network scan from menu or toolbar"""
        # Make sure scanner tab is shown
        self.tab_widget.setCurrentWidget(self.scanner_tab)
        # Start scanning
        self.scanner_tab.start_scan()
        
    def _stop_scan(self):
        """Stop network scan from menu or toolbar"""
        self.scanner_tab.stop_scan()
        
    def _port_scan_selected(self):
        """Perform port scan on selected device"""
        if self.tab_widget.currentWidget() == self.scanner_tab:
            self.scanner_tab._scan_ports_of_selected()
        elif self.tab_widget.currentWidget() == self.devices_tab:
            self.devices_tab._scan_ports_of_selected()
        else:
            QMessageBox.information(
                self,
                "Port Scan",
                "Port scanning is only available from the Network Scanner and Devices tabs."
            )
            
    def _show_settings(self):
        """Show application settings dialog"""
        QMessageBox.information(
            self,
            "Settings",
            "Settings functionality will be implemented in a future update."
        )
            
    def _show_about(self):
        """Show application about dialog"""
        QMessageBox.about(
            self,
            "About Network Scanner & Management Tool",
            "Network Scanner & Management Tool\n\n"
            "Version: 1.0.0\n"
            "Author: AnoirELGUEDDAR\n\n"
            "A comprehensive tool for network scanning, device discovery, remote management, "
            "messaging, file searching and network monitoring on local networks."
        )