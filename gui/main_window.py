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
    QToolBar, QLabel, QMessageBox, QFileDialog, QInputDialog
)
from PyQt5.QtCore import Qt, QSize, QTimer
from PyQt5.QtGui import QIcon

# Use your actual file names as they exist in the project
from gui.scanner_tab import ScannerTab
from gui.devices_tab import DevicesTab
from gui.remote_tab import RemoteTab
from gui.messaging_tab import MessagingTab, NewMessageDialog, ClientMessagingMode
from gui.files_tab import FilesTab

from core.messaging.message_service import MessageService
from core.messaging.message import Message, MessageType
from core.messaging.message_server import MessageServer
from core.file_transfer.file_service import FileTransferService

# Import the DeviceManager for remote device management
from core.remote.device_manager import DeviceManager

logger = logging.getLogger(__name__)

class MainWindow(QMainWindow):
    """Main application window"""
    
    def __init__(self, settings: Dict = None):
        super().__init__()
        
        self.settings = settings or {}
        self.setWindowTitle("Network Scanner & Management Tool")
        self.setMinimumSize(1000, 700)
        
        # Initialize MessageService
        self.message_service = MessageService()
        
        # Set administrator username
        self.message_service.set_username("AnoirELGUEDDAR")
        
        # Initialize MessageServer (for client-admin communication)
        self.message_server = MessageServer(
            port=9876,
            message_service=self.message_service,
            auth_token="change_this_token_immediately"  # Use same token in clients
        )
        
        # Initialize FileTransferService
        self.file_service = FileTransferService(storage_dir="file_storage")
        
        # Initialize DeviceManager for remote device management
        self.device_manager = DeviceManager()
        
        # Start the services
        self.message_service.start()
        self.message_server.start()
        
        # Setup UI
        self._setup_ui()
        
        logger.info("Main window initialized")
        self.status_bar.showMessage(f"Ready - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Send welcome message
        welcome_msg = Message(
            content=f"Application started successfully at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            msg_type=MessageType.INFO,
            sender="System"
        )
        self.message_service.send_message(welcome_msg)
        
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
        self.messaging_tab = MessagingTab(self.message_service)
        
        # Add tabs to widget
        self.tab_widget.addTab(self.scanner_tab, "Network Scanner")
        self.tab_widget.addTab(self.devices_tab, "Devices")
        self.tab_widget.addTab(self.remote_tab, "Remote Management")
        self.tab_widget.addTab(self.messaging_tab, "Messaging")
        
        # Initialize Files Tab with our implementation - Use DeviceManager
        self.files_tab = FilesTab(
            self.device_manager,  # Pass the device_manager instead of None
            self.file_service,
            self.message_service
        )
        self.tab_widget.addTab(self.files_tab, "Files")
        
        # Keep the placeholder for monitoring tab
        self.monitoring_tab = QWidget()
        monitoring_layout = QVBoxLayout(self.monitoring_tab)
        monitoring_layout.addWidget(QLabel("Network monitoring functionality will be implemented here"))
        self.tab_widget.addTab(self.monitoring_tab, "Monitoring")
        
        # Connect scanner tab signals to devices tab
        self.scanner_tab.device_discovered.connect(self.devices_tab.add_device_from_scan)
        
        # Connect scanner tab signals to send messages
        self.scanner_tab.device_discovered.connect(self._on_device_discovered)
        
        # Setup status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        # Setup menu bar
        self._setup_menu()
        
        # Setup toolbar
        self._setup_toolbar()
        
    def _on_device_discovered(self, device_info):
        """Handle a device discovered by the scan"""
        # Send a notification via the messaging system about the discovered device
        device_ip = device_info.get('ip', 'unknown')
        device_mac = device_info.get('mac', 'unknown')
        device_name = device_info.get('hostname', 'unnamed')
        
        # Register device with message service
        device_id = device_ip  # Use IP address as device ID
        self.message_service.register_device(device_id, device_info)
        
        # Send notification message
        message = Message(
            content=f"New device discovered: {device_name} ({device_ip}, {device_mac})",
            msg_type=MessageType.INFO,
            sender="Scanner"
        )
        self.message_service.send_message(message)
        
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
        
        # Messaging menu
        message_menu = self.menuBar().addMenu("&Messaging")
        
        new_msg_action = QAction("&New Message", self)
        new_msg_action.setStatusTip("Create a new message")
        new_msg_action.triggered.connect(self._create_new_message)
        message_menu.addAction(new_msg_action)
        
        refresh_msgs_action = QAction("&Refresh Messages", self)
        refresh_msgs_action.setStatusTip("Refresh message list")
        refresh_msgs_action.triggered.connect(lambda: self.messaging_tab.refresh_conversations())
        message_menu.addAction(refresh_msgs_action)
        
        message_menu.addSeparator()
        
        # Add Client Mode action
        client_mode_action = QAction("Start &Client Mode", self)
        client_mode_action.setStatusTip("Start client messaging mode")
        client_mode_action.triggered.connect(self._start_client_mode)
        message_menu.addAction(client_mode_action)
        
        # Add Broadcast Message action
        broadcast_action = QAction("&Broadcast Message", self)
        broadcast_action.setStatusTip("Send a message to all devices")
        broadcast_action.triggered.connect(self._broadcast_message)
        message_menu.addAction(broadcast_action)
        
        # File menu
        file_transfer_menu = self.menuBar().addMenu("&Files")
        
        upload_action = QAction("&Upload Files", self)
        upload_action.setStatusTip("Upload files to clients")
        upload_action.triggered.connect(self._upload_files)
        file_transfer_menu.addAction(upload_action)
        
        download_action = QAction("&Download Files", self)
        download_action.setStatusTip("Download files from clients")
        download_action.triggered.connect(self._download_files)
        file_transfer_menu.addAction(download_action)
        
        file_transfer_menu.addSeparator()
        
        search_action = QAction("&Search Files", self)
        search_action.setStatusTip("Search for files on clients")
        search_action.triggered.connect(self._search_files)
        file_transfer_menu.addAction(search_action)
        
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
        
        # Add message button
        message_action = QAction(QIcon("icons/message.png") if os.path.exists("icons/message.png") else "Message", self)
        message_action.setStatusTip("Create a new message")
        message_action.triggered.connect(self._create_new_message)
        toolbar.addAction(message_action)
        
        # Add client mode button
        client_action = QAction(QIcon("icons/client.png") if os.path.exists("icons/client.png") else "Client", self)
        client_action.setStatusTip("Start client messaging mode")
        client_action.triggered.connect(self._start_client_mode)
        toolbar.addAction(client_action)
        
        # Add file upload button
        upload_action = QAction(QIcon("icons/upload.png") if os.path.exists("icons/upload.png") else "Upload", self)
        upload_action.setStatusTip("Upload files to clients")
        upload_action.triggered.connect(self._upload_files)
        toolbar.addAction(upload_action)
        
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
        
        # Send notification message
        message = Message(
            content="Network scan started",
            msg_type=MessageType.INFO,
            sender="System"
        )
        self.message_service.send_message(message)
        
    def _stop_scan(self):
        """Stop network scan from menu or toolbar"""
        self.scanner_tab.stop_scan()
        
        # Send notification message
        message = Message(
            content="Network scan stopped",
            msg_type=MessageType.INFO,
            sender="System"
        )
        self.message_service.send_message(message)
        
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
            
    def _create_new_message(self):
        """Create a new message from menu or toolbar"""
        # Switch to messaging tab
        self.tab_widget.setCurrentWidget(self.messaging_tab)
        
        # Open the new message dialog
        dialog = NewMessageDialog(self.message_service, self)
        if dialog.exec_():
            # Get message data from dialog
            msg_data = dialog.get_message_data()
            if not msg_data["content"]:
                return
                
            # Create and send the message
            message = Message(
                content=msg_data["content"],
                msg_type=msg_data["msg_type"],
                sender="AnoirELGUEDDAR",
                recipient=msg_data["recipient"],
                is_broadcast=msg_data["is_broadcast"]
            )
            
            self.message_service.send_message(message)
            
            # Refresh conversations and select the new one
            self.messaging_tab.refresh_conversations()
            
    def _start_client_mode(self):
        """Start client messaging mode"""
        # Open the client messaging dialog
        client_dialog = ClientMessagingMode(self.message_service, self)
        client_dialog.exec_()
        
        # Refresh conversations when done
        self.messaging_tab.refresh_conversations()
        
    def _broadcast_message(self):
        """Broadcast a message to all clients"""
        # Create a simple input dialog for the message
        text, ok = QInputDialog.getText(
            self, 
            "Broadcast Message", 
            "Enter message to broadcast to all devices:"
        )
        
        if ok and text.strip():
            # Send the broadcast message
            self.message_service.broadcast_message(
                content=text.strip(),
                msg_type=MessageType.INFO
            )
            
            # Refresh conversations
            self.messaging_tab.refresh_conversations()
    
    def _upload_files(self):
        """Upload files to clients"""
        # Switch to files tab
        self.tab_widget.setCurrentWidget(self.files_tab)
        
        # Call the upload method
        self.files_tab._upload_file()
    
    def _download_files(self):
        """Download files from clients"""
        # Switch to files tab
        self.tab_widget.setCurrentWidget(self.files_tab)
        
        # Call the download method
        self.files_tab._download_selected()
    
    def _search_files(self):
        """Search for files on clients"""
        # Switch to files tab
        self.tab_widget.setCurrentWidget(self.files_tab)
        
        # Prompt for search query
        text, ok = QInputDialog.getText(
            self, 
            "Search Files", 
            "Enter search query:"
        )
        
        if ok and text.strip():
            # Set the search input and trigger search
            self.files_tab.search_input.setText(text.strip())
            self.files_tab.search_files()
            
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
        
    def closeEvent(self, event):
        """Handle application close event"""
        # Clean up the DeviceManager
        if hasattr(self, 'device_manager'):
            self.device_manager.cleanup()
            
        # Stop the message service
        if hasattr(self, 'message_service'):
            self.message_service.stop()
            
        # Stop the message server
        if hasattr(self, 'message_server'):
            self.message_server.stop()
        
        # Call the base class implementation to continue with the close event
        super().closeEvent(event)