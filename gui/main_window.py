"""
Main window for the Network Scanner & Management Tool
Current Date and Time (UTC): 2025-05-12 23:26:21
Author: AnoirELGUEDDAR
"""
import logging
import os
from datetime import datetime
from typing import Dict

from PyQt5.QtWidgets import (
    QMainWindow, QTabWidget, QVBoxLayout, QHBoxLayout,
    QWidget, QPushButton, QStatusBar, QAction, QMenu,
    QToolBar, QLabel, QMessageBox, QFileDialog, QInputDialog,
    QStackedWidget, QGraphicsOpacityEffect
)
from PyQt5.QtCore import (
    Qt, QSize, QTimer, QEasingCurve, QPropertyAnimation, 
    QParallelAnimationGroup, QSequentialAnimationGroup, QPoint, pyqtSlot
)
from PyQt5.QtGui import QIcon, QFont, QPalette, QColor

# Use your actual file names as they exist in the project
from gui.scanner_tab import ScannerTab
from gui.devices_tab import DevicesTab
from gui.remote_tab import RemoteTab
from gui.monitoring_tab import MonitoringTab
from gui.messaging_tab import MessagingTab, NewMessageDialog, ClientMessagingMode
from gui.files_tab import FilesTab

from core.messaging.message_service import MessageService
from core.messaging.message import Message, MessageType
from core.messaging.message_server import MessageServer
from core.file_transfer.file_service import FileTransferService

# Import the DeviceManager for remote device management
from core.remote.device_manager import DeviceManager

logger = logging.getLogger(__name__)

class AnimatedButton(QPushButton):
    """Button with hover animation effect"""
    
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setMouseTracking(True)
        self._hovered = False
        self._original_stylesheet = ""
        self._hover_stylesheet = ""
        
    def setStyleSheets(self, original, hover):
        """Set the normal and hover stylesheets"""
        self._original_stylesheet = original
        self._hover_stylesheet = hover
        self.setStyleSheet(self._original_stylesheet)
        
    def enterEvent(self, event):
        """Handle mouse enter event"""
        if not self._hovered:
            self._hovered = True
            # Use QTimer to prevent painting issues
            QTimer.singleShot(10, self._apply_hover_style)
        super().enterEvent(event)
        
    def leaveEvent(self, event):
        """Handle mouse leave event"""
        if self._hovered:
            self._hovered = False
            # Use QTimer to prevent painting issues
            QTimer.singleShot(10, self._apply_normal_style)
        super().leaveEvent(event)
        
    def _apply_hover_style(self):
        """Apply hover style with scale effect"""
        if self._hovered and self._hover_stylesheet:
            self.setStyleSheet(self._hover_stylesheet)
    
    def _apply_normal_style(self):
        """Apply normal style"""
        if not self._hovered and self._original_stylesheet:
            self.setStyleSheet(self._original_stylesheet)

class MainWindow(QMainWindow):
    """Main application window"""
    
    def __init__(self, settings: Dict = None):
        super().__init__()
        
        self.settings = settings or {}
        self.setWindowTitle("Network Scanner & Management Tool")
        self.setMinimumSize(1366, 768)
        
        # Initialize MessageService
        self.message_service = MessageService()
        
        # Set administrator username
        self.message_service.set_username("ADMIN")
        
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
        
        # Set up variables for animations
        self.pulse_timer = None
        self.pulse_growing = True
        self.current_pulse_size = 0
        
        # Apply dark theme to the entire application
        self._apply_dark_theme()
        
        # Setup UI
        self._setup_ui()
        
        # Apply startup animation - using a gentler approach
        self._setup_startup_animation()
        
        # Add debug button for diagnostics
        self.debug_btn = QPushButton("Debug Integration", self)
        self.debug_btn.clicked.connect(self._debug_integration)
        self.statusBar().addPermanentWidget(self.debug_btn)
        
        logger.info("Main window initialized")
        self.status_bar.showMessage(f"Ready - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Send welcome message
        welcome_msg = Message(
            content=f"Application started successfully at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            msg_type=MessageType.INFO,
            sender="System"
        )
        self.message_service.send_message(welcome_msg)
    
    def _debug_integration(self):
        """Debug tab integration"""
        print("\n--- DEBUG INTEGRATION ---")
        scanner_devices = len(self.scanner_tab.devices) if hasattr(self.scanner_tab, 'devices') else "devices attribute not found"
        print(f"Scanner has {scanner_devices} devices")
        
        # Check if monitoring tab can access devices
        if hasattr(self, 'monitoring_tab'):
            print(f"Monitoring tab exists: {self.monitoring_tab is not None}")
            # Check direct reference
            if hasattr(self.monitoring_tab, 'scanner_devices'):
                print(f"scanner_devices attribute exists with {len(self.monitoring_tab.scanner_devices) if isinstance(self.monitoring_tab.scanner_devices, list) else 'not a list'}")
            else:
                print("scanner_devices attribute doesn't exist on monitoring_tab")
            
            # Check device_manager
            if hasattr(self.monitoring_tab, 'device_manager'):
                print(f"device_manager exists: {self.monitoring_tab.device_manager is not None}")
                
                if self.monitoring_tab.device_manager is self.scanner_tab:
                    print("device_manager is correctly set to scanner_tab")
                else:
                    print("device_manager is NOT set to scanner_tab")
                
                if hasattr(self.monitoring_tab.device_manager, 'devices'):
                    print(f"device_manager.devices exists with {len(self.monitoring_tab.device_manager.devices) if isinstance(self.monitoring_tab.device_manager.devices, list) else 'not a list'}")
                else:
                    print("device_manager.devices doesn't exist")
        
        print("--- END DEBUG ---\n")
        
        # Update direct reference again
        self.monitoring_tab.scanner_devices = self.scanner_tab.devices
        print(f"Direct reference updated. monitoring_tab.scanner_devices now has {len(self.scanner_tab.devices)} devices")
    
    def _setup_startup_animation(self):
        """Set up a safer, timer-based startup animation"""
        self.central_widget.setVisible(False)
        QTimer.singleShot(100, self._fade_in_ui)
    
    def _fade_in_ui(self):
        """Fade in the UI elements safely"""
        self.central_widget.setVisible(True)
        # Start pulse timer for the scan button
        QTimer.singleShot(500, self._start_safe_pulse)
        
    def _start_safe_pulse(self):
        """Start a safer pulsing animation for the scan button"""
        if hasattr(self, "pulse_timer") and self.pulse_timer is None:
            self.pulse_timer = QTimer(self)
            self.pulse_timer.timeout.connect(self._update_scan_button_pulse)
            self.pulse_timer.start(50)  # 20 fps
    
    def _stop_safe_pulse(self):
        """Stop the pulse animation safely"""
        if self.pulse_timer is not None:
            self.pulse_timer.stop()
            self.pulse_timer = None
            # Reset the button style
            if hasattr(self, 'start_scan_btn'):
                self.start_scan_btn.setStyleSheet("""
                    QPushButton {
                        background-color: #0078d7;
                        color: white;
                        border-radius: 100px;
                        font-size: 22px;
                        font-weight: bold;
                    }
                    QPushButton:hover {
                        background-color: #0086f0;
                    }
                    QPushButton:pressed {
                        background-color: #0066b8;
                    }
                """)
    
    def _update_scan_button_pulse(self):
        """Update the pulse effect for the scan button using stylesheet only"""
        if not hasattr(self, 'start_scan_btn'):
            return
            
        # Use stylesheet-based animation instead of geometry
        if self.pulse_growing:
            self.current_pulse_size += 1
            if self.current_pulse_size >= 10:
                self.pulse_growing = False
        else:
            self.current_pulse_size -= 1
            if self.current_pulse_size <= 0:
                self.pulse_growing = True
                
        # Apply shadow effect simulating pulse
        self.start_scan_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: #0078d7;
                color: white;
                border-radius: 100px;
                font-size: 22px;
                font-weight: bold;
                border: {self.current_pulse_size}px solid rgba(0, 120, 215, 0.{3+self.current_pulse_size});
            }}
            QPushButton:hover {{
                background-color: #0086f0;
            }}
            QPushButton:pressed {{
                background-color: #0066b8;
            }}
        """)
        
    def _apply_dark_theme(self):
        """Apply dark theme to the application"""
        dark_palette = QPalette()
        dark_color = QColor(26, 38, 51)  # #1a2633
        dark_palette.setColor(QPalette.Window, dark_color)
        dark_palette.setColor(QPalette.WindowText, Qt.white)
        dark_palette.setColor(QPalette.Base, QColor(18, 30, 43))
        dark_palette.setColor(QPalette.AlternateBase, dark_color)
        dark_palette.setColor(QPalette.ToolTipBase, Qt.white)
        dark_palette.setColor(QPalette.ToolTipText, Qt.white)
        dark_palette.setColor(QPalette.Text, Qt.white)
        dark_palette.setColor(QPalette.Button, dark_color)
        dark_palette.setColor(QPalette.ButtonText, Qt.white)
        dark_palette.setColor(QPalette.BrightText, Qt.red)
        dark_palette.setColor(QPalette.Link, QColor(0, 120, 215))
        dark_palette.setColor(QPalette.Highlight, QColor(0, 120, 215))
        dark_palette.setColor(QPalette.HighlightedText, Qt.white)
        
        self.setPalette(dark_palette)
        
        # Style sheet for more specific styling
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1a2633;
            }
            QMenuBar {
                background-color: #1a2633;
                color: white;
            }
            QMenuBar::item {
                background-color: #1a2633;
                color: white;
            }
            QMenuBar::item:selected {
                background-color: #2c3e50;
            }
            QMenu {
                background-color: #1a2633;
                color: white;
            }
            QMenu::item:selected {
                background-color: #2c3e50;
            }
            QToolBar {
                background-color: #1a2633;
                color: white;
                border: none;
            }
            QToolButton {
                color: white;
                background-color: transparent;
                padding: 6px;
            }
            QToolButton:hover {
                background-color: #2c3e50;
            }
            QTabWidget::pane {
                border: 1px solid #2c3e50;
                background-color: #1a2633;
            }
            QTabBar::tab {
                background-color: #1a2633;
                color: white;
                padding: 8px 12px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #0078d7;
            }
            QTabBar::tab:!selected {
                background-color: #2c3e50;
            }
            QPushButton {
                background-color: #2c3e50;
                color: white;
                border: none;
                padding: 6px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #34495e;
            }
            QPushButton:pressed {
                background-color: #1c2e40;
            }
            QLineEdit, QTextEdit, QPlainTextEdit, QComboBox {
                background-color: #2c3e50;
                color: white;
                border: 1px solid #34495e;
                border-radius: 3px;
                padding: 3px;
            }
            QTableView, QTreeView, QListView {
                background-color: #1a2633;
                color: white;
                border: 1px solid #2c3e50;
            }
            QHeaderView::section {
                background-color: #2c3e50;
                color: white;
                padding: 4px;
                border: none;
            }
            QStatusBar {
                background-color: #1a2633;
                color: white;
            }
        """)
        
    def _setup_ui(self):
        """Setup the user interface"""
        # Central widget
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        # Main layout
        self.main_layout = QVBoxLayout(self.central_widget)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)
        
        # Create stacked widget for different screens
        self.stacked_widget = QStackedWidget()
        self.main_layout.addWidget(self.stacked_widget)
        
        # Create home screen
        self.home_screen = self._create_home_screen()
        
        # Create tab screen (contains all functionality tabs)
        self.tab_screen = QWidget()
        self.tab_layout = QVBoxLayout(self.tab_screen)
        self.tab_layout.setContentsMargins(5, 5, 5, 5)
        
        # Tab widget (for functionality screens)
        self.tab_widget = QTabWidget()
        self.tab_layout.addWidget(self.tab_widget)
        
        # Add both screens to stacked widget
        self.stacked_widget.addWidget(self.home_screen)
        self.stacked_widget.addWidget(self.tab_screen)
        
        # Create scanner tab FIRST (this is crucial)
        self.scanner_tab = ScannerTab()
        
        # Create other tabs
        self.devices_tab = DevicesTab()
        self.remote_tab = RemoteTab()
        self.messaging_tab = MessagingTab(self.message_service)
        
        # Add scanner tab first
        self.tab_widget.addTab(self.scanner_tab, "Network Scanner")
        
        # Now initialize monitoring tab with reference to scanner
        self.monitoring_tab = MonitoringTab(self, device_manager=self.scanner_tab)
        
        # CRITICAL: Set up direct reference to devices
        self.monitoring_tab.scanner_devices = self.scanner_tab.devices
        
        # Initialize Files Tab with our implementation - Use DeviceManager
        self.files_tab = FilesTab(
            self.device_manager,  # Pass the device_manager instead of None
            self.file_service,
            self.message_service
        )
        
        # Add remaining tabs to widget
        self.tab_widget.addTab(self.devices_tab, "Devices")
        self.tab_widget.addTab(self.remote_tab, "Remote Management")
        self.tab_widget.addTab(self.messaging_tab, "Messaging")
        self.tab_widget.addTab(self.files_tab, "Files")
        self.tab_widget.addTab(self.monitoring_tab, "Monitoring")
        
        # FIX: Connect scanner tab signals to devices tab through adapter
        self.scanner_tab.device_discovered.connect(self._device_discovered_adapter)
        
        # Connect scanner tab signals to send messages
        self.scanner_tab.device_discovered.connect(self._on_device_discovered_adapter)
        
        # Connect signal to update monitoring tab when scan completes
        self.scanner_tab.scan_completed_signal.connect(self._update_monitoring_reference)
        
        # Setup status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        # Setup menu bar
        self._setup_menu()
        
        # Show home screen by default
        self.stacked_widget.setCurrentIndex(0)
    
    def _update_monitoring_reference(self):
        """Update monitoring tab's reference to scanner devices after scan completes"""
        print("Scan completed - updating monitoring tab reference")
        device_count = len(self.scanner_tab.devices) if hasattr(self.scanner_tab, 'devices') else 0
        print(f"Scanner has {device_count} devices now")
        
        # Update the reference
        self.monitoring_tab.scanner_devices = self.scanner_tab.devices
        
        # Print device count
        print(f"Monitoring tab now has reference to {device_count} devices")
        
    # FIX: Add adapter methods for signal/slot compatibility
        
    @pyqtSlot(str, str, str, str)
    def _device_discovered_adapter(self, ip, mac, hostname, manufacturer):
        """Adapter method to connect ScannerTab signals to DevicesTab
        
        This resolves the incompatible signature between ScannerTab.device_discovered
        and DevicesTab.add_device_from_scan
        """
        device_info = {
        'ip': ip,
        'mac': mac,
        'hostname': hostname,
        'manufacturer': manufacturer
    }
        # Call the devices tab method with correct parameters (likely just 3)
        self.devices_tab.add_device_from_scan(device_info)
    
    @pyqtSlot(str, str, str, str)
    def _on_device_discovered_adapter(self, ip, mac, hostname, manufacturer):
        """Adapter method for device discovery to message service"""
        # Create a device info dictionary from the separate parameters
        device_info = {
            'ip': ip,
            'mac': mac,
            'hostname': hostname,
            'manufacturer': manufacturer
        }
        
        # Call the original method with the dictionary
        self._on_device_discovered(device_info)
        
    def _create_home_screen(self):
        """Create the home screen widget as shown in the image"""
        home_widget = QWidget()
        home_layout = QVBoxLayout(home_widget)
        home_layout.setContentsMargins(20, 20, 20, 20)
        home_layout.setSpacing(20)
        
        # Center title layout
        center_layout = QVBoxLayout()
        center_layout.setAlignment(Qt.AlignCenter)
        
        # Title
        title_label = QLabel("Network Scanner & Management tool")
        title_label.setObjectName("mainTitle")
        title_label.setAlignment(Qt.AlignCenter)
        title_font = QFont()
        title_font.setPointSize(36)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setMinimumWidth(900)
        title_label.setStyleSheet("color: white; font-size: 40pt; font-weight: bold; margin: 0 30px;")
        # Subtitle
        subtitle_label = QLabel("Your Network, Under Control.")
        subtitle_label.setAlignment(Qt.AlignCenter)
        subtitle_font = QFont()
        subtitle_font.setPointSize(14)
        subtitle_label.setFont(subtitle_font)
        subtitle_label.setStyleSheet("color: #cccccc;")
        
        # Add to center layout
        center_layout.addWidget(title_label)
        center_layout.addWidget(subtitle_label)
        home_layout.addSpacing(30)
        # Add center layout to main layout with stretch
        home_layout.addStretch(1)
        home_layout.addLayout(center_layout)
        home_layout.addStretch(1)
        
        # Central start scan button - using regular QPushButton instead of custom class
        self.start_scan_btn = QPushButton("Start Scan")
        self.start_scan_btn.setFixedSize(200, 200)
        self.start_scan_btn.setStyleSheet("""
            QPushButton {
                background-color: #0078d7;
                color: white;
                border-radius: 100px;
                font-size: 22px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #0086f0;
            }
            QPushButton:pressed {
                background-color: #0066b8;
            }
        """)
        self.start_scan_btn.clicked.connect(self._start_scan_from_home)
        
        # Center the button
        button_layout = QHBoxLayout()
        button_layout.addStretch(1)
        button_layout.addWidget(self.start_scan_btn)
        button_layout.addStretch(1)
        
        home_layout.addLayout(button_layout)
        home_layout.addStretch(1)
        
        # Feature buttons layout
        feature_layout = QHBoxLayout()
        feature_layout.setSpacing(15)
        
        # Create circular feature buttons with CSS-based hover effects
        self.feature_buttons = []
        features = [
            ("Scanner", self._go_to_scanner_tab),
            ("Devices", self._go_to_devices_tab),
            ("Remote", self._go_to_remote_tab),
            ("Messaging", self._go_to_messaging_tab),
            ("Files", self._go_to_files_tab),
            ("Monitoring", self._go_to_monitoring_tab)
        ]
        
        for text, callback in features:
            button = AnimatedButton(text)
            button.setFixedSize(100, 100)
            button.setStyleSheets(
                original="""
                    background-color: #2c3e50;
                    color: white;
                    border-radius: 50px;
                """,
                hover="""
                    background-color: #34495e;
                    color: white;
                    border-radius: 50px;
                    border: 3px solid #0078d7;
                """
            )
            button.clicked.connect(callback)
            feature_layout.addWidget(button)
            self.feature_buttons.append(button)
            
        # Center the feature buttons
        feature_container_layout = QHBoxLayout()
        feature_container_layout.addStretch(1)
        feature_container_layout.addLayout(feature_layout)
        feature_container_layout.addStretch(1)
        
        home_layout.addLayout(feature_container_layout)
        home_layout.addStretch(1)
        
        return home_widget
    
    # Navigation methods with safe transitions
    def _change_screen(self, index):
        """Change screen with safer animation approach"""
        if self.stacked_widget.currentIndex() == index:
            return
            
        # Stop the pulse animation if moving away from home
        if self.stacked_widget.currentIndex() == 0:
            self._stop_safe_pulse()
            
        # Use a timer to delay the screen change for smoother visual effect
        self.stacked_widget.setCurrentIndex(index)
        
        # If returning to home screen, restart the pulse
        if index == 0:
            QTimer.singleShot(300, self._start_safe_pulse)
    
    def _start_scan_from_home(self):
        """Start scan from the home screen button"""
        # Change appearance briefly to give feedback
        self.start_scan_btn.setStyleSheet("""
            QPushButton {
                background-color: #0066b8;
                color: white;
                border-radius: 100px;
                font-size: 22px;
                font-weight: bold;
            }
        """)
        
        # Stop pulsing
        self._stop_safe_pulse()
        
        # Change to scanner tab with a slight delay for visual feedback
        QTimer.singleShot(150, lambda: self._change_screen(1))
        QTimer.singleShot(300, lambda: self._start_scan())
    
    def _go_to_scanner_tab(self):
        """Navigate to scanner tab"""
        self._change_screen(1)
        QTimer.singleShot(50, lambda: self.tab_widget.setCurrentWidget(self.scanner_tab))
    
    def _go_to_devices_tab(self):
        """Navigate to devices tab"""
        self._change_screen(1)
        QTimer.singleShot(50, lambda: self.tab_widget.setCurrentWidget(self.devices_tab))
    
    def _go_to_remote_tab(self):
        """Navigate to remote tab"""
        self._change_screen(1)
        QTimer.singleShot(50, lambda: self.tab_widget.setCurrentWidget(self.remote_tab))
    
    def _go_to_messaging_tab(self):
        """Navigate to messaging tab"""
        self._change_screen(1)
        QTimer.singleShot(50, lambda: self.tab_widget.setCurrentWidget(self.messaging_tab))
    
    def _go_to_files_tab(self):
        """Navigate to files tab"""
        self._change_screen(1)
        QTimer.singleShot(50, lambda: self.tab_widget.setCurrentWidget(self.files_tab))
    
    def _go_to_monitoring_tab(self):
        """Navigate to monitoring tab"""
        # Update the monitoring tab's reference to scanner devices before showing
        self.monitoring_tab.scanner_devices = self.scanner_tab.devices
        
        self._change_screen(1)
        QTimer.singleShot(50, lambda: self.tab_widget.setCurrentWidget(self.monitoring_tab))
    
    def _go_to_home(self):
        """Navigate back to home screen"""
        self._change_screen(0)
        
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
        
        home_action = QAction("&Home", self)
        home_action.setStatusTip("Return to home screen")
        home_action.triggered.connect(self._go_to_home)
        file_menu.addAction(home_action)
        
        file_menu.addSeparator()
        
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
        file_transfer_menu = self.menuBar().addMenu("F&iles")
        
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
        
        # Debug menu item
        debug_action = QAction("&Debug Integration", self)
        debug_action.setStatusTip("Debug tab integration")
        debug_action.triggered.connect(self._debug_integration)
        tools_menu.addAction(debug_action)
        
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
        
        # Add home button
        home_action = QAction(QIcon("icons/home.png") if os.path.exists("icons/home.png") else "Home", self)
        home_action.setStatusTip("Return to home screen")
        home_action.triggered.connect(self._go_to_home)
        toolbar.addAction(home_action)
        
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
            self.scanner_tab._export_results()  # Changed to match the actual method name
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
        self._change_screen(1)
        self.tab_widget.setCurrentWidget(self.scanner_tab)
        
        # Start scanning after a brief delay for UI to update
        QTimer.singleShot(100, lambda: self.scanner_tab._start_scan())  # Changed to match actual method name
        
        # Send notification message
        message = Message(
            content="Network scan started",
            msg_type=MessageType.INFO,
            sender="System"
        )
        self.message_service.send_message(message)
        
    def _stop_scan(self):
        """Stop network scan from menu or toolbar"""
        # If we're on the home screen, do nothing
        if self.stacked_widget.currentIndex() == 0:
            return
            
        self.scanner_tab._stop_scan()  # Changed to match actual method name
        
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
            self.scanner_tab._scan_ports()  # Changed to match actual method name
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
        self._change_screen(1)
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
                sender="ADMIN",
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
        self._change_screen(1)
        self.tab_widget.setCurrentWidget(self.files_tab)
        
        # Call the upload method
        self.files_tab._upload_file()
    
    def _download_files(self):
        """Download files from clients"""
        # Switch to files tab
        self._change_screen(1)
        self.tab_widget.setCurrentWidget(self.files_tab)
        
        # Call the download method
        self.files_tab._download_selected()
    
    def _search_files(self):
        """Search for files on clients"""
        # Switch to files tab
        self._change_screen(1)
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
            "Author: ADMIN\n\n"
            "A comprehensive tool for network scanning, device discovery, remote management, "
            "messaging, file searching and network monitoring on local networks.\n\n"
            "Last updated: 2025-05-12 23:26:21"
        )
        
    def closeEvent(self, event):
        """Handle application close event"""
        # Clean up animations before closing
        self._stop_safe_pulse()
        
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