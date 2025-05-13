#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Network Scanner & Management Tool
Main application entry point
Current Date: 2025-05-10 13:29:32
Author: AnoirELGUEDDAR
"""

import sys
import os
import logging
import logging.handlers
import platform
from datetime import datetime

from PyQt5.QtWidgets import (
    QApplication, QSplashScreen, QLabel, QCheckBox, 
    QGroupBox, QRadioButton  # Added these imports
)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QPixmap, QFont

# Import main window
from gui.main_window import MainWindow
from gui.style_manager import StyleManager

# Set up logging
def setup_logging():
    """Configure application logging"""
    log_dir = "logs"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    log_file = os.path.join(log_dir, f"network_scanner_{datetime.now().strftime('%Y%m%d')}.log")
    
    # Configure root logger
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    
    # File handler with rotation
    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=5*1024*1024, backupCount=3, encoding='utf-8'
    )
    file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_formatter = logging.Formatter('%(levelname)s: %(message)s')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    return logger

def main():
    """Main application entry point"""
    # Initialize logging
    logger = setup_logging()
    logger.info(f"Starting Network Scanner & Management Tool")
    logger.info(f"Platform: {platform.platform()}, Python: {platform.python_version()}")
    
    # Check OS permissions
    if platform.system() == "Windows":
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            logger.warning("Application not running with admin privileges. Some features may be limited.")
    elif platform.system() in ["Linux", "Darwin"]:
        if os.geteuid() != 0:
            logger.warning("Application not running with root privileges. Some features may be limited.")
    
    # Initialize application
    app = QApplication(sys.argv)
    app.setApplicationName("Network Scanner & Management Tool")
    app.setOrganizationName("AnoirELGUEDDAR")
    
    # Set default font
    default_font = QFont("Segoe UI", 10)
    app.setFont(default_font)
    
    # Show splash screen if available
    splash = None
    if os.path.exists("icons/splash.png"):
        splash_pixmap = QPixmap("icons/splash.png")
        splash = QSplashScreen(splash_pixmap, Qt.WindowStaysOnTopHint)
        splash.show()
        splash.showMessage("Loading...", Qt.AlignBottom | Qt.AlignCenter, Qt.white)
        app.processEvents()
    
    # Apply style
    StyleManager.apply_style(app)
    
    # CRITICAL FIX: Force white text on all standard widgets
    # This will override any other styling and ensure text is visible
    app.setStyleSheet(app.styleSheet() + """
    QLabel { color: white !important; }
    QGroupBox { color: white !important; }
    QCheckBox { color: white !important; }
    QRadioButton { color: white !important; }
    QGroupBox::title { color: white !important; }
    QTabBar::tab { color: white !important; }
    """)
    
    # Create main window
    main_window = MainWindow()
    
    # Direct label color fix for all tabs
    def fix_all_labels():
        for widget in main_window.findChildren(QLabel):
            widget.setStyleSheet("color: white;")
        for widget in main_window.findChildren(QCheckBox):
            widget.setStyleSheet("color: white;")
        for widget in main_window.findChildren(QGroupBox):
            widget.setStyleSheet("color: white;")
        for widget in main_window.findChildren(QRadioButton):
            widget.setStyleSheet("color: white;")
    
    # Close splash and show main window
    if splash:
        QTimer.singleShot(1500, splash.close)
        QTimer.singleShot(1500, main_window.show)
        QTimer.singleShot(1600, fix_all_labels)  # Apply fix after window is shown
    else:
        main_window.show()
        QTimer.singleShot(100, fix_all_labels)  # Apply fix after window is shown
    
    # Run the application event loop
    exit_code = app.exec_()
    
    logger.info(f"Application exited with code {exit_code}")
    return exit_code

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        logging.critical(f"Unhandled exception: {str(e)}", exc_info=True)
        sys.exit(1)