#!/usr/bin/env python3
"""
Network Scanner & Management Tool
Author: AnoirELGUEDDAR
Date: 2025-04-20
Last Updated: 2025-05-04 14:31:20 UTC
User: AnoirELGUEDDAR
Version: 1.0.0

A comprehensive tool for network scanning, device discovery, remote management,
messaging, file searching and network monitoring on local networks.
"""

import sys
import os
import logging
from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPalette, QColor
from datetime import datetime

from utils.logging_utils import setup_logging
from gui.main_window import MainWindow
from config.settings import load_settings

def apply_dark_theme(app):
    """Apply dark theme to the entire application"""
    # Force the style to be the same on all OSs
    app.setStyle("Fusion")
    
    # Set dark theme palette
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
    
    app.setPalette(dark_palette)
    
    # Apply additional styling to ensure consistency
    app.setStyleSheet("""
        QToolTip {
            color: white;
            background-color: #2c3e50;
            border: 1px solid #34495e;
            border-radius: 3px;
        }
        QMessageBox {
            background-color: #1a2633;
            color: white;
        }
        QInputDialog {
            background-color: #1a2633;
            color: white;
        }
        QFileDialog {
            background-color: #1a2633;
            color: white;
        }
    """)

def main():
    # Setup logging
    setup_logging()
    logger = logging.getLogger('main')
    logger.info("Starting Network Scanner & Management Tool")
    logger.info(f"Application started by user: {os.getenv('USERNAME', 'AnoirELGUEDDAR')}")
    logger.info(f"Start time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    
    # Load application settings
    settings = load_settings()
    
    # Start GUI application
    app = QApplication(sys.argv)
    app.setApplicationName("Network Scanner & Management Tool")
    app.setOrganizationName("NetworkTools")
    
    # Apply dark theme to entire application
    apply_dark_theme(app)
    
    window = MainWindow(settings)
    window.show()
    
    # Check for icons directory and create if it doesn't exist
    if not os.path.exists("icons"):
        os.makedirs("icons")
        logger.info("Created icons directory")
    
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()