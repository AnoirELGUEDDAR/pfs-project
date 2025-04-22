#!/usr/bin/env python3
"""
Network Scanner & Management Tool
Author: AnoirELGUEDDAR
Date: 2025-04-20
Last Updated: 2025-04-20 17:46:16 UTC
User: AnoirELGUEDDAR
Version: 1.0.0

A comprehensive tool for network scanning, device discovery, remote management,
messaging, file searching and network monitoring on local networks.
"""

import sys
import os
import logging
from PyQt5.QtWidgets import QApplication
from datetime import datetime

from utils.logging_utils import setup_logging
from gui.main_window import MainWindow
from config.settings import load_settings

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
    app.setApplicationName("Network Scanner")
    app.setOrganizationName("NetworkTools")
    
    window = MainWindow(settings)
    window.show()
    
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()