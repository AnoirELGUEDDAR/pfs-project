import os

# Create directories if they don't exist
for dir_path in ["utils", "config", "core", "core/scanner", "gui"]:
    os.makedirs(dir_path, exist_ok=True)

# Create empty __init__.py files
for dir_path in ["utils", "config", "core", "core/scanner", "gui"]:
    with open(f"{dir_path}/__init__.py", "w", encoding="utf-8") as f:
        f.write("")

# Write logging_utils.py
with open("utils/logging_utils.py", "w", encoding="utf-8") as f:
    f.write("""\"\"\"
Logging utility functions
\"\"\"
import os
import logging
import logging.handlers
from datetime import datetime

def setup_logging(log_dir="logs", log_level=logging.INFO):
    \"\"\"
    Setup application logging
    
    Args:
        log_dir: Directory for log files
        log_level: Default logging level
    \"\"\"
    # Create logs directory if it doesn't exist
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # Generate log file name with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f"network_scanner_{timestamp}.log")
    
    # Create root logger
    logger = logging.getLogger()
    logger.setLevel(log_level)
    
    # Create handlers
    console_handler = logging.StreamHandler()
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=10485760,  # 10 MB
        backupCount=5
    )
    
    # Set formatter
    formatter = logging.Formatter(
        \"%(asctime)s - %(name)s - %(levelname)s - %(message)s\"
    )
    console_handler.setFormatter(formatter)
    file_handler.setFormatter(formatter)
    
    # Add handlers to logger
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    
    logging.info(f"Logging initialized. Log file: {log_file}")
    
    return logger
""")

# Write settings.py
with open("config/settings.py", "w", encoding="utf-8") as f:
    f.write("""\"\"\"
Application settings and configuration
\"\"\"
import os
import json
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

# Default configuration
DEFAULT_SETTINGS = {
    "general": {
        "theme": "system",
        "language": "en",
        "save_results_path": "results",
        "auto_save": False
    },
    "scanning": {
        "timeout": 3,
        "max_threads": 100,
        "default_ports": "21,22,23,25,53,80,443,445,3389,8080",
        "ping_before_scan": True,
        "scan_all_ports": False
    }
}

# Config file path
CONFIG_FILE = os.path.expanduser("~/.network_scanner/config.json")

def load_settings() -> Dict[str, Any]:
    \"\"\"
    Load application settings from config file or create default if not exists
    
    Returns:
        Dictionary containing application settings
    \"\"\"
    if not os.path.exists(CONFIG_FILE):
        return _create_default_settings()
    
    try:
        with open(CONFIG_FILE, "r") as f:
            settings = json.load(f)
        
        # Update with any new default settings
        updated = False
        for section, values in DEFAULT_SETTINGS.items():
            if section not in settings:
                settings[section] = values
                updated = True
            else:
                for key, value in values.items():
                    if key not in settings[section]:
                        settings[section][key] = value
                        updated = True
        
        if updated:
            save_settings(settings)
            logger.info("Settings updated with new default values")
            
        logger.info("Settings loaded successfully")
        return settings
    except Exception as e:
        logger.error(f"Error loading settings: {e}")
        return _create_default_settings()

def save_settings(settings: Dict[str, Any]) -> bool:
    \"\"\"
    Save settings to config file
    
    Args:
        settings: Dictionary containing application settings
        
    Returns:
        True if successful, False otherwise
    \"\"\"
    try:
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
        
        with open(CONFIG_FILE, "w") as f:
            json.dump(settings, f, indent=4)
            
        logger.info("Settings saved successfully")
        return True
    except Exception as e:
        logger.error(f"Error saving settings: {e}")
        return False

def _create_default_settings() -> Dict[str, Any]:
    \"\"\"
    Create and save default settings
    
    Returns:
        Dictionary containing default settings
    \"\"\"
    try:
        save_settings(DEFAULT_SETTINGS)
        logger.info("Default settings created")
    except Exception as e:
        logger.error(f"Error creating default settings: {e}")
    
    return DEFAULT_SETTINGS
""")

# Create a stub for MainWindow
with open("gui/main_window.py", "w", encoding="utf-8") as f:
    f.write("""\"\"\"
Main window for Network Scanner application
\"\"\"
import logging
from PyQt5.QtWidgets import QMainWindow, QLabel, QVBoxLayout, QWidget

logger = logging.getLogger(__name__)

class MainWindow(QMainWindow):
    \"\"\"Main application window\"\"\"
    
    def __init__(self, settings=None):
        super().__init__()
        self.settings = settings or {}
        self.setWindowTitle("Network Scanner")
        self.setMinimumSize(800, 600)
        
        # Create a simple layout with a label
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        label = QLabel("Network Scanner - Initial Setup")
        label.setStyleSheet("font-size: 24px;")
        layout.addWidget(label)
        
        info_label = QLabel("GUI components will be implemented here.")
        layout.addWidget(info_label)
""")

print("Files created successfully!")