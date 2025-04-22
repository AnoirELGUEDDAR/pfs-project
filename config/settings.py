"""
Application settings and configuration
"""
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
    """
    Load application settings from config file or create default if not exists
    
    Returns:
        Dictionary containing application settings
    """
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
    """
    Save settings to config file
    
    Args:
        settings: Dictionary containing application settings
        
    Returns:
        True if successful, False otherwise
    """
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
    """
    Create and save default settings
    
    Returns:
        Dictionary containing default settings
    """
    try:
        save_settings(DEFAULT_SETTINGS)
        logger.info("Default settings created")
    except Exception as e:
        logger.error(f"Error creating default settings: {e}")
    
    return DEFAULT_SETTINGS
