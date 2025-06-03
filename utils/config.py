import json
import os
from pathlib import Path

class Config:
    """Configuration manager for the Network Management Suite"""
    
    def __init__(self):
        # Get the application directory
        self.app_dir = Path.home() / '.network_management_suite'
        self.config_path = self.app_dir / 'config.json'
        
        # Default configuration
        self.default_config = {
            'scan_timeout': 2.0,
            'scan_threads': 100,
            'default_port_list': [22, 80, 443, 445, 3389, 8080],
            'auto_scan_interval': 1800,  # 30 minutes
            'interface': '',  # Default interface, empty means auto-detect
            'messenger_port': 12345,
            'monitoring_interval': 60,  # 1 minute
            'last_scan_range': '',
            'theme': 'dark',
            'notifications_enabled': True,
            'trusted_devices': {},  # MAC address -> device name mapping
            'wol_targets': {},      # Friendly name -> MAC address mapping
            'saved_credentials': {} # Encrypted credentials for remote access
        }
        
        # Create config directory if it doesn't exist
        if not self.app_dir.exists():
            self.app_dir.mkdir(parents=True)
        
        # Load or create config file
        self.config = self.load_config()
    
    def load_config(self):
        """Load configuration from file or create default if not exists"""
        if not self.config_path.exists():
            self.save_config(self.default_config)
            return self.default_config.copy()
        
        try:
            with open(self.config_path, 'r') as f:
                config = json.load(f)
                
            # Update with any missing default keys
            updated = False
            for key, value in self.default_config.items():
                if key not in config:
                    config[key] = value
                    updated = True
            
            if updated:
                self.save_config(config)
                
            return config
        except Exception as e:
            print(f"Error loading config: {e}")
            return self.default_config.copy()
    
    def save_config(self, config):
        """Save configuration to file"""
        try:
            with open(self.config_path, 'w') as f:
                json.dump(config, f, indent=4)
            return True
        except Exception as e:
            print(f"Error saving config: {e}")
            return False
    
    def get(self, key, default=None):
        """Get a configuration value"""
        return self.config.get(key, default)
    
    def set(self, key, value):
        """Set a configuration value and save"""
        self.config[key] = value
        return self.save_config(self.config)