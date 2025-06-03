import logging
import sys
from pathlib import Path
from datetime import datetime

class Logger:
    """Logging utility for the Network Management Suite"""
    
    def __init__(self, name='network_management_suite'):
        # Create logs directory
        self.logs_dir = Path.home() / '.network_management_suite' / 'logs'
        if not self.logs_dir.exists():
            self.logs_dir.mkdir(parents=True)
        
        # Set up logging
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        
        # Set up console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(console_format)
        
        # Set up file handler
        log_file = self.logs_dir / f"{datetime.now().strftime('%Y-%m-%d')}.log"
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(file_format)
        
        # Add handlers
        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)
    
    def debug(self, message):
        """Log debug message"""
        self.logger.debug(message)
    
    def info(self, message):
        """Log info message"""
        self.logger.info(message)
    
    def warning(self, message):
        """Log warning message"""
        self.logger.warning(message)
    
    def error(self, message):
        """Log error message"""
        self.logger.error(message)
    
    def critical(self, message):
        """Log critical message"""
        self.logger.critical(message)