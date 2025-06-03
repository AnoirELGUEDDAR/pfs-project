"""
Logging utility functions
"""
import os
import logging
import logging.handlers
from datetime import datetime

def setup_logging(log_dir="logs", log_level=logging.INFO):
    """
    Setup application logging
    
    Args:
        log_dir: Directory for log files
        log_level: Default logging level
    """
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
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    console_handler.setFormatter(formatter)
    file_handler.setFormatter(formatter)
    
    # Add handlers to logger
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    
    logging.info(f"Logging initialized. Log file: {log_file}")
    
    return logger
