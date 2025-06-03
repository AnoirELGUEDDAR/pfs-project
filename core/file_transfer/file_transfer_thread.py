"""
File transfer thread for handling file transfers in background
Current Date: 2025-05-10 12:10:00
Author: AnoirELGUEDDAR
"""
import os
import time
import random
import logging
from enum import Enum, auto
from typing import Optional

from PyQt5.QtCore import QThread, pyqtSignal

logger = logging.getLogger(__name__)

class TransferType(Enum):
    """File transfer direction"""
    UPLOAD = auto()
    DOWNLOAD = auto()

class FileTransferThread(QThread):
    """Thread for handling file transfers in the background"""
    
    # Signals for progress updates and completion
    progress_updated = pyqtSignal(int)  # Progress percentage
    transfer_completed = pyqtSignal(bool, str)  # Success, message
    
    def __init__(self, 
                file_path: str, 
                device_id: str, 
                destination: str, 
                transfer_type: TransferType, 
                file_service: Optional = None):
        """
        Initialize the file transfer thread
        
        Args:
            file_path: Path to the source file
            device_id: ID of the target/source device
            destination: Destination path
            transfer_type: Type of transfer (upload/download)
            file_service: Reference to the file service for backend operations
        """
        super().__init__()
        
        self.file_path = file_path
        self.device_id = device_id
        self.destination = destination
        self.transfer_type = transfer_type
        self.file_service = file_service
        
        self.cancelled = False
        self.transfer_id = None
        
        logger.debug(f"FileTransferThread initialized: {transfer_type.name} {file_path}")
    
    def run(self):
        """Main thread function executed when thread starts"""
        if self.transfer_type == TransferType.UPLOAD:
            self._perform_upload()
        else:
            self._perform_download()
    
    def _perform_upload(self):
        """Handle file upload process"""
        try:
            # Check if file exists
            if not os.path.isfile(self.file_path):
                self.transfer_completed.emit(False, "File not found")
                return
                
            # Get file size for progress calculation
            file_size = os.path.getsize(self.file_path)
            
            # If we have a file service, use it to initiate the transfer
            if self.file_service:
                success, message = self.file_service.upload_file(
                    self.file_path,
                    self.device_id,
                    self.destination
                )
                
                if not success:
                    self.transfer_completed.emit(False, message)
                    return
                    
                # Extract transfer ID if available
                if message.startswith("Transfer initiated with ID:"):
                    self.transfer_id = message.split(":")[-1].strip()
            
            # Simulate upload with progress updates
            # In a real implementation, this would monitor actual upload progress
            progress = 0
            
            while progress < 100 and not self.cancelled:
                # Simulate variable transfer speed
                increment = random.randint(1, 5)
                progress = min(progress + increment, 100)
                
                # Emit progress update
                self.progress_updated.emit(progress)
                
                # Short sleep to simulate transfer time
                time.sleep(0.1)
            
            # Complete the transfer
            if self.cancelled:
                self.transfer_completed.emit(False, "Transfer cancelled")
                
                # Cancel in file service if available
                if self.file_service and self.transfer_id:
                    self.file_service.cancel_transfer(self.transfer_id)
            else:
                # Final progress update
                self.progress_updated.emit(100)
                
                # For demonstration, simulate actual file copy to destination
                # This would be a copy to a staging area in a real implementation
                if os.path.dirname(self.destination) and not os.path.exists(os.path.dirname(self.destination)):
                    os.makedirs(os.path.dirname(self.destination), exist_ok=True)
                    
                # In a real implementation, we'd verify the upload with the remote device
                
                # Signal completion
                self.transfer_completed.emit(True, "Upload completed successfully")
                
                logger.info(f"Upload completed: {os.path.basename(self.file_path)} to {self.device_id}")
                
        except Exception as e:
            logger.error(f"Upload error: {str(e)}")
            self.transfer_completed.emit(False, f"Error: {str(e)}")
    
    def _perform_download(self):
        """Handle file download process"""
        try:
            # Get expected destination directory
            dest_dir = os.path.dirname(self.destination)
            
            # Create destination directory if it doesn't exist
            if dest_dir and not os.path.exists(dest_dir):
                os.makedirs(dest_dir, exist_ok=True)
            
            # If we have a file service, use it to initiate the transfer
            if self.file_service:
                success, message = self.file_service.download_file(
                    self.file_path,
                    self.device_id,
                    self.destination
                )
                
                if not success:
                    self.transfer_completed.emit(False, message)
                    return
                    
                # Extract transfer ID if available
                if message.startswith("Transfer initiated with ID:"):
                    self.transfer_id = message.split(":")[-1].strip()
            
            # Simulate download with progress updates
            # In a real implementation, this would monitor actual download progress
            progress = 0
            
            while progress < 100 and not self.cancelled:
                # Simulate variable transfer speed
                increment = random.randint(1, 5)
                progress = min(progress + increment, 100)
                
                # Emit progress update
                self.progress_updated.emit(progress)
                
                # Short sleep to simulate transfer time
                time.sleep(0.1)
            
            # Complete the transfer
            if self.cancelled:
                self.transfer_completed.emit(False, "Transfer cancelled")
                
                # Cancel in file service if available
                if self.file_service and self.transfer_id:
                    self.file_service.cancel_transfer(self.transfer_id)
            else:
                # Final progress update
                self.progress_updated.emit(100)
                
                # For demonstration, create a dummy file to simulate successful download
                # In a real implementation, this would be the actual file from the remote device
                
                # Create a dummy file for demonstration
                file_name = os.path.basename(self.file_path)
                file_ext = os.path.splitext(file_name)[1].lower()
                
                with open(self.destination, 'wb') as f:
                    # Different file types get different content
                    if file_ext == '.txt':
                        f.write(f"This is demo content for {file_name}\n".encode('utf-8'))
                        f.write(f"Downloaded from {self.device_id}\n".encode('utf-8'))
                        f.write(f"Original path: {self.file_path}\n".encode('utf-8'))
                        f.write(f"Current date: {time.ctime()}\n".encode('utf-8'))
                    elif file_ext in ['.jpg', '.png', '.gif']:
                        # Create a small binary file to simulate an image
                        f.write(b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\xff\xff?\x00\x05\x00\x01\xf6\x178U\x00\x00\x00\x00IEND\xaeB`\x82')
                    elif file_ext in ['.pdf', '.doc', '.docx']:
                        # Create a slightly larger dummy file
                        f.write(b'%PDF-1.4\n%\xe2\xe3\xcf\xd3\n4 0 obj\n<</Type/Page/Parent 3 0 R>>\nendobj\n')
                        f.write(f"Demo file {file_name} content\n".encode('utf-8'))
                    else:
                        # Generic binary data for other types
                        f.write(os.urandom(1024))  # 1KB of random data
                
                # Signal completion
                self.transfer_completed.emit(True, "Download completed successfully")
                
                logger.info(f"Download completed: {file_name} from {self.device_id}")
                
        except Exception as e:
            logger.error(f"Download error: {str(e)}")
            self.transfer_completed.emit(False, f"Error: {str(e)}")
    
    def cancel(self):
        """Cancel the transfer"""
        self.cancelled = True
        
        # In a real implementation, we would send a cancel request to the file service
        if self.file_service and self.transfer_id:
            self.file_service.cancel_transfer(self.transfer_id)