"""
File transfer service for managing file transfers between devices
Current Date: 2025-05-10 12:02:05
Author: AnoirELGUEDDAR
"""
import os
import shutil
import logging
import uuid
import json
from datetime import datetime
from enum import Enum, auto
from typing import Dict, List, Any, Optional, Tuple

logger = logging.getLogger(__name__)

class TransferStatus(Enum):
    """File transfer status"""
    PENDING = auto()
    TRANSFERRING = auto()
    COMPLETED = auto()
    FAILED = auto()
    CANCELLED = auto()

class FileTransferService:
    """Service for managing file transfers between devices"""
    
    def __init__(self, storage_dir: str = "file_storage"):
        """Initialize the file transfer service"""
        self.storage_dir = storage_dir
        
        # Create storage directory if it doesn't exist
        if not os.path.exists(storage_dir):
            os.makedirs(storage_dir)
        
        # Track active transfers
        self.active_transfers = {}  # {transfer_id: transfer_info}
        
        # Track shared files
        self.shared_files = {}  # {file_id: {path, name, owner, shared_with, permissions}}
        
        # Load shared files from disk if available
        self._load_shared_files()
        
        logger.info("FileTransferService initialized")
    
    def upload_file(self, file_path: str, device_id: str, destination: str) -> Tuple[bool, str]:
        """
        Upload a file to a remote device
        
        Args:
            file_path: Path to the file to upload
            device_id: ID of the target device
            destination: Destination path on the target device
            
        Returns:
            (success, message) tuple
        """
        # In a real implementation, this would communicate with the remote device
        # For demo purposes, we'll simulate successful uploads with a delay
        
        try:
            # Check if file exists
            if not os.path.isfile(file_path):
                return False, "File not found"
                
            # Generate a transfer ID
            transfer_id = str(uuid.uuid4())
            
            # Create transfer record
            transfer = {
                'id': transfer_id,
                'file_path': file_path,
                'device_id': device_id,
                'destination': destination,
                'direction': 'upload',
                'status': TransferStatus.PENDING.name,
                'start_time': datetime.now().isoformat(),
                'size': os.path.getsize(file_path),
                'progress': 0,
            }
            
            # Store the transfer
            self.active_transfers[transfer_id] = transfer
            
            # In a real implementation, the file would be sent to the remote device
            # Here we'll just simulate success
            
            # Log transfer
            logger.info(f"File upload initiated: {os.path.basename(file_path)} to {device_id}")
            
            return True, f"Transfer initiated with ID: {transfer_id}"
            
        except Exception as e:
            logger.error(f"Error starting upload: {str(e)}")
            return False, f"Error: {str(e)}"
    
    def download_file(self, file_path: str, device_id: str, destination: str) -> Tuple[bool, str]:
        """
        Download a file from a remote device
        
        Args:
            file_path: Path to the file on the remote device
            device_id: ID of the source device
            destination: Destination path on the local system
            
        Returns:
            (success, message) tuple
        """
        # In a real implementation, this would communicate with the remote device
        # For demo purposes, we'll simulate successful downloads with a delay
        
        try:
            # Generate a transfer ID
            transfer_id = str(uuid.uuid4())
            
            # Create transfer record
            transfer = {
                'id': transfer_id,
                'file_path': file_path,
                'device_id': device_id,
                'destination': destination,
                'direction': 'download',
                'status': TransferStatus.PENDING.name,
                'start_time': datetime.now().isoformat(),
                'size': 0,  # Unknown until download starts
                'progress': 0,
            }
            
            # Store the transfer
            self.active_transfers[transfer_id] = transfer
            
            # In a real implementation, the file would be requested from the remote device
            # Here we'll just simulate success by creating a dummy file
            
            # Log transfer
            logger.info(f"File download initiated: {os.path.basename(file_path)} from {device_id}")
            
            return True, f"Transfer initiated with ID: {transfer_id}"
            
        except Exception as e:
            logger.error(f"Error starting download: {str(e)}")
            return False, f"Error: {str(e)}"
    
    def get_transfer_status(self, transfer_id: str) -> Dict[str, Any]:
        """
        Get the status of a transfer
        
        Args:
            transfer_id: ID of the transfer
            
        Returns:
            Transfer information or empty dict if not found
        """
        return self.active_transfers.get(transfer_id, {})
    
    def cancel_transfer(self, transfer_id: str) -> Tuple[bool, str]:
        """
        Cancel a file transfer
        
        Args:
            transfer_id: ID of the transfer to cancel
            
        Returns:
            (success, message) tuple
        """
        if transfer_id not in self.active_transfers:
            return False, "Transfer not found"
            
        transfer = self.active_transfers[transfer_id]
        
        # Can only cancel if not completed or already cancelled
        if transfer['status'] in [TransferStatus.COMPLETED.name, TransferStatus.CANCELLED.name]:
            return False, "Transfer already completed or cancelled"
            
        # Update status
        transfer['status'] = TransferStatus.CANCELLED.name
        
        logger.info(f"Transfer cancelled: {transfer_id}")
        
        return True, "Transfer cancelled"
    
    def share_file(self, file_path: str, recipients: List[str], permissions: Dict[str, Any]) -> Tuple[bool, str, str]:
        """
        Share a file with other devices
        
        Args:
            file_path: Path to the file to share
            recipients: List of device IDs to share with
            permissions: Dictionary of permissions for the shared file
            
        Returns:
            (success, message, share_id) tuple
        """
        try:
            # Check if file exists
            if not os.path.isfile(file_path):
                return False, "File not found", ""
                
            # Generate a share ID
            share_id = str(uuid.uuid4())
            
            # Get file name
            file_name = os.path.basename(file_path)
            
            # Create a copy in the storage directory
            shared_path = os.path.join(self.storage_dir, f"{share_id}_{file_name}")
            shutil.copy2(file_path, shared_path)
            
            # Create share record
            share = {
                'id': share_id,
                'original_path': file_path,
                'shared_path': shared_path,
                'name': file_name,
                'owner': 'local',  # Current system is the owner
                'shared_with': recipients,
                'permissions': permissions,
                'created_at': datetime.now().isoformat(),
            }
            
            # Store the share
            self.shared_files[share_id] = share
            
            # Save shared files to disk
            self._save_shared_files()
            
            logger.info(f"File shared: {file_name} with {len(recipients)} recipients")
            
            return True, "File shared successfully", share_id
            
        except Exception as e:
            logger.error(f"Error sharing file: {str(e)}")
            return False, f"Error: {str(e)}", ""
    
    def unshare_file(self, share_id: str) -> Tuple[bool, str]:
        """
        Stop sharing a file
        
        Args:
            share_id: ID of the share to remove
            
        Returns:
            (success, message) tuple
        """
        if share_id not in self.shared_files:
            return False, "Share not found"
            
        share = self.shared_files[share_id]
        
        try:
            # Remove the shared copy
            if os.path.exists(share['shared_path']):
                os.remove(share['shared_path'])
                
            # Remove the share record
            del self.shared_files[share_id]
            
            # Save shared files to disk
            self._save_shared_files()
            
            logger.info(f"File unshared: {share['name']}")
            
            return True, "File unshared successfully"
            
        except Exception as e:
            logger.error(f"Error unsharing file: {str(e)}")
            return False, f"Error: {str(e)}"
    
    def get_shared_files(self, device_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get list of shared files, optionally filtered by device
        
        Args:
            device_id: ID of the device to filter by (optional)
            
        Returns:
            List of shared file records
        """
        if device_id is None:
            # Return all shared files
            return list(self.shared_files.values())
            
        # Filter by device ID
        return [
            share for share in self.shared_files.values()
            if device_id in share['shared_with'] or share['owner'] == device_id
        ]
    
    def _save_shared_files(self):
        """Save shared files information to disk"""
        try:
            # Convert to serializable format
            data = {}
            for share_id, share in self.shared_files.items():
                data[share_id] = dict(share)  # Make a copy
            
            # Save to file
            with open(os.path.join(self.storage_dir, 'shared_files.json'), 'w') as f:
                json.dump(data, f, indent=2)
                
        except Exception as e:
            logger.error(f"Error saving shared files: {str(e)}")
    
    def _load_shared_files(self):
        """Load shared files information from disk"""
        try:
            file_path = os.path.join(self.storage_dir, 'shared_files.json')
            
            if not os.path.exists(file_path):
                return
                
            with open(file_path, 'r') as f:
                self.shared_files = json.load(f)
                
            # Verify that shared files still exist, remove if not
            for share_id, share in list(self.shared_files.items()):
                if not os.path.exists(share['shared_path']):
                    del self.shared_files[share_id]
                    
        except Exception as e:
            logger.error(f"Error loading shared files: {str(e)}")
            self.shared_files = {}
    
    def cleanup(self):
        """Clean up resources before shutdown"""
        # Save shared files
        self._save_shared_files()
        
        logger.info("FileTransferService cleanup completed")