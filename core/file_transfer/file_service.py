"""
File transfer service for sending and receiving files between server and clients
"""

import os
import csv
import logging
import shutil
import time
import uuid
import math
from datetime import datetime
from pathlib import Path
from threading import Thread, Lock
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

class FileTransferService:
    """Service to handle file transfers"""
    
    def __init__(self, storage_dir="file_storage"):
        self.storage_dir = Path(storage_dir)
        self.received_dir = self.storage_dir / "received"
        self.sending_dir = self.storage_dir / "sending"
        self.active_transfers = {}  # Dictionary of active transfers
        self.transfer_history = []  # List of completed transfers
        self.lock = Lock()  # For thread safety
        
        # Create necessary directories
        self.received_dir.mkdir(parents=True, exist_ok=True)
        self.sending_dir.mkdir(parents=True, exist_ok=True)
        
        # Load history
        self._load_history()
        
    def _load_history(self):
        """Load transfer history from disk"""
        history_file = self.storage_dir / "transfer_history.csv"
        if history_file.exists():
            try:
                with open(history_file, "r", newline="") as f:
                    reader = csv.DictReader(f)
                    self.transfer_history = list(reader)
                    
                # Convert stored strings to appropriate types
                for item in self.transfer_history:
                    item["timestamp"] = float(item.get("timestamp", 0))
                    item["size"] = int(item.get("size", 0))
            except Exception as e:
                logger.error(f"Error loading transfer history: {e}")
                self.transfer_history = []
        
    def _save_history(self):
        """Save transfer history to disk"""
        history_file = self.storage_dir / "transfer_history.csv"
        try:
            with open(history_file, "w", newline="") as f:
                if self.transfer_history:
                    fieldnames = self.transfer_history[0].keys()
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(self.transfer_history)
        except Exception as e:
            logger.error(f"Error saving transfer history: {e}")
    
    def send_file(self, file_path: str, recipient: str) -> str:
        """
        Begin sending a file to a client
        
        Args:
            file_path: Path to the file to send
            recipient: Client ID to send to
            
        Returns:
            Transfer ID
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File {file_path} not found")
            
        # Generate a unique ID for this transfer
        transfer_id = str(uuid.uuid4())
        
        # Create the transfer object
        transfer = {
            "id": transfer_id,
            "file_path": file_path,
            "recipient": recipient,
            "start_time": time.time(),
            "progress": 0.0,
            "status": "Starting",
            "size": os.path.getsize(file_path)
        }
        
        # Add to active transfers
        with self.lock:
            self.active_transfers[transfer_id] = transfer
        
        # Start the transfer in a background thread
        Thread(target=self._transfer_file, args=(transfer_id,), daemon=True).start()
        
        return transfer_id
    
    def _transfer_file(self, transfer_id: str):
        """
        Process a file transfer in the background
        
        Args:
            transfer_id: ID of the transfer to process
        """
        with self.lock:
            if transfer_id not in self.active_transfers:
                logger.error(f"Transfer {transfer_id} not found")
                return
                
            transfer = self.active_transfers[transfer_id]
            
        try:
            # In a real implementation, this would involve network communication
            # with the client, chunking the file, tracking progress, etc.
            
            # For this example, we'll simulate the transfer with a delay
            file_path = transfer["file_path"]
            recipient = transfer["recipient"]
            file_size = transfer["size"]
            
            # Update status
            with self.lock:
                self.active_transfers[transfer_id]["status"] = "Transferring"
            
            # Simulate transfer progress
            chunks = 10
            chunk_size = file_size / chunks
            
            for i in range(chunks):
                # Check if transfer was canceled
                with self.lock:
                    if transfer_id not in self.active_transfers:
                        logger.info(f"Transfer {transfer_id} was canceled")
                        return
                
                # Simulate network delay
                time.sleep(0.5)
                
                # Update progress
                with self.lock:
                    self.active_transfers[transfer_id]["progress"] = (i + 1) / chunks
            
            # Simulate completion
            with self.lock:
                # Update transfer status
                self.active_transfers[transfer_id]["status"] = "Completed"
                self.active_transfers[transfer_id]["progress"] = 1.0
                self.active_transfers[transfer_id]["end_time"] = time.time()
                
                # Add to history
                history_item = {
                    "file_path": self.active_transfers[transfer_id]["file_path"],
                    "direction": "outgoing",
                    "user": self.active_transfers[transfer_id]["recipient"],
                    "size": self.active_transfers[transfer_id]["size"],
                    "timestamp": time.time(),
                    "status": "Completed"
                }
                self.transfer_history.append(history_item)
                self._save_history()
                
                # Remove from active transfers after a delay
                active_transfer = self.active_transfers[transfer_id]
                del self.active_transfers[transfer_id]
                
            logger.info(f"File transfer {transfer_id} completed: {file_path} to {recipient}")
            
        except Exception as e:
            logger.error(f"Error transferring file: {e}")
            
            # Update transfer status
            with self.lock:
                if transfer_id in self.active_transfers:
                    self.active_transfers[transfer_id]["status"] = "Failed"
                    self.active_transfers[transfer_id]["error"] = str(e)
                    
                    # Add to history
                    history_item = {
                        "file_path": self.active_transfers[transfer_id]["file_path"],
                        "direction": "outgoing",
                        "user": self.active_transfers[transfer_id]["recipient"],
                        "size": self.active_transfers[transfer_id]["size"],
                        "timestamp": time.time(),
                        "status": "Failed"
                    }
                    self.transfer_history.append(history_item)
                    self._save_history()
    
    def receive_file(self, file_data: bytes, file_name: str, sender: str) -> str:
        """
        Handle receiving a file from a client
        
        Args:
            file_data: Binary file data
            file_name: Original file name
            sender: Client ID that sent the file
            
        Returns:
            Path to the saved file
        """
        # Generate a unique filename to prevent overwrites
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        unique_name = f"{timestamp}_{file_name}"
        
        # Path where the file will be saved
        file_path = self.received_dir / unique_name
        
        # Save the file
        try:
            with open(file_path, "wb") as f:
                f.write(file_data)
                
            # Add to history
            with self.lock:
                history_item = {
                    "file_path": str(file_path),
                    "direction": "incoming",
                    "user": sender,
                    "size": len(file_data),
                    "timestamp": time.time(),
                    "status": "Received"
                }
                self.transfer_history.append(history_item)
                self._save_history()
                
            logger.info(f"File received from {sender}: {file_name}, saved as {file_path}")
            return str(file_path)
            
        except Exception as e:
            logger.error(f"Error receiving file {file_name} from {sender}: {e}")
            raise
    
    def cancel_transfer(self, transfer_id: str):
        """
        Cancel an ongoing file transfer
        
        Args:
            transfer_id: ID of the transfer to cancel
        """
        with self.lock:
            if transfer_id in self.active_transfers:
                # Add to history as canceled
                transfer = self.active_transfers[transfer_id]
                history_item = {
                    "file_path": transfer["file_path"],
                    "direction": "outgoing",
                    "user": transfer["recipient"],
                    "size": transfer["size"],
                    "timestamp": time.time(),
                    "status": "Canceled"
                }
                self.transfer_history.append(history_item)
                self._save_history()
                
                # Remove from active transfers
                del self.active_transfers[transfer_id]
                logger.info(f"Transfer {transfer_id} canceled")
            else:
                logger.warning(f"Cannot cancel transfer {transfer_id}: not found")
    
    def get_active_transfers(self) -> List[Dict[str, Any]]:
        """
        Get a list of active transfers
        
        Returns:
            List of transfer dictionaries
        """
        with self.lock:
            # Return a copy to prevent modification during iteration
            return list(self.active_transfers.values())
    
    def get_received_files(self) -> List[Dict[str, Any]]:
        """
        Get a list of received files
        
        Returns:
            List of file info dictionaries
        """
        received_files = []
        
        # Get files from history
        with self.lock:
            for item in self.transfer_history:
                if item.get("direction") == "incoming" and item.get("status") == "Received":
                    path = item.get("file_path")
                    # Check if file still exists
                    if os.path.exists(path):
                        received_files.append({
                            "path": path,
                            "sender": item.get("user"),
                            "size": item.get("size"),
                            "timestamp": item.get("timestamp")
                        })
        
        return received_files
    
    def get_transfer_history(self) -> List[Dict[str, Any]]:
        """
        Get the transfer history
        
        Returns:
            List of history item dictionaries
        """
        with self.lock:
            # Return a copy to prevent modification
            return list(self.transfer_history)
    
    def clear_history(self):
        """Clear the transfer history"""
        with self.lock:
            self.transfer_history = []
            self._save_history()
            
    def export_history_to_csv(self, file_path: str):
        """
        Export transfer history to a CSV file
        
        Args:
            file_path: Path to save CSV file to
        """
        with self.lock:
            if not self.transfer_history:
                raise ValueError("No transfer history to export")
                
            try:
                with open(file_path, "w", newline="") as f:
                    fieldnames = self.transfer_history[0].keys()
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(self.transfer_history)
            except Exception as e:
                logger.error(f"Error exporting history: {e}")
                raise