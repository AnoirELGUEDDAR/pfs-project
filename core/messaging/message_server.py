"""
LAN Messaging Server
"""
import socket
import threading
import json
import logging
import time
import pickle
import os
from datetime import datetime
from typing import Dict, List, Set, Optional, Tuple, Union, Any

import zmq

from config.constants import MESSAGE_TYPES

logger = logging.getLogger(__name__)

class MessageServer:
    """
    Server component for LAN messaging system
    """
    
    def __init__(self, port: int = 8765, save_history: bool = True, history_path: str = "message_history"):
        self.port = port
        self.save_history = save_history
        self.history_path = history_path
        self.running = False
        self.clients = {}  # {client_id: {"username": name, "last_seen": timestamp}}
        self.message_history = []  # List of message dictionaries
        self.context = zmq.Context()
        self._lock = threading.Lock()
        
        # Create history directory if needed
        if self.save_history and not os.path.exists(self.history_path):
            os.makedirs(self.history_path)
    
    def start(self) -> bool:
        """
        Start the message server
        
        Returns:
            True if server started successfully
        """
        if self.running:
            logger.warning("Message server already running")
            return False
        
        try:
            # Create publisher socket for broadcasting messages
            self.publisher = self.context.socket(zmq.PUB)
            self.publisher.bind(f"tcp://*:{self.port}")
            
            # Create router socket for receiving messages
            self.receiver = self.context.socket(zmq.ROUTER)
            self.receiver.bind(f"tcp://*:{self.port+1}")
            
            self.running = True
            
            # Start receiver thread
            self.receiver_thread = threading.Thread(target=self._receive_messages)
            self.receiver_thread.daemon = True
            self.receiver_thread.start()
            
            # Start presence thread
            self.presence_thread = threading.Thread(target=self._presence_check)
            self.presence_thread.daemon = True
            self.presence_thread.start()
            
            logger.info(f"Message server started on port {self.port}")
            return True
        
        except Exception as e:
            logger.error(f"Error starting message server: {e}")
            self.running = False
            return False
    
    def stop(self) -> None:
        """Stop the message server"""
        if not self.running:
            return
            
        logger.info("Stopping message server")
        self.running = False
        
        # Wait for threads to finish
        if hasattr(self, 'receiver_thread'):
            self.receiver_thread.join(1)
        if hasattr(self, 'presence_thread'):
            self.presence_thread.join(1)
        
        # Close sockets
        self.publisher.close()
        self.receiver.close()
        
        # Save message history
        if self.save_history:
            self._save_history()
    
    def broadcast_message(self, message_data: Dict) -> bool:
        """
        Broadcast a message to all clients
        
        Args:
            message_data: Dictionary with message data
            
        Returns:
            True if message was sent
        """
        if not self.running:
            logger.warning("Cannot send message: server not running")
            return False
            
        try:
            # Add timestamp if not present
            if "timestamp" not in message_data:
                message_data["timestamp"] = time.time()
                
            # Add formatted time for display
            message_data["time"] = datetime.fromtimestamp(
                message_data["timestamp"]
            ).strftime("%H:%M:%S")
            
            # Convert message to JSON
            message_json = json.dumps(message_data)
            
            # Send to all clients
            self.publisher.send_multipart([b"message", message_json.encode('utf-8')])
            
            # Add to history
            with self._lock:
                self.message_history.append(message_data)
                
                # Trim history to last 1000 messages
                if len(self.message_history) > 1000:
                    self.message_history = self.message_history[-1000:]
            
            logger.debug(f"Broadcast message: {message_data.get('content', '')} from {message_data.get('sender', '')}")
            return True
            
        except Exception as e:
            logger.error(f"Error broadcasting message: {e}")
            return False
    
    def send_system_message(self, content: str, target: Optional[str] = None) -> bool:
        """
        Send a system message
        
        Args:
            content: Message content
            target: Target client ID (None for broadcast)
            
        Returns:
            True if message was sent
        """
        message_data = {
            "type": MESSAGE_TYPES["SYSTEM"],
            "sender": "System",
            "content": content,
            "timestamp": time.time()
        }
        
        if target:
            message_data["target"] = target
            
        return self.broadcast_message(message_data)
    
    def get_client_list(self) -> List[Dict]:
        """
        Get a list of connected clients
        
        Returns:
            List of client dictionaries
        """
        client_list = []
        current_time = time.time()
        
        with self._lock:
            for client_id, data in self.clients.items():
                # Only include clients seen in the last 2 minutes
                if current_time - data["last_seen"] < 120:
                    client_list.append({
                        "client_id": client_id,
                        "username": data["username"],
                        "last_seen": data["last_seen"],
                        "last_seen_formatted": datetime.fromtimestamp(data["last_seen"]).strftime("%H:%M:%S")
                    })
                    
        return client_list
    
    def get_message_history(self, limit: int = 50) -> List[Dict]:
        """
        Get recent message history
        
        Args:
            limit: Maximum number of messages to return
            
        Returns:
            List of message dictionaries
        """
        with self._lock:
            return self.message_history[-limit:]
    
    def _receive_messages(self) -> None:
        """Receiver thread function"""
        while self.running:
            try:
                # Receive message as multipart: [client_id, message_json]
                if not self.receiver.poll(1000):
                    continue
                    
                multipart = self.receiver.recv_multipart()
                if len(multipart) != 2:
                    continue
                    
                client_id = multipart[0]
                message_json = multipart[1].decode('utf-8')
                message_data = json.loads(message_json)
                
                # Update client info
                if "sender" in message_data:
                    with self._lock:
                        self.clients[client_id.decode('utf-8')] = {
                            "username": message_data["sender"],
                            "last_seen": time.time()
                        }
                
                # Handle message based on type
                if "type" in message_data:
                    if message_data["type"] == MESSAGE_TYPES["PING"]:
                        # Ping message - just update client info
                        pass
                        
                    elif message_data["type"] == MESSAGE_TYPES["TEXT"]:
                        # Regular text message - broadcast to all
                        self.broadcast_message(message_data)
                        
                    elif message_data["type"] == MESSAGE_TYPES["FILE"]:
                        # File transfer message - broadcast metadata only
                        if "file_size" in message_data:
                            # This is the initial file transfer request
                            self.broadcast_message({
                                "type": MESSAGE_TYPES["FILE"],
                                "sender": message_data["sender"],
                                "filename": message_data.get("filename", "unknown"),
                                "file_size": message_data["file_size"],
                                "content": f"File transfer: {message_data.get('filename', 'unknown')} ({self._format_size(message_data['file_size'])})",
                                "timestamp": time.time()
                            })
                    
                    elif message_data["type"] == MESSAGE_TYPES["STATUS"]:
                        # Status update - broadcast to all
                        self.broadcast_message(message_data)
                
            except Exception as e:
                logger.error(f"Error receiving message: {e}")
                time.sleep(0.1)
    
    def _presence_check(self) -> None:
        """Presence checking thread function"""
        while self.running:
            try:
                # Clean up clients that haven't been seen for 2 minutes
                current_time = time.time()
                inactive_clients = []
                
                with self._lock:
                    for client_id, data in self.clients.items():
                        if current_time - data["last_seen"] > 120:
                            inactive_clients.append((client_id, data["username"]))
                    
                    # Remove inactive clients
                    for client_id, username in inactive_clients:
                        logger.info(f"Client {username} ({client_id}) timed out")
                        del self.clients[client_id]
                        
                        # Send system message about client disconnect
                        self.send_system_message(f"{username} disconnected (timeout)")
                
                # Send presence ping every 30 seconds
                self.publisher.send_multipart([
                    b"presence", 
                    json.dumps({
                        "type": "server_ping",
                        "timestamp": current_time
                    }).encode('utf-8')
                ])
                
                # Save history periodically
                if self.save_history and len(self.message_history) > 0:
                    self._save_history()
                    
                time.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                logger.error(f"Error in presence check: {e}")
                time.sleep(30)
    
    def _save_history(self) -> None:
        """Save message history to file"""
        if not self.save_history:
            return
            
        try:
            # Save to a file with current date
            filename = os.path.join(
                self.history_path,
                f"messages_{datetime.now().strftime('%Y%m%d')}.pickle"
            )
            
            with self._lock:
                with open(filename, 'wb') as f:
                    pickle.dump(self.message_history, f)
                    
            logger.debug(f"Message history saved to {filename}")
            
        except Exception as e:
            logger.error(f"Error saving message history: {e}")
    
    def _format_size(self, size: int) -> str:
        """
        Format file size into human-readable string
        
        Args:
            size: Size in bytes
            
        Returns:
            Formatted size string
        """
        if size < 1024:
            return f"{size} B"
        elif size < 1024 * 1024:
            return f"{size/1024:.1f} KB"
        elif size < 1024 * 1024 * 1024:
            return f"{size/(1024*1024):.1f} MB"
        else:
            return f"{size/(1024*1024*1024):.2f} GB"