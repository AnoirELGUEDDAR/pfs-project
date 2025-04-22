"""
LAN Messaging Client
"""
import socket
import threading
import json
import logging
import time
import uuid
import os
from datetime import datetime
from typing import Dict, List, Set, Optional, Tuple, Union, Any, Callable

import zmq

from config.constants import MESSAGE_TYPES

logger = logging.getLogger(__name__)

class MessageClient:
    """
    Client component for LAN messaging system
    """
    
    def __init__(self, username: str, server_address: str, port: int = 8765):
        self.username = username
        self.server_address = server_address
        self.port = port
        self.client_id = str(uuid.uuid4())
        self.running = False
        self.context = zmq.Context()
        self.message_callbacks = []
        self.presence_callbacks = []
        self.message_history = []
        self.connected_clients = {}
    
    def connect(self) -> bool:
        """
        Connect to the message server
        
        Returns:
            True if connected successfully
        """
        if self.running:
            logger.warning("Message client already running")
            return False
        
        try:
            # Connect to publisher socket for receiving messages
            self.subscriber = self.context.socket(zmq.SUB)
            self.subscriber.connect(f"tcp://{self.server_address}:{self.port}")
            self.subscriber.setsockopt(zmq.SUBSCRIBE, b"message")
            self.subscriber.setsockopt(zmq.SUBSCRIBE, b"presence")
            
            # Connect to router socket for sending messages
            self.sender = self.context.socket(zmq.DEALER)
            self.sender.setsockopt(zmq.IDENTITY, self.client_id.encode('utf-8'))
            self.sender.connect(f"tcp://{self.server_address}:{self.port+1}")
            
            self.running = True
            
            # Start receiver thread
            self.receiver_thread = threading.Thread(target=self._receive_messages)
            self.receiver_thread.daemon = True
            self.receiver_thread.start()
            
            # Start presence ping thread
            self.presence_thread = threading.Thread(target=self._send_presence_ping)
            self.presence_thread.daemon = True
            self.presence_thread.start()
            
            # Send initial presence ping
            self._send_ping()
            
            logger.info(f"Connected to message server at {self.server_address}:{self.port}")
            return True
            
        except Exception as e:
            logger.error(f"Error connecting to message server: {e}")
            self.running = False
            return False
    
    def disconnect(self) -> None:
        """Disconnect from the message server"""
        if not self.running:
            return
            
        logger.info("Disconnecting from message server")
        self.running = False
        
        # Send disconnection status
        self.send_status("offline")
        
        # Wait for threads to finish
        if hasattr(self, 'receiver_thread'):
            self.receiver_thread.join(1)
        if hasattr(self, 'presence_thread'):
            self.presence_thread.join(1)
        
        # Close sockets
        if hasattr(self, 'subscriber'):
            self.subscriber.close()
        if hasattr(self, 'sender'):
            self.sender.close()
    
    def send_message(self, content: str, target: Optional[str] = None) -> bool:
        """
        Send a text message
        
        Args:
            content: Message content
            target: Target client ID (None for broadcast)
            
        Returns:
            True if message was sent
        """
        if not self.running:
            logger.warning("Cannot send message: not connected")
            return False
            
        try:
            message_data = {
                "type": MESSAGE_TYPES["TEXT"],
                "sender": self.username,
                "sender_id": self.client_id,
                "content": content,
                "timestamp": time.time()
            }
            
            if target:
                message_data["target"] = target
                
            # Send message
            self.sender.send(json.dumps(message_data).encode('utf-8'))
            
            # Add to local history
            message_data["time"] = datetime.fromtimestamp(
                message_data["timestamp"]
            ).strftime("%H:%M:%S")
            self.message_history.append(message_data)
            
            return True
            
        except Exception as e:
            logger.error(f"Error sending message: {e}")
            return False
    
    def send_file(self, file_path: str, target: Optional[str] = None) -> bool:
        """
        Send a file
        
        Args:
            file_path: Path to the file to send
            target: Target client ID (None for broadcast)
            
        Returns:
            True if file transfer initiated
        """
        if not self.running:
            