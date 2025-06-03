"""
Message service for handling messaging between devices
Current Date: 2025-05-10 12:12:47
Author: AnoirELGUEDDAR
"""
import logging
import time
from typing import Dict, List, Optional
from enum import Enum
from datetime import datetime
from PyQt5.QtCore import QObject, pyqtSignal

from core.messaging.message import Message, MessageType

logger = logging.getLogger(__name__)

class MessageService(QObject):
    """Service for handling message delivery and storage"""
    
    # Signal emitted when a new message is received
    message_received = pyqtSignal(object)  # Signal takes a Message object
    
    def __init__(self):
        """Initialize the message service"""
        super().__init__()
        
        # Store messages by conversation
        self.conversations = {}  # {conversation_id: [message1, message2, ...]}
        
        # Store device information
        self.devices = {}  # {device_id: device_info}
        
        # Store username for this instance
        self.username = "Administrator"  # Default username
        
        # Background thread for checking messages
        self.running = False
        
        logger.info("MessageService initialized")
        
    def start(self):
        """Start the message service"""
        self.running = True
        logger.info("MessageService started")
        
    def stop(self):
        """Stop the message service"""
        self.running = False
        logger.info("MessageService stopped")
        
    def set_username(self, username):
        """Set the username for this service instance"""
        self.username = username
        logger.info(f"Username set to: {username}")
        
    def register_device(self, device_id, device_info):
        """Register a device with the messaging service"""
        self.devices[device_id] = device_info
        
        # Create a default conversation for this device if not exists
        if device_id not in self.conversations:
            self.conversations[device_id] = []
            
        logger.info(f"Device registered: {device_id}")
        
    def send_message(self, message):
        """Send a message"""
        # Validate message
        if not isinstance(message, Message):
            logger.error("Invalid message object")
            return False
            
        # Set sender if not set
        if not message.sender:
            message.sender = self.username
            
        # Add timestamp if not set
        if not message.timestamp:
            message.timestamp = datetime.now()
            
        # Determine conversation ID
        conversation_id = message.recipient if message.recipient else "broadcast"
        
        # Store message
        if conversation_id not in self.conversations:
            self.conversations[conversation_id] = []
        self.conversations[conversation_id].append(message)
        
        # Log message
        logger.info(f"Message sent to {conversation_id}: {message.content[:30]}...")
        
        # Emit signal for the message (this will make it work with FilesTab)
        self.message_received.emit(message)
        
        return True
        
    def broadcast_message(self, content, msg_type=MessageType.INFO):
        """Send a broadcast message to all devices"""
        message = Message(
            content=content,
            msg_type=msg_type,
            sender=self.username,
            is_broadcast=True
        )
        
        # Store in broadcast conversation
        if "broadcast" not in self.conversations:
            self.conversations["broadcast"] = []
        self.conversations["broadcast"].append(message)
        
        # Log message
        logger.info(f"Broadcast message sent: {content[:30]}...")
        
        # Emit signal for the message
        self.message_received.emit(message)
        
        return True
        
    def get_conversations(self):
        """Get all conversations"""
        return self.conversations
        
    def get_conversation(self, conversation_id):
        """Get messages for a specific conversation"""
        return self.conversations.get(conversation_id, [])
        
    def get_devices(self):
        """Get registered devices"""
        return self.devices