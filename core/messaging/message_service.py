"""
Message service for handling messaging between devices
Current Date: 2025-06-10 01:10:00
Author: AnoirELGUEDDAR
"""
import logging
import time
import os
import json
import threading
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
        self.check_thread = None
        
        # Track last known message timestamps for each conversation
        self.last_check_time = {}
        
        # Cache of processed message IDs to prevent duplicates
        self.processed_message_ids = set()
        
        logger.info("MessageService initialized")
        
    def start(self):
        """Start the message service"""
        self.running = True
        # Start background thread to check for new messages
        self.check_thread = threading.Thread(target=self._check_messages_worker, daemon=True)
        self.check_thread.start()
        logger.info("MessageService started")
        
    def stop(self):
        """Stop the message service"""
        self.running = False
        if self.check_thread:
            self.check_thread.join(timeout=1)
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
        # Force a refresh of local messages
        self._sync_local_messages()
        return self.conversations
        
    def get_conversation(self, conversation_id):
        """
        Get messages for a specific conversation
        This method now integrates with local message files
        """
        # Check if we have a conversation with this ID already
        existing_messages = self.conversations.get(conversation_id, [])
        
        # Read any messages from the local filesystem
        local_messages = self._read_local_messages(conversation_id)
        
        # Combine and deduplicate messages
        if local_messages:
            # Use a set to track unique message IDs
            message_ids = {msg.id for msg in existing_messages}
            
            # Add local messages that aren't already in memory
            for msg in local_messages:
                if msg.id not in message_ids:
                    existing_messages.append(msg)
                    message_ids.add(msg.id)
            
            # Sort by timestamp
            existing_messages.sort(key=lambda m: m.timestamp)
            
            # Store the updated list
            self.conversations[conversation_id] = existing_messages
        
        return self.conversations.get(conversation_id, [])
        
    def get_devices(self):
        """Get registered devices"""
        # Add any devices from the message folders
        self._scan_message_devices()
        return self.devices
        
    def _check_messages_worker(self):
        """Background thread to check for new messages periodically"""
        while self.running:
            try:
                self._sync_local_messages()
            except Exception as e:
                logger.error(f"Error checking messages: {e}")
            
            # Sleep for a short time before checking again
            time.sleep(2)
            
    def _sync_local_messages(self):
        """Sync all messages from local files"""
        # First check if directory exists
        messages_dir = os.path.join(os.getcwd(), "messages")
        if not os.path.exists(messages_dir):
            return
        
        # Get all message files
        try:
            message_files = [f for f in os.listdir(messages_dir) 
                            if f.startswith("message_") and f.endswith(".json")]
        except Exception as e:
            logger.error(f"Error listing message directory: {e}")
            return
            
        # Read each file if it hasn't been processed yet
        for filename in message_files:
            try:
                file_path = os.path.join(messages_dir, filename)
                
                # Skip if already processed
                if file_path in self.processed_message_ids:
                    continue
                    
                # Skip if the message is older than last check (if we have a timestamp)
                file_mod_time = os.path.getmtime(file_path)
                if filename in self.last_check_time and file_mod_time <= self.last_check_time.get(filename, 0):
                    continue
                
                # Read the message file
                with open(file_path, 'r') as f:
                    msg_data = json.load(f)
                
                # Convert to Message object
                message_id = msg_data.get("id", os.path.splitext(filename)[0].replace("message_", ""))
                
                # Skip if already processed by ID
                if message_id in self.processed_message_ids:
                    continue
                
                # Parse timestamp
                timestamp = None
                timestamp_str = msg_data.get("timestamp")
                if timestamp_str:
                    try:
                        timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                    except:
                        timestamp = datetime.now()
                else:
                    timestamp = datetime.now()
                
                # Create Message object
                message = Message(
                    id=message_id,
                    content=msg_data.get("text", ""),  # Note: 'text' in files, 'content' in Message
                    msg_type=MessageType.INFO,  # Default
                    sender=msg_data.get("sender", "Unknown"),
                    recipient="Administrator",  # Default recipient
                    timestamp=timestamp,
                    is_broadcast=False,
                    read=msg_data.get("read", False)
                )
                
                # Determine conversation ID (default to sender)
                conversation_id = msg_data.get("sender", "Unknown")
                
                # Store in appropriate conversation
                if conversation_id not in self.conversations:
                    self.conversations[conversation_id] = []
                self.conversations[conversation_id].append(message)
                
                # Mark as processed
                self.processed_message_ids.add(message_id)
                self.processed_message_ids.add(file_path)
                self.last_check_time[filename] = file_mod_time
                
                # Emit signal for new message
                self.message_received.emit(message)
                
                logger.info(f"New local message processed: {message_id} from {message.sender}")
                
            except Exception as e:
                logger.error(f"Error processing message file {filename}: {e}")
    
    def _read_local_messages(self, conversation_id=None):
        """Read messages from the local message directory"""
        messages = []
        messages_dir = os.path.join(os.getcwd(), "messages")
        
        if not os.path.exists(messages_dir):
            return messages
        
        try:
            # List all message files
            message_files = [f for f in os.listdir(messages_dir) 
                            if f.startswith("message_") and f.endswith(".json")]
            
            # Sort by name (which contains timestamp)
            message_files.sort()
            
            # Process each file
            for filename in message_files:
                try:
                    file_path = os.path.join(messages_dir, filename)
                    with open(file_path, 'r') as f:
                        msg_data = json.load(f)
                    
                    # Extract message data
                    message_id = msg_data.get("id", os.path.splitext(filename)[0].replace("message_", ""))
                    sender = msg_data.get("sender", "Unknown")
                    
                    # Skip if not relevant to the conversation
                    # In a simple system, the conversation_id might be the sender's name/ID
                    if conversation_id and conversation_id != "broadcast" and sender != conversation_id:
                        # Special case: conversation_id might be the message sender
                        is_relevant = (sender == conversation_id) or (conversation_id == "Administrator")
                        if not is_relevant:
                            continue
                    
                    # Parse timestamp
                    timestamp = None
                    timestamp_str = msg_data.get("timestamp")
                    if timestamp_str:
                        try:
                            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                        except:
                            timestamp = datetime.fromtimestamp(int(message_id) / 1000)
                    else:
                        timestamp = datetime.fromtimestamp(int(message_id) / 1000)
                    
                    # Create Message object
                    message = Message(
                        id=message_id,
                        content=msg_data.get("text", ""),  # 'text' in files, 'content' in Message
                        msg_type=MessageType.INFO,
                        sender=sender,
                        recipient="Administrator",
                        timestamp=timestamp,
                        is_broadcast=False,
                        conversation_id=conversation_id if conversation_id else sender,
                        read=msg_data.get("read", False)
                    )
                    
                    messages.append(message)
                    
                except Exception as e:
                    logger.error(f"Error reading message {filename}: {e}")
            
            # Sort by timestamp
            messages.sort(key=lambda m: m.timestamp)
            
        except Exception as e:
            logger.error(f"Error reading local messages: {e}")
        
        return messages

    def _scan_message_devices(self):
        """Scan messages to identify devices that have sent messages"""
        messages_dir = os.path.join(os.getcwd(), "messages")
        
        if not os.path.exists(messages_dir):
            return
        
        try:
            message_files = [f for f in os.listdir(messages_dir) 
                            if f.startswith("message_") and f.endswith(".json")]
                            
            for filename in message_files:
                try:
                    file_path = os.path.join(messages_dir, filename)
                    with open(file_path, 'r') as f:
                        msg_data = json.load(f)
                    
                    sender = msg_data.get("sender", "Unknown")
                    
                    # Add sender as device if not already known
                    if sender and sender != "Administrator" and sender not in self.devices:
                        self.devices[sender] = {
                            "last_seen": msg_data.get("timestamp", "Unknown"),
                            "name": sender
                        }
                        
                except Exception as e:
                    logger.error(f"Error scanning message file {filename}: {e}")
        except Exception as e:
            logger.error(f"Error scanning message directory: {e}")

    def mark_message_read(self, message_id):
        """Mark a message as read in the local storage"""
        messages_dir = os.path.join(os.getcwd(), "messages")
        message_path = os.path.join(messages_dir, f"message_{message_id}.json")
        
        if not os.path.exists(message_path):
            return False
        
        try:
            # Read message file
            with open(message_path, 'r') as f:
                message = json.load(f)
            
            # Update read status
            message["read"] = True
            
            # Write back to file
            with open(message_path, 'w') as f:
                json.dump(message, f, indent=2)
            
            # Update in memory if present
            for conversation in self.conversations.values():
                for msg in conversation:
                    if hasattr(msg, 'id') and msg.id == message_id:
                        msg.read = True
            
            return True
        except Exception as e:
            logger.error(f"Error marking message {message_id} as read: {e}")
            return False