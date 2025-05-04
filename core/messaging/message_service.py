# core/messaging/message_service.py - Enhanced message service
import threading
import queue
import logging
from datetime import datetime
from .message import Message, MessageType

class MessageService:
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(MessageService, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance
    
    def __init__(self):
        if getattr(self, "_initialized", False):
            return
            
        self._initialized = True
        self.message_queue = queue.Queue()
        self.subscribers = {}
        self.message_history = {}
        self.conversations = {}  # Store messages by conversation ID
        self.devices = set()     # Track known devices
        self.username = "Administrator"  # Default sender name
        self.running = False
        self.logger = logging.getLogger(__name__)
        
    def start(self):
        """Start the message service"""
        if self.running:
            return
            
        self.running = True
        self.worker_thread = threading.Thread(target=self._process_messages, daemon=True)
        self.worker_thread.start()
        self.logger.info("Message service started")
        
    def stop(self):
        """Stop the message service"""
        self.running = False
        if hasattr(self, "worker_thread") and self.worker_thread.is_alive():
            try:
                self.worker_thread.join(timeout=1.0)
            except Exception:
                pass
        self.logger.info("Message service stopped")
    
    def register_device(self, device_id, device_info=None):
        """Register a device that can receive messages"""
        self.devices.add(device_id)
        return True
        
    def set_username(self, username):
        """Set the name to use when sending messages"""
        self.username = username
        
    def send_message(self, message):
        """Send a message to the queue"""
        if not isinstance(message, Message):
            raise TypeError("Expected a Message object")
            
        self.message_queue.put(message)
        
        # Store in history by sender
        sender = message.sender or "anonymous"
        if sender not in self.message_history:
            self.message_history[sender] = []
        self.message_history[sender].append(message)
        
        # Store in conversations
        if message.conversation_id not in self.conversations:
            self.conversations[message.conversation_id] = []
        self.conversations[message.conversation_id].append(message)
        
        return message.id
        
    def send_to_device(self, content, device_id, msg_type=MessageType.INFO, 
                      conversation_id=None):
        """Send a message to a specific device"""
        message = Message(
            content=content,
            msg_type=msg_type,
            sender=self.username,
            recipient=device_id,
            conversation_id=conversation_id,
            is_broadcast=False
        )
        return self.send_message(message)
        
    def broadcast_message(self, content, msg_type=MessageType.INFO):
        """Send a message to all devices"""
        message = Message(
            content=content,
            msg_type=msg_type,
            sender=self.username,
            recipient="all",
            is_broadcast=True
        )
        return self.send_message(message)
        
    def get_devices(self):
        """Get list of registered devices"""
        return list(self.devices)
        
    def subscribe(self, callback, filter_type=None, filter_sender=None, filter_recipient=None,
                 filter_conversation=None):
        """Subscribe to messages with optional filters"""
        subscriber_id = str(len(self.subscribers) + 1)
        self.subscribers[subscriber_id] = {
            "callback": callback,
            "filter_type": filter_type,
            "filter_sender": filter_sender,
            "filter_recipient": filter_recipient,
            "filter_conversation": filter_conversation
        }
        return subscriber_id
        
    def get_message_history(self, sender=None, recipient=None, conversation_id=None, limit=50):
        """Get message history with various filters"""
        if conversation_id and conversation_id in self.conversations:
            # Get messages from a specific conversation
            messages = self.conversations[conversation_id]
            return messages[-limit:]
            
        elif sender and sender in self.message_history:
            # Get messages from a specific sender
            messages = self.message_history[sender]
            
            # Further filter by recipient if needed
            if recipient:
                messages = [msg for msg in messages if msg.recipient == recipient 
                           or msg.is_broadcast]
                
            return messages[-limit:]
            
        elif recipient:
            # Get all messages for a specific recipient
            result = []
            for sender_history in self.message_history.values():
                for msg in sender_history:
                    if msg.recipient == recipient or msg.is_broadcast:
                        result.append(msg)
            
            # Sort by timestamp
            result.sort(key=lambda msg: msg.timestamp)
            return result[-limit:]
            
        else:
            # Get all messages (combined history)
            all_messages = []
            for sender_history in self.message_history.values():
                all_messages.extend(sender_history)
                
            # Sort by timestamp
            all_messages.sort(key=lambda msg: msg.timestamp)
            return all_messages[-limit:]
    
    def get_conversations(self):
        """Get list of all conversation IDs with their latest message"""
        result = []
        for conv_id, messages in self.conversations.items():
            if not messages:
                continue
                
            # Get the most recent message
            latest = max(messages, key=lambda x: x.timestamp)
            
            # Create conversation summary
            result.append({
                'id': conv_id,
                'last_message': latest.content[:30] + ('...' if len(latest.content) > 30 else ''),
                'timestamp': latest.timestamp,
                'participants': list(set(filter(None, [msg.sender for msg in messages] + 
                                             [msg.recipient for msg in messages]))),
                'message_count': len(messages),
                'unread_count': sum(1 for msg in messages if not msg.read)
            })
            
        # Sort by timestamp (most recent first)
        result.sort(key=lambda x: x['timestamp'], reverse=True)
        return result
        
    def mark_conversation_read(self, conversation_id):
        """Mark all messages in a conversation as read"""
        if conversation_id not in self.conversations:
            return False
            
        for message in self.conversations[conversation_id]:
            message.mark_as_read()
            
        return True
    
    def _process_messages(self):
        """Process messages in the queue"""
        while self.running:
            try:
                message = self.message_queue.get(timeout=0.5)
                self._dispatch_message(message)
                self.message_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Error processing message: {e}")
                
    def _dispatch_message(self, message):
        """Dispatch message to subscribers"""
        for sub_id, subscriber in self.subscribers.items():
            should_notify = True
            
            # Apply filters
            if subscriber["filter_type"] and message.type != subscriber["filter_type"]:
                should_notify = False
            if subscriber["filter_sender"] and message.sender != subscriber["filter_sender"]:
                should_notify = False
            if subscriber["filter_recipient"] and message.recipient != subscriber["filter_recipient"]:
                should_notify = False
            if subscriber["filter_conversation"] and message.conversation_id != subscriber["filter_conversation"]:
                should_notify = False
                
            if should_notify:
                try:
                    subscriber["callback"](message)
                except Exception as e:
                    self.logger.error(f"Error in subscriber callback {sub_id}: {e}")
                    
# Add this method to the MessageService class if it's missing

    def unsubscribe(self, subscriber_id):
        """Unsubscribe from messages"""
        if subscriber_id in self.subscribers:
            del self.subscribers[subscriber_id]
            return True
        return False