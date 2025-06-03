# core/messaging/message.py - Enhanced message class
from enum import Enum
import time
import uuid

class MessageType(Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    COMMAND = "command"
    RESPONSE = "response"
    DATA = "data"

class Message:
    def __init__(self, content, msg_type=MessageType.INFO, sender=None, recipient=None, 
                 conversation_id=None, is_broadcast=False):
        self.id = str(uuid.uuid4())
        self.timestamp = time.time()
        self.content = content
        self.type = msg_type
        self.sender = sender
        self.recipient = recipient
        self.read = False
        # New fields for conversations
        self.conversation_id = conversation_id or str(uuid.uuid4())
        self.is_broadcast = is_broadcast  # True if sent to all devices
        
    def mark_as_read(self):
        self.read = True
        
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp,
            'content': self.content,
            'type': self.type.value,
            'sender': self.sender,
            'recipient': self.recipient,
            'read': self.read,
            'conversation_id': self.conversation_id,
            'is_broadcast': self.is_broadcast
        }
        
    @classmethod
    def from_dict(cls, data):
        msg = cls(
            content=data['content'],
            msg_type=MessageType(data['type']),
            sender=data['sender'],
            recipient=data['recipient'],
            conversation_id=data.get('conversation_id'),
            is_broadcast=data.get('is_broadcast', False)
        )
        msg.id = data['id']
        msg.timestamp = data['timestamp']
        msg.read = data['read']
        return msg