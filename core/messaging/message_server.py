"""
Message Server for Network Scanner application
Handles client connections and message routing
"""

import socket
import threading
import json
import logging
from datetime import datetime

from core.messaging.message import Message, MessageType

class MessageServer:
    def __init__(self, port=9876, message_service=None, auth_token="change_this_token_immediately"):
        self.port = port
        self.message_service = message_service
        self.running = False
        self.auth_token = auth_token
        self.logger = logging.getLogger(__name__)
        
        # Active clients
        self.active_clients = {}  # client_id -> {last_seen, info}
        
    def start(self):
        """Start the message server"""
        if self.running:
            return
            
        self.running = True
        self.server_thread = threading.Thread(target=self._run_server, daemon=True)
        self.server_thread.start()
        self.logger.info(f"Message server started on port {self.port}")
        print(f"Message server started on port {self.port}")
        
    def stop(self):
        """Stop the message server"""
        self.running = False
        self.logger.info("Message server stopped")
        
    def _run_server(self):
        """Run the server socket"""
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(('0.0.0.0', self.port))
            server_socket.settimeout(1.0)  # Allow checking self.running periodically
            server_socket.listen(5)
            
            self.logger.info(f"Listening for client connections on port {self.port}")
            print(f"Listening for client connections on port {self.port}")
            
            while self.running:
                try:
                    client_socket, address = server_socket.accept()
                    self.logger.info(f"Connection from {address[0]}:{address[1]}")
                    
                    # Handle client in separate thread
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, address),
                        daemon=True
                    )
                    client_thread.start()
                except socket.timeout:
                    continue  # Check if we should still be running
                except Exception as e:
                    if self.running:  # Only log if we're still supposed to be running
                        self.logger.error(f"Error accepting connection: {e}")
                    
        except Exception as e:
            self.logger.error(f"Server error: {e}")
        finally:
            try:
                server_socket.close()
            except:
                pass
            
    def _handle_client(self, client_socket, address):
        """Handle a client connection"""
        try:
            # Set a timeout on the socket
            client_socket.settimeout(5)
            
            # Receive data
            data = b""
            chunk = client_socket.recv(4096)
            if not chunk:
                return
                
            data += chunk
            
            # Handle potential larger messages
            if len(chunk) >= 4000:
                client_socket.settimeout(10)  # Longer timeout for large messages
                while True:
                    try:
                        chunk = client_socket.recv(8192)
                        if not chunk:
                            break
                        data += chunk
                        if len(data) > 1_000_000:  # 1MB limit to prevent DoS
                            raise ValueError("Message too large")
                        if chunk.endswith(b'}'):  # Simple check for JSON end
                            break
                    except socket.timeout:
                        break
                        
            # Parse the message
            message = json.loads(data.decode('utf-8'))
            
            # Check authentication
            if message.get("auth_token") != self.auth_token:
                self.logger.warning(f"Authentication failed from {address[0]}")
                response = {"status": "error", "message": "Invalid authentication token"}
                client_socket.sendall(json.dumps(response).encode('utf-8'))
                return
                
            # Process the command
            command = message.get("command")
            params = message.get("params", {})
            
            self.logger.info(f"Received command: {command} from {address[0]}")
            
            if command == "client_message":
                # Handle message from client device
                msg_data = params.get("message", {})
                
                # Extract client ID for active clients tracking
                client_id = msg_data.get("sender")
                if client_id:
                    self.active_clients[client_id] = {
                        "last_seen": datetime.now(),
                        "address": address[0]
                    }
                
                # Format recipient for cleaner display
                recipient = msg_data.get("recipient")
                if recipient == "Administrator" or recipient == "all":
                    # These are fine as is
                    pass
                elif recipient and recipient.startswith("Administrator"):
                    msg_data["recipient"] = "Administrator"
                
                # Create a Message object
                msg = Message(
                    content=msg_data.get("content", ""),
                    msg_type=msg_data.get("type", MessageType.INFO),
                    sender=msg_data.get("sender", "Unknown Client"),
                    recipient=msg_data.get("recipient", "Administrator"),
                    conversation_id=msg_data.get("conversation_id"),
                    is_broadcast=msg_data.get("is_broadcast", False)
                )
                
                # Send to message service
                if self.message_service:
                    self.message_service.send_message(msg)
                    response = {"status": "success", "message": "Message received"}
                else:
                    response = {"status": "error", "message": "Message service unavailable"}
                    
            elif command == "get_client_messages":
                # Client is requesting messages intended for it
                client_id = params.get("client_id")
                mark_as_read = params.get("mark_as_read", True)
                
                # Update active clients tracking
                if client_id:
                    self.active_clients[client_id] = {
                        "last_seen": datetime.now(),
                        "address": address[0]
                    }
                
                if not client_id:
                    response = {"status": "error", "message": "Client ID required"}
                else:
                    if self.message_service:
                        # Get messages for this client
                        messages = self.message_service.get_message_history(recipient=client_id)
                        
                        # Also get broadcast messages
                        broadcast_msgs = [msg for msg in self.message_service.get_message_history(recipient="all") 
                                         if not msg.read or not mark_as_read]
                        
                        # Combine messages
                        all_messages = messages + broadcast_msgs
                        
                        # Convert to dict for JSON serialization
                        message_dicts = []
                        for msg in all_messages:
                            try:
                                msg_dict = {
                                    'id': msg.id,
                                    'timestamp': msg.timestamp,
                                    'content': msg.content,
                                    'type': msg.type.value if hasattr(msg.type, 'value') else str(msg.type),
                                    'sender': msg.sender,
                                    'recipient': msg.recipient,
                                    'read': msg.read,
                                    'conversation_id': msg.conversation_id,
                                    'is_broadcast': msg.is_broadcast
                                }
                                message_dicts.append(msg_dict)
                            except Exception as e:
                                self.logger.error(f"Error converting message: {e}")
                        
                        # Mark messages as read if requested
                        if mark_as_read:
                            for msg in all_messages:
                                msg.mark_as_read()
                        
                        response = {"status": "success", "data": {"messages": message_dicts}}
                    else:
                        response = {"status": "error", "message": "Message service unavailable"}
                        
            elif command == "register_client":
                # Client is registering itself
                client_id = params.get("client_id")
                client_info = params.get("client_info", {})
                
                if not client_id:
                    response = {"status": "error", "message": "Client ID required"}
                else:
                    # Add to active clients
                    self.active_clients[client_id] = {
                        "last_seen": datetime.now(),
                        "info": client_info,
                        "address": address[0]
                    }
                    
                    if self.message_service:
                        self.message_service.register_device(client_id, client_info)
                        print(f"Client registered: {client_id}")
                        
                        # Send system notification about new client
                        system_msg = Message(
                            content=f"Client {client_id} ({client_info.get('username', 'Unknown')}) has connected",
                            msg_type=MessageType.INFO,
                            sender="System",
                            recipient="Administrator"
                        )
                        self.message_service.send_message(system_msg)
                        
                        response = {"status": "success", "message": "Client registered"}
                    else:
                        response = {"status": "error", "message": "Message service unavailable"}
                        
            elif command == "get_active_clients":
                # Return list of active clients (for admin only)
                if self.message_service:
                    clients = []
                    for client_id, data in self.active_clients.items():
                        clients.append({
                            "id": client_id,
                            "last_seen": data.get("last_seen", datetime.now()).strftime("%Y-%m-%d %H:%M:%S"),
                            "address": data.get("address", "unknown"),
                            "info": data.get("info", {})
                        })
                    
                    response = {"status": "success", "data": {"clients": clients}}
                else:
                    response = {"status": "error", "message": "Message service unavailable"}
                
            else:
                response = {"status": "error", "message": f"Unknown command: {command}"}
                
            # Send the response
            client_socket.sendall(json.dumps(response).encode('utf-8'))
            
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON from {address[0]}: {e}")
            try:
                response = {"status": "error", "message": "Invalid JSON message"}
                client_socket.sendall(json.dumps(response).encode('utf-8'))
            except:
                pass
        except Exception as e:
            self.logger.error(f"Error handling client {address[0]}: {e}")
            try:
                response = {"status": "error", "message": str(e)}
                client_socket.sendall(json.dumps(response).encode('utf-8'))
            except:
                pass
        finally:
            try:
                client_socket.close()
            except:
                pass