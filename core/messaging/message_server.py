"""
Message Server for Network Scanner application
Handles client connections and message routing
Author: AnoirELGUEDDAR
Date: 2025-06-10 00:50:41
"""

import socket
import threading
import json
import logging
import os
import time
import base64
from datetime import datetime

from core.messaging.message import Message, MessageType
from core.remote.device_manager import DeviceManager

class MessageServer:
    def __init__(self, port=9876, message_service=None, auth_token="change_this_token_immediately"):
        self.port = port
        self.message_service = message_service
        self.running = False
        self.auth_token = auth_token
        self.logger = logging.getLogger(__name__)
        
        # Active clients
        self.active_clients = {}  # client_id -> {last_seen, info}
        
        # Initialiser le gestionnaire d'appareils pour accéder aux appareils gérés
        self.device_manager = DeviceManager()
        
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

            elif command == "direct_message":
                # Envoyer un message directement à un appareil distant
                target_device = params.get("device_id")
                message_text = params.get("message")
                priority = params.get("priority", "normal")
                require_ack = params.get("require_acknowledgement", False)
                sender = params.get("sender", "Administrator")
                
                if not target_device or not message_text:
                    response = {"status": "error", "message": "Device ID and message text required"}
                else:
                    # Vérifier si l'appareil existe
                    if target_device in self.device_manager.devices:
                        # Envoyer la commande à l'agent distant
                        success = self.send_message_to_device(
                            target_device, 
                            message_text, 
                            sender=sender,
                            priority=priority, 
                            require_ack=require_ack
                        )
                        
                        if success:
                            response = {"status": "success", "message": f"Message envoyé à {target_device}"}
                            
                            # Enregistrer dans l'historique centralisé si message_service est disponible
                            if self.message_service:
                                device_name = self.device_manager.devices[target_device].get("name", target_device)
                                central_msg = Message(
                                    content=f"[Message envoyé] {message_text}",
                                    msg_type=MessageType.DIRECT,
                                    sender="Administrator",
                                    recipient=device_name
                                )
                                self.message_service.send_message(central_msg)
                        else:
                            response = {"status": "error", "message": f"Échec d'envoi à {target_device}"}
                    else:
                        response = {"status": "error", "message": f"Appareil {target_device} introuvable"}

            elif command == "get_device_messages":
                # Récupérer les messages stockés sur un appareil distant
                device_id = params.get("device_id")
                include_read = params.get("include_read", True)
                
                if not device_id:
                    response = {"status": "error", "message": "Device ID required"}
                else:
                    messages = self._get_device_messages(device_id, include_read)
                    if messages is not None:
                        response = {"status": "success", "data": {"messages": messages}}
                    else:
                        response = {"status": "error", "message": f"Échec de récupération des messages pour {device_id}"}

            elif command == "mark_message_read":
                # Marquer un message comme lu sur un appareil distant
                device_id = params.get("device_id")
                message_id = params.get("message_id")
                
                if not device_id or not message_id:
                    response = {"status": "error", "message": "Device ID and message ID required"}
                else:
                    success = self.mark_message_read(device_id, message_id)
                    if success:
                        response = {"status": "success", "message": "Message marqué comme lu"}
                    else:
                        response = {"status": "error", "message": "Échec de marquage du message"}
                
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
    
    def send_message_to_device(self, device_id, message_text, sender="Administrator", priority="normal", require_ack=False):
        """
        Méthode améliorée pour envoyer un message à un appareil distant
        """
        try:
            # Résoudre l'identifiant si c'est une IP
            if device_id not in self.device_manager.devices:
                # Tenter de résoudre par IP
                for did, device in self.device_manager.devices.items():
                    if device.get("ip") == device_id:
                        device_id = did
                        break
                
                # Si toujours pas trouvé
                if device_id not in self.device_manager.devices:
                    self.logger.error(f"Appareil {device_id} non trouvé")
                    return False
            
            # Récupérer les informations de l'appareil
            device = self.device_manager.devices[device_id]
            ip = device.get("ip")
            port = device.get("port", 9877)  # Port par défaut de l'agent
            token = device.get("token")
            
            # Préparer les paramètres du message
            message_params = {
                "type": "send",
                "text": message_text,
                "sender": sender,
                "priority": priority,
                "require_ack": require_ack,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
            # Créer la connexion à l'agent
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            
            try:
                sock.connect((ip, int(port)))
            except (socket.error, ConnectionRefusedError) as e:
                self.logger.error(f"Impossible de se connecter à {ip}:{port}: {e}")
                return False
            
            # Préparer le message
            message = {
                "auth_token": token,
                "command": "message",
                "params": message_params
            }
            
            # Envoyer la commande
            sock.sendall(json.dumps(message).encode('utf-8'))
            
            # Recevoir la réponse avec timeout
            response_data = b""
            sock.settimeout(10)
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response_data += chunk
                    if chunk.endswith(b'}'):
                        break
            except socket.timeout:
                self.logger.warning(f"Timeout lors de la réception de la réponse de {ip}:{port}")
            
            sock.close()
            
            # Analyser la réponse
            if response_data:
                try:
                    response = json.loads(response_data.decode('utf-8'))
                    success = response.get("status") == "success"
                    
                    if success:
                        self.logger.info(f"Message envoyé avec succès à {device_id}")
                        
                        # Mettre à jour le statut de l'appareil
                        if "last_connected" not in device or not device["last_connected"]:
                            device["last_connected"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            device["status"] = "online"
                            self.device_manager.save_devices()
                    else:
                        self.logger.error(f"Échec de l'envoi du message à {device_id}: {response.get('message', 'Erreur inconnue')}")
                    
                    return success
                except json.JSONDecodeError:
                    self.logger.error(f"Réponse invalide de {ip}:{port}: {response_data}")
                    return False
            
            return False
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'envoi du message à {device_id}: {e}")
            return False
            
    def _send_direct_message(self, device_id, message_params):
        """
        Méthode existante conservée pour compatibilité, utilise la nouvelle implémentation 
        """
        try:
            # Extraire les paramètres essentiels
            text = message_params.get("text", "")
            sender = message_params.get("sender", "Administrator")
            priority = message_params.get("priority", "normal")
            require_ack = message_params.get("require_ack", False)
            
            # Appeler la nouvelle méthode
            return self.send_message_to_device(
                device_id, 
                text, 
                sender=sender,
                priority=priority, 
                require_ack=require_ack
            )
            
        except Exception as e:
            self.logger.error(f"Erreur dans _send_direct_message: {e}")
            return False
            
    def _get_device_messages(self, device_id, include_read=True, fallback_to_local=True):
        """
        Récupère les messages stockés sur un appareil distant, avec fallback
        """
        try:
            if device_id not in self.device_manager.devices:
                return None
                
            device = self.device_manager.devices[device_id]
            ip = device.get("ip")
            port = device.get("port", 9877)
            token = device.get("token")
            
            # Créer la connexion
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            
            try:
                sock.connect((ip, int(port)))
            except (socket.error, ConnectionRefusedError) as e:
                self.logger.error(f"Connexion échouée à {ip}:{port}: {e}")
                if fallback_to_local and device.get("last_messages"):
                    self.logger.info(f"Utilisation des messages en cache pour {device_id}")
                    return device.get("last_messages")
                return None
            
            # Préparer la requête
            message = {
                "auth_token": token,
                "command": "message",
                "params": {
                    "type": "list",
                    "include_read": include_read
                }
            }
            
            # Envoyer la requête
            sock.sendall(json.dumps(message).encode('utf-8'))
            
            # Recevoir la réponse avec gestion améliorée
            response_data = b""
            sock.settimeout(10)
            start_time = time.time()
            
            try:
                while time.time() - start_time < 10:  # Timeout de 10 secondes
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response_data += chunk
                    if chunk.endswith(b'}'):
                        break
            except socket.timeout:
                self.logger.warning(f"Timeout lors de la réception des messages de {ip}:{port}")
                
            sock.close()
            
            # Analyser la réponse
            if response_data:
                try:
                    response = json.loads(response_data.decode('utf-8'))
                    if response.get("status") == "success":
                        messages = response.get("data", {}).get("messages", [])
                        
                        # Mettre en cache pour usage futur
                        device["last_messages"] = messages
                        device["last_message_update"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        self.device_manager.save_devices()
                        
                        return messages
                except json.JSONDecodeError:
                    self.logger.error(f"Réponse JSON invalide de {ip}:{port}")
                    
            # Utiliser le cache si disponible
            if fallback_to_local and device.get("last_messages"):
                self.logger.info(f"Utilisation des messages en cache pour {device_id}")
                return device.get("last_messages")
                
            return None
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des messages de {device_id}: {e}")
            
            # Utiliser le cache si disponible
            if fallback_to_local and device.get("last_messages"):
                self.logger.info(f"Utilisation des messages en cache pour {device_id}")
                return device.get("last_messages")
                
            return None

    def mark_message_read(self, device_id, message_id):
        """Marque un message comme lu sur un appareil distant"""
        try:
            if device_id not in self.device_manager.devices:
                return False
                
            device = self.device_manager.devices[device_id]
            ip = device.get("ip")
            port = device.get("port", 9877)
            token = device.get("token")
            
            # Créer la connexion
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            
            try:
                sock.connect((ip, int(port)))
            except (socket.error, ConnectionRefusedError) as e:
                self.logger.error(f"Connexion échouée à {ip}:{port}: {e}")
                return False
            
            # Préparer la requête
            message = {
                "auth_token": token,
                "command": "message",
                "params": {
                    "type": "mark_read",
                    "message_id": message_id
                }
            }
            
            # Envoyer la requête
            sock.sendall(json.dumps(message).encode('utf-8'))
            
            # Recevoir la réponse
            response_data = b""
            try:
                response_data = sock.recv(4096)
            except socket.timeout:
                self.logger.warning(f"Timeout lors de la réception de la réponse de {ip}:{port}")
                sock.close()
                return False
            
            sock.close()
            
            # Analyser la réponse
            if response_data:
                try:
                    response = json.loads(response_data.decode('utf-8'))
                    success = response.get("status") == "success"
                    
                    # Mettre à jour le cache si le message est marqué comme lu
                    if success and device.get("last_messages"):
                        for msg in device.get("last_messages", []):
                            if msg.get("id") == message_id:
                                msg["read"] = True
                                self.logger.info(f"Message {message_id} marqué comme lu dans le cache")
                                self.device_manager.save_devices()
                                break
                    
                    return success
                except json.JSONDecodeError:
                    self.logger.error(f"Réponse JSON invalide de {ip}:{port}")
            
            return False
            
        except Exception as e:
            self.logger.error(f"Erreur lors du marquage du message {message_id} sur {device_id}: {e}")
            return False