"""
Device Manager for Remote Management
Current Date: 2025-06-10 00:12:11
Author: AnoirELGUEDDAR
"""
import os
import json
import socket
import struct
import logging
import traceback
import base64
from datetime import datetime
import threading
import time
import re
import xml.etree.ElementTree as ET
import tempfile

logger = logging.getLogger(__name__)

class DeviceManager:
    """Management of remote devices via network agent"""
    
    CONFIG_FILE = "remote_devices.json"
    
    def __init__(self):
        """Initialize the device manager"""
        self.devices = {}
        self.load_devices()
        self.device_change_callbacks = []
        self.connection_test_callbacks = {}
        
        # Start periodic check thread
        self._running = True
        self._check_thread = threading.Thread(target=self._periodic_check, daemon=True)
        self._check_thread.start()
        
        # Important: Register messaging client if not present
        self._register_default_messaging_client()
        
    def _register_default_messaging_client(self):
        """Register the default messaging client if not present"""
        client_ip = "192.168.100.24"  # IP fixe du client
        client_port = 9877           # Port standard de l'agent
        client_id = f"client_{client_ip.replace('.', '_')}"
        token = "change_this_token_immediately"
        
        if client_id not in self.devices:
            logger.info(f"Registering default messaging client {client_id} at {client_ip}:{client_port}")
            self.devices[client_id] = {
                "name": f"Agent sur {client_ip}",
                "ip": client_ip,
                "port": client_port,
                "token": token,
                "status": "online",  # Set as online by default
                "last_connected": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "type": "messaging_client",
                "messaging_enabled": True
            }
            self.save_devices()
            
    def _periodic_check(self):
        """Periodically check device status"""
        while self._running:
            try:
                time.sleep(300)  # Check every 5 minutes
                devices_copy = self.devices.copy()
                for device_id in devices_copy:
                    self.ping_device_async(device_id)
            except Exception as e:
                logger.error(f"Error during periodic check: {e}")
    
    def save_devices(self):
        """Save devices to configuration file"""
        try:
            with open(self.CONFIG_FILE, 'w') as f:
                json.dump(self.devices, f, indent=4)
            return True
        except Exception as e:
            logger.error(f"Error saving devices: {e}")
            return False
            
    def load_devices(self):
        """Load devices from configuration file"""
        if os.path.exists(self.CONFIG_FILE):
            try:
                with open(self.CONFIG_FILE, 'r') as f:
                    self.devices = json.load(f)
                return True
            except Exception as e:
                logger.error(f"Error loading devices: {e}")
                return False
        return True
    
    def add_device(self, name, ip, port, token):
        """Add a new device with non-blocking connection test"""
        device_id = f"{ip}:{port}"
        
        # Update if device exists, otherwise create new entry
        if device_id in self.devices:
            self.devices[device_id].update({
                "name": name,
                "token": token
            })
        else:
            self.devices[device_id] = {
                "name": name,
                "ip": ip,
                "port": port,
                "token": token,
                "status": "unknown",
                "last_connected": ""
            }
        
        # Save first without waiting for ping
        self.save_devices()
        self._notify_device_change()
        
        # Ping device in background thread to verify connection
        self.ping_device_async(device_id)
        
        return True  # Return immediately, don't wait for ping
    
    def remove_device(self, device_id):
        """Remove a device"""
        if device_id in self.devices:
            del self.devices[device_id]
            self.save_devices()
            self._notify_device_change()
            return True
        return False
    
    def get_devices(self):
        """Get the list of devices"""
        return self.devices
    
    def ping_device_async(self, device_id, callback=None):
        """
        Check if a device is online asynchronously
        
        Args:
            device_id: ID of the device to ping
            callback: Optional callback function called with result (bool)
        """
        if device_id not in self.devices:
            logger.warning(f"Device {device_id} not found")
            if callback:
                callback(False)
            return False
        
        # Start the ping in a separate thread
        def ping_thread():
            success = self.ping_device_internal(device_id)
            # Call the callback if provided
            if callback:
                callback(success)
            # Notify all listeners that device status changed
            self._notify_device_change()
            
        threading.Thread(target=ping_thread, daemon=True).start()
        return True
    
    def ping_device(self, device_id):
        """
        Backward compatibility wrapper for ping_device_internal
        This function is now deprecated as it blocks the calling thread
        """
        logger.warning("ping_device is deprecated, use ping_device_async instead")
        return self.ping_device_internal(device_id)
    
    def ping_device_internal(self, device_id):
        """
        Internal implementation to check if a device is online
        This method blocks the calling thread
        """
        if device_id not in self.devices:
            logger.warning(f"Device {device_id} not found")
            return False
        
        device = self.devices[device_id]
        ip = device["ip"]
        port = device["port"]
        token = device["token"]
        
        logger.debug(f"Testing connection to {ip}:{port}")
        
        try:
            # Check if port is open
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)  # Reduced timeout for better responsiveness
            result = sock.connect_ex((ip, int(port)))
            
            if result == 0:
                # Port is open, try to ping the agent
                try:
                    # Prepare JSON message
                    message = {
                        "auth_token": token,
                        "command": "ping"
                    }
                    
                    # Send and receive
                    sock.sendall(json.dumps(message).encode('utf-8'))
                    sock.settimeout(5)
                    response_data = sock.recv(1024)
                    
                    if response_data:
                        try:
                            response = json.loads(response_data.decode('utf-8'))
                            if response.get("status") == "success":
                                # Update status
                                self.devices[device_id]["status"] = "online"
                                self.devices[device_id]["last_connected"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                # Get platform info if available
                                if response.get("agent_version"):
                                    self.devices[device_id]["agent_version"] = response.get("agent_version")
                                if response.get("platform"):
                                    self.devices[device_id]["platform"] = response.get("platform")
                                self.save_devices()
                                logger.info(f"Device {ip}:{port} is online (ping response)")
                                sock.close()
                                return True
                        except json.JSONDecodeError:
                            logger.warning(f"Invalid response from {ip}:{port}: {response_data}")
                except Exception as e:
                    logger.error(f"Error pinging agent: {e}")
                
                # If TCP connected but protocol failed, still consider online
                self.devices[device_id]["status"] = "online"
                self.devices[device_id]["last_connected"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.save_devices()
                logger.info(f"Device {ip}:{port} is online (port open only)")
                sock.close()
                return True
            else:
                # Port closed
                logger.info(f"Port {port} closed on {ip}, error code: {result}")
                self.devices[device_id]["status"] = "offline"
                self.save_devices()
                sock.close()
                return False
                
        except Exception as e:
            logger.error(f"Error testing connection to {ip}:{port}: {str(e)}")
            self.devices[device_id]["status"] = "offline"
            self.save_devices()
            return False
    
    # === Messaging-specific methods ===
    
    def register_messaging_client(self, name, ip, port, token):
        """Register a specific messaging client"""
        device_id = f"client_{ip.replace('.', '_')}"
        
        # Add client with messaging-specific properties
        self.devices[device_id] = {
            "name": name,
            "ip": ip,
            "port": port,
            "token": token,
            "status": "unknown",
            "last_connected": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "type": "messaging_client",
            "messaging_enabled": True
        }
        
        self.save_devices()
        self._notify_device_change()
        
        # Ping device in background thread to verify connection
        self.ping_device_async(device_id)
        
        return device_id
    
    def send_message_to_client(self, client_id, message_text, sender="Administrator", priority="normal", require_ack=False):
        """Send a message to a messaging client"""
        if client_id not in self.devices:
            # Try resolving by IP address
            client_ip = client_id
            for device_id, device in self.devices.items():
                if device.get("ip") == client_ip:
                    client_id = device_id
                    break
                    
            # If still not found, check if it's an IP address that can be registered
            if client_id not in self.devices and re.match(r'^\d+\.\d+\.\d+\.\d+$', client_id):
                # Auto-register the device
                device_id = self.register_messaging_client(
                    f"Agent sur {client_id}",
                    client_id,
                    9877,
                    "change_this_token_immediately"
                )
                client_id = device_id
        
        # If still not found after resolution attempts
        if client_id not in self.devices:
            logger.error(f"Client {client_id} not found for messaging")
            return False
        
        device = self.devices[client_id]
        
        try:
            # Create socket connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((device["ip"], int(device["port"])))
            
            # Prepare message 
            message_params = {
                "type": "send",
                "text": message_text,
                "sender": sender,
                "priority": priority,
                "require_ack": require_ack,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
            message_data = {
                "auth_token": device["token"],
                "command": "message",
                "params": message_params
            }
            
            # Send message
            sock.sendall(json.dumps(message_data).encode('utf-8'))
            
            # Get response
            response_data = sock.recv(4096)
            sock.close()
            
            # Process response
            if response_data:
                try:
                    response = json.loads(response_data.decode('utf-8'))
                    success = response.get("status") == "success"
                    
                    if success:
                        logger.info(f"Message sent successfully to client {client_id}")
                        # Update last_connected time
                        self.devices[client_id]["last_connected"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        self.devices[client_id]["status"] = "online"
                        self.save_devices()
                    else:
                        logger.error(f"Error sending message to client {client_id}: {response.get('message', 'Unknown error')}")
                        
                    return success
                except json.JSONDecodeError:
                    logger.error(f"Invalid response from client {client_id}")
                    return False
            
            return False
            
        except Exception as e:
            logger.error(f"Error sending message to client {client_id}: {str(e)}")
            return False
    
    def get_client_messages(self, client_id, include_read=True):
        """Get messages stored on a client"""
        if client_id not in self.devices:
            logger.error(f"Client {client_id} not found for retrieving messages")
            return None
        
        device = self.devices[client_id]
        
        try:
            # Create socket connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((device["ip"], int(device["port"])))
            
            # Prepare request
            message_data = {
                "auth_token": device["token"],
                "command": "message",
                "params": {
                    "type": "list",
                    "include_read": include_read
                }
            }
            
            # Send request
            sock.sendall(json.dumps(message_data).encode('utf-8'))
            
            # Get response with potential chunking for large responses
            response_data = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response_data += chunk
                    if chunk.endswith(b'}'):  # Potential JSON end
                        break
                except socket.timeout:
                    break
            
            sock.close()
            
            # Process response
            if response_data:
                try:
                    response = json.loads(response_data.decode('utf-8'))
                    if response.get("status") == "success":
                        messages = response.get("data", {}).get("messages", [])
                        
                        # Update last_connected time
                        self.devices[client_id]["last_connected"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        self.devices[client_id]["status"] = "online"
                        self.save_devices()
                        
                        return messages
                    else:
                        logger.error(f"Error retrieving messages from client {client_id}: {response.get('message', 'Unknown error')}")
                        return None
                except json.JSONDecodeError:
                    logger.error(f"Invalid response from client {client_id}")
                    return None
            
            return None
            
        except Exception as e:
            logger.error(f"Error retrieving messages from client {client_id}: {str(e)}")
            return None
    
    def mark_message_read_on_client(self, client_id, message_id):
        """Mark a message as read on a client"""
        if client_id not in self.devices:
            logger.error(f"Client {client_id} not found for marking message as read")
            return False
        
        device = self.devices[client_id]
        
        try:
            # Create socket connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((device["ip"], int(device["port"])))
            
            # Prepare request
            message_data = {
                "auth_token": device["token"],
                "command": "message",
                "params": {
                    "type": "mark_read",
                    "message_id": message_id
                }
            }
            
            # Send request
            sock.sendall(json.dumps(message_data).encode('utf-8'))
            
            # Get response
            response_data = sock.recv(4096)
            sock.close()
            
            # Process response
            if response_data:
                try:
                    response = json.loads(response_data.decode('utf-8'))
                    success = response.get("status") == "success"
                    
                    if success:
                        logger.info(f"Message {message_id} marked as read on client {client_id}")
                    else:
                        logger.error(f"Error marking message as read on client {client_id}: {response.get('message', 'Unknown error')}")
                        
                    return success
                except json.JSONDecodeError:
                    logger.error(f"Invalid response from client {client_id}")
                    return False
            
            return False
            
        except Exception as e:
            logger.error(f"Error marking message as read on client {client_id}: {str(e)}")
            return False

    def test_device_connection(self, name, ip, port, token, callback=None):
        """
        Test connection to a device without adding it to the device list.
        Non-blocking implementation that keeps UI responsive.
        """
        logger.info(f"Testing connection to {name} at {ip}:{port}")
        
        # Generate a test ID to track this test
        test_id = f"{ip}:{port}:{time.time()}"
        
        # Function executed in separate thread
        def test_thread():
            success = False
            error_message = ""
            
            try:
                # Check if port is open
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)  # Short timeout for UI responsiveness
                
                logger.debug(f"Connecting to {ip}:{port}...")
                result = sock.connect_ex((ip, int(port)))
                
                if result == 0:
                    logger.debug(f"TCP connection to {ip}:{port} successful")
                    # Port is open, try to ping the agent
                    try:
                        # Prepare JSON message
                        message = {
                            "auth_token": token,
                            "command": "ping"
                        }
                        
                        # Send ping
                        logger.debug(f"Sending ping to {ip}:{port}")
                        sock.sendall(json.dumps(message).encode('utf-8'))
                        
                        # Receive response with timeout
                        sock.settimeout(5)
                        response_data = sock.recv(1024)
                        
                        if response_data:
                            try:
                                response = json.loads(response_data.decode('utf-8'))
                                if response.get("status") == "success":
                                    success = True
                                    logger.info(f"Ping successful to {ip}:{port}")
                                else:
                                    error_message = f"Réponse de l'agent: {response.get('message', 'Erreur inconnue')}"
                                    logger.warning(f"Ping failed with response: {error_message}")
                            except json.JSONDecodeError:
                                error_message = "Réponse non-JSON reçue de l'agent"
                                logger.warning(f"Invalid JSON response from {ip}:{port}")
                        else:
                            error_message = "Aucune réponse de l'agent"
                            logger.warning(f"No response from {ip}:{port}")
                    except socket.timeout:
                        error_message = "Délai de réponse dépassé"
                        logger.warning(f"Socket timeout waiting for response from {ip}:{port}")
                    except Exception as e:
                        error_message = f"Erreur de communication: {str(e)}"
                        logger.error(f"Communication error with {ip}:{port}: {e}")
                else:
                    error_message = f"Le port {port} est fermé (code {result})"
                    logger.warning(f"Port {port} closed on {ip}, error code: {result}")
                
                # Close socket
                try:
                    sock.close()
                except:
                    pass
                    
            except socket.timeout:
                error_message = "Délai de connexion dépassé"
                logger.warning(f"Connection timeout to {ip}:{port}")
            except Exception as e:
                error_message = f"Erreur: {str(e)}"
                logger.error(f"Test connection error to {ip}:{port}: {e}")
            
            # Call callback with results
            if callback:
                try:
                    callback(success, error_message)
                except Exception as e:
                    logger.error(f"Error in test connection callback: {e}")
        
        # Start test thread
        thread = threading.Thread(target=test_thread, daemon=True)
        thread.start()
        
        return test_id
    
    def _execute_command_with_socket(self, device_id, command, params=None, timeout=30):
        """
        Helper method to execute commands via socket connection
        """
        if device_id not in self.devices:
            return None
            
        device = self.devices[device_id]
        
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((device["ip"], int(device["port"])))
            
            # Prepare message
            message = {
                "auth_token": device["token"],
                "command": command
            }
            if params:
                message["params"] = params
                
            # Send command
            sock.sendall(json.dumps(message).encode('utf-8'))
            
            # Receive response
            response_data = b""
            start_time = time.time()
            while time.time() - start_time < timeout:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response_data += chunk
                    if chunk.endswith(b'}'):  # Probable end of JSON
                        break
                except socket.timeout:
                    break
            
            sock.close()
            
            # Parse response
            if response_data:
                try:
                    response = json.loads(response_data.decode('utf-8'))
                    if response.get("status") == "success":
                        if command == "execute":
                            return response.get("data", {}).get("output", "")
                        return response.get("data", {})
                except json.JSONDecodeError:
                    pass
            
            return None
            
        except Exception as e:
            logger.error(f"Error executing command {command}: {str(e)}")
            return None
    
    def execute_command_async(self, device_id, command, params=None, callback=None, timeout=30):
        """
        Execute a command asynchronously to prevent UI blocking
        
        Args:
            device_id: Device identifier
            command: Command to execute
            params: Parameters for the command
            callback: Function called with result when complete
            timeout: Timeout in seconds
        """
        if device_id not in self.devices:
            if callback:
                callback(None)
            return False
            
        device = self.devices[device_id]
        
        # Execute in thread
        def execute_thread():
            result = None
            try:
                # Create socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect((device["ip"], int(device["port"])))
                
                # Prepare message
                message = {
                    "auth_token": device["token"],
                    "command": command
                }
                if params:
                    message["params"] = params
                    
                # Send command
                sock.sendall(json.dumps(message).encode('utf-8'))
                
                # Receive response
                response_data = b""
                start_time = time.time()
                while time.time() - start_time < timeout:
                    try:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        response_data += chunk
                        if chunk.endswith(b'}'):  # Probable end of JSON
                            break
                    except socket.timeout:
                        break
                
                sock.close()
                
                # Parse response
                if response_data:
                    try:
                        response = json.loads(response_data.decode('utf-8'))
                        if response.get("status") == "success":
                            if command == "execute":
                                result = response.get("data", {}).get("output", "")
                            else:
                                result = response.get("data", {})
                    except json.JSONDecodeError:
                        pass
            except Exception as e:
                logger.error(f"Error in async command execution: {str(e)}")
            
            # Call callback with result
            if callback:
                try:
                    callback(result)
                except Exception as e:
                    logger.error(f"Error in execute command callback: {e}")
        
        # Start execution thread
        thread = threading.Thread(target=execute_thread, daemon=True)
        thread.start()
        
        return True
    
    def get_system_info(self, device_id):
        """Get system information from a remote device"""
        return self._execute_command_with_socket(device_id, "system_info", timeout=10)
    
    def get_system_info_async(self, device_id, callback=None):
        """Get system information asynchronously"""
        return self.execute_command_async(device_id, "system_info", callback=callback, timeout=10)
    
    def execute_command(self, device_id, command):
        """Execute a command on a remote device"""
        if device_id not in self.devices:
            return None
        
        device = self.devices[device_id]
        
        # Detect Windows device and adjust command if needed
        is_windows = "windows" in device.get("platform", "").lower()
        if is_windows:
            if command.startswith("ls -la"):
                command = command.replace("ls -la", "dir /a")
            elif command.startswith("ls -"):
                command = command.replace("ls -", "dir ")
            elif command.startswith("find /"):
                search_term = command.split("-name")[1].strip().replace('"', '').replace("*", "").replace("'", "")
                command = f"dir /s /b | findstr /i \"{search_term}\""
            elif command.startswith("mkdir -p"):
                path = command.split("mkdir -p")[1].strip().replace('"', '')
                command = f"if not exist \"{path}\" mkdir \"{path}\""
            elif command.startswith("rm -f"):
                path = command.split("rm -f")[1].strip().replace('"', '')
                command = f"del /q \"{path}\""
        
        # Execute command
        return self._execute_command_with_socket(device_id, "execute", params={"cmd": command}, timeout=30)
    
    def send_file_async(self, device_id, local_file_path, remote_directory, callback=None):
        """
        Send a file to a remote device asynchronously
        
        Args:
            device_id: ID of the device
            local_file_path: Path to the local file
            remote_directory: Target directory on the remote device
            callback: Function called with success flag (bool) when complete
        """
        if device_id not in self.devices:
            logger.error(f"Device {device_id} unknown")
            if callback:
                callback(False)
            return False
        
        # Validate file exists
        if not os.path.isfile(local_file_path):
            logger.error(f"File {local_file_path} not found")
            if callback:
                callback(False)
            return False
        
        # Execute in thread
        def upload_thread():
            success = False
            try:
                device = self.devices[device_id]
                
                # Read file content
                with open(local_file_path, 'rb') as f:
                    file_content = f.read()
                
                # Get filename
                file_name = os.path.basename(local_file_path)
                
                # Debug info
                file_size = len(file_content)
                logger.info(f"Sending file {file_name} to {device_id}, size: {file_size} bytes")
                
                # Use base64 encoding
                content_b64 = base64.b64encode(file_content).decode('ascii')
                
                # Create socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(60)  # Longer timeout for file transfers
                
                try:
                    sock.connect((device["ip"], int(device["port"])))
                except socket.error as e:
                    logger.error(f"Socket error connecting to {device_id}: {str(e)}")
                    sock.close()
                    if callback:
                        callback(False)
                    return
                
                # Send command
                try:
                    message = {
                        "auth_token": device["token"],
                        "command": "upload_file",
                        "params": {
                            "file_name": file_name,
                            "directory": remote_directory,
                            "encoding": "base64",
                            "content": content_b64
                        }
                    }
                    
                    # Serialize and send
                    json_data = json.dumps(message).encode('utf-8')
                    sock.sendall(json_data)
                    logger.info(f"Data sent to {device_id}, JSON size: {len(json_data)} bytes")
                    
                except Exception as e:
                    logger.error(f"Error sending to {device_id}: {str(e)}")
                    sock.close()
                    if callback:
                        callback(False)
                    return
                
                # Receive response
                try:
                    response_data = b""
                    sock.settimeout(60)
                    try:
                        response_data = sock.recv(4096)
                    except socket.timeout:
                        logger.error("Timeout waiting for response")
                        sock.close()
                        if callback:
                            callback(False)
                        return
                    
                    sock.close()
                    
                    # Parse response
                    if response_data:
                        try:
                            response = json.loads(response_data.decode('utf-8'))
                            success = response.get("status") == "success"
                            logger.info(f"Response received: {success}")
                        except json.JSONDecodeError as e:
                            logger.error(f"JSON error in response: {str(e)}")
                            success = False
                    else:
                        logger.error("No response received")
                        success = False
                        
                except Exception as e:
                    logger.error(f"Error receiving response: {str(e)}")
                    success = False
            except Exception as e:
                logger.error(f"General error in file upload: {str(e)}")
                success = False
            
            # Call callback with result
            if callback:
                try:
                    callback(success)
                except Exception as e:
                    logger.error(f"Error in send file callback: {e}")
        
        # Start upload thread
        thread = threading.Thread(target=upload_thread, daemon=True)
        thread.start()
        
        return True  # Return success of starting the thread
    
    def send_file(self, device_id, local_file_path, remote_directory):
        """Send a file to a remote device"""
        if device_id not in self.devices:
            logger.error(f"Device {device_id} unknown")
            return False
        
        device = self.devices[device_id]
        
        try:
            # Check if file exists
            if not os.path.isfile(local_file_path):
                logger.error(f"File {local_file_path} not found")
                return False
            
            # Read file content
            with open(local_file_path, 'rb') as f:
                file_content = f.read()
            
            # Get filename
            file_name = os.path.basename(local_file_path)
            
            # Debug info
            file_size = len(file_content)
            if file_size > 1024*1024:
                logger.warning(f"Large file: {file_size} bytes. May fail.")
            logger.info(f"Sending file {file_name} to {device_id}, size: {file_size} bytes")
            
            # Use base64 encoding
            content_b64 = base64.b64encode(file_content).decode('ascii')
            
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(60)  # Longer timeout for file transfers
            
            try:
                sock.connect((device["ip"], int(device["port"])))
            except socket.error as e:
                logger.error(f"Socket error connecting to {device_id}: {str(e)}")
                sock.close()
                return False
            
            # Send command
            try:
                message = {
                    "auth_token": device["token"],
                    "command": "upload_file",
                    "params": {
                        "file_name": file_name,
                        "directory": remote_directory,
                        "encoding": "base64",
                        "content": content_b64
                    }
                }
                
                # Serialize and send
                json_data = json.dumps(message).encode('utf-8')
                sock.sendall(json_data)
                logger.info(f"Data sent to {device_id}, JSON size: {len(json_data)} bytes")
                
            except Exception as e:
                logger.error(f"Error sending to {device_id}: {str(e)}")
                sock.close()
                return False
            
            # Receive response
            try:
                response_data = b""
                sock.settimeout(60)
                try:
                    response_data = sock.recv(4096)
                except socket.timeout:
                    logger.error("Timeout waiting for response")
                    sock.close()
                    return False
                
                sock.close()
                
                # Parse response
                if response_data:
                    try:
                        response = json.loads(response_data.decode('utf-8'))
                        success = response.get("status") == "success"
                        logger.info(f"Response received: {success}")
                        return success
                    except json.JSONDecodeError as e:
                        logger.error(f"JSON error in response: {str(e)}")
                        return False
                else:
                    logger.error("No response received")
                    return False
                    
            except Exception as e:
                logger.error(f"Error receiving response: {str(e)}")
                return False
                
        except Exception as e:
            logger.error(f"General error: {str(e)}")
            return False

    def _device_power_action_async(self, device_id, action, delay=0, callback=None):
        """
        Helper for device power actions (shutdown/restart) with async execution
        """
        if device_id not in self.devices:
            if callback:
                callback(False)
            return False
        
        device = self.devices[device_id]
        
        # Execute in thread
        def power_action_thread():
            success = False
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((device["ip"], int(device["port"])))
                
                message = {
                    "auth_token": device["token"],
                    "command": action,
                    "params": {
                        "delay": delay
                    }
                }
                sock.sendall(json.dumps(message).encode('utf-8'))
                
                # Receive response
                response_data = b""
                try:
                    response_data = sock.recv(4096)
                except socket.timeout:
                    pass
                
                sock.close()
                
                if response_data:
                    try:
                        response = json.loads(response_data.decode('utf-8'))
                        success = response.get("status") == "success"
                    except json.JSONDecodeError:
                        pass
            except Exception as e:
                logger.error(f"Error performing {action} on device: {str(e)}")
            
            # Call callback with result
            if callback:
                try:
                    callback(success)
                except Exception as e:
                    logger.error(f"Error in power action callback: {e}")
        
        # Start thread
        thread = threading.Thread(target=power_action_thread, daemon=True)
        thread.start()
        
        return True
    
    def _device_power_action(self, device_id, action, delay=0):
        """Helper for device power actions (shutdown/restart)"""
        if device_id not in self.devices:
            return False
        
        device = self.devices[device_id]
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((device["ip"], int(device["port"])))
            
            message = {
                "auth_token": device["token"],
                "command": action,
                "params": {
                    "delay": delay
                }
            }
            sock.sendall(json.dumps(message).encode('utf-8'))
            
            # Receive response
            response_data = b""
            try:
                response_data = sock.recv(4096)
            except socket.timeout:
                pass
            
            sock.close()
            
            if response_data:
                try:
                    response = json.loads(response_data.decode('utf-8'))
                    return response.get("status") == "success"
                except json.JSONDecodeError:
                    pass
            
            return False
            
        except Exception as e:
            logger.error(f"Error performing {action} on device: {str(e)}")
            return False
    
    def shutdown_device(self, device_id, delay=0):
        """Shutdown a remote device"""
        return self._device_power_action(device_id, "shutdown", delay)
    
    def shutdown_device_async(self, device_id, delay=0, callback=None):
        """Shutdown a remote device asynchronously"""
        return self._device_power_action_async(device_id, "shutdown", delay, callback)
    
    def restart_device(self, device_id, delay=0):
        """Restart a remote device"""
        return self._device_power_action(device_id, "restart", delay)
    
    def restart_device_async(self, device_id, delay=0, callback=None):
        """Restart a remote device asynchronously"""
        return self._device_power_action_async(device_id, "restart", delay, callback)
    
    def wake_on_lan(self, mac_address, broadcast_ip=None):
        """Send Wake-on-LAN packet"""
        try:
            # Format MAC address
            mac = mac_address.replace(':', '').replace('-', '').replace('.', '')
            if len(mac) != 12:
                logger.error(f"Invalid MAC address format: {mac_address}")
                return False
            
            # Build "Magic Packet"
            mac_bytes = bytes.fromhex(mac)
            magic_packet = b'\xff' * 6 + mac_bytes * 16
            
            # Default broadcast address
            if not broadcast_ip:
                broadcast_ip = '255.255.255.255'
            
            # Send packet
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.sendto(magic_packet, (broadcast_ip, 9))
            sock.close()
            
            logger.info(f"Wake-on-LAN packet sent to {mac_address}")
            return True
            
        except Exception as e:
            logger.error(f"Error sending Wake-on-LAN packet: {str(e)}")
            return False
    
    def cleanup(self):
        """Clean up resources"""
        self._running = False
        if hasattr(self, '_check_thread'):
            self._check_thread.join(1)
    
    # === Device Integration Methods ===
    
    def add_device_change_callback(self, callback):
        """Add callback for device list changes"""
        if callback not in self.device_change_callbacks:
            self.device_change_callbacks.append(callback)
            
    def _notify_device_change(self):
        """Notify callbacks when device list changes"""
        for callback in self.device_change_callbacks:
            try:
                callback()
            except Exception as e:
                logger.error(f"Error in device change callback: {e}")
    
    def get_discovered_devices(self):
        """Get online devices with network_agent"""
        result = []
        for device_id, device in self.devices.items():
            if device.get('status') == 'online':
                result.append({
                    'id': device_id,
                    'ip_address': device.get('ip'),
                    'hostname': device.get('name', f"Agent ({device.get('ip')})"),
                    'has_network_agent': True,
                    'remote_management_enabled': True,
                    'platform': device.get('platform', 'unknown')
                })
        return result

    # Remaining methods in the class are kept as they were...
    # (The rest of the class with all other methods should be preserved)

    # === REMOTE MANAGEMENT MODULES ===
    
    # === Windows Management Instrumentation (WMI) ===
    
    def query_wmi(self, device_id, wmi_query, namespace="root\\\\cimv2"):
        """Execute WMI query on remote Windows device"""
        if device_id not in self.devices:
            logger.error(f"Device {device_id} not found")
            return None
            
        device = self.devices[device_id]
        
        # Check if device is Windows
        if "windows" not in device.get("platform", "").lower():
            logger.error(f"Device {device_id} is not a Windows machine")
            return None
            
        try:
            # Execute WMI query via PowerShell
            ps_command = f'powershell "Get-WmiObject -Query \'{wmi_query}\' -Namespace \'{namespace}\' | ConvertTo-Json -Depth 3"'
            result = self.execute_command(device_id, ps_command)
            
            if not result:
                logger.error(f"Failed to execute WMI query on {device_id}")
                return None
                
            try:
                # Parse JSON result
                return json.loads(result)
            except json.JSONDecodeError:
                logger.error(f"Error parsing WMI query result: {result[:200]}...")
                return None
                
        except Exception as e:
            logger.error(f"Error executing WMI query: {str(e)}")
            return None
    
    def query_wmi_async(self, device_id, wmi_query, namespace="root\\\\cimv2", callback=None):
        """
        Execute WMI query on remote Windows device asynchronously
        """
        if device_id not in self.devices:
            logger.error(f"Device {device_id} not found")
            if callback:
                callback(None)
            return False
            
        device = self.devices[device_id]
        
        # Check if device is Windows
        if "windows" not in device.get("platform", "").lower():
            logger.error(f"Device {device_id} is not a Windows machine")
            if callback:
                callback(None)
            return False
            
        # Execute in thread
        def wmi_thread():
            result = None
            try:
                # Execute WMI query via PowerShell
                ps_command = f'powershell "Get-WmiObject -Query \'{wmi_query}\' -Namespace \'{namespace}\' | ConvertTo-Json -Depth 3"'
                output = self.execute_command(device_id, ps_command)
                
                if output:
                    try:
                        # Parse JSON result
                        result = json.loads(output)
                    except json.JSONDecodeError:
                        logger.error(f"Error parsing WMI query result: {output[:200]}...")
            except Exception as e:
                logger.error(f"Error executing WMI query: {str(e)}")
            
            # Call callback with result
            if callback:
                try:
                    callback(result)
                except Exception as e:
                    logger.error(f"Error in WMI query callback: {e}")
        
        # Start thread
        thread = threading.Thread(target=wmi_thread, daemon=True)
        thread.start()
        
        return True

    # === Registry Management ===
    
    def read_registry_value(self, device_id, key_path, value_name):
        """Read registry value from Windows device"""
        if not self._check_windows_device(device_id):
            return None
            
        try:
            # Format PowerShell command
            key_path = key_path.replace('"', '\\"')
            value_name = value_name.replace('"', '\\"')
            
            ps_command = f'powershell "Get-ItemProperty -Path \'{key_path}\' -Name \'{value_name}\' | ConvertTo-Json"'
            result = self.execute_command(device_id, ps_command)
            
            if not result:
                return None
                
            try:
                data = json.loads(result)
                if value_name in data:
                    return data[value_name]
                return None
            except json.JSONDecodeError:
                logger.error(f"Error parsing registry result: {result[:200]}...")
                return None
                
        except Exception as e:
            logger.error(f"Error reading registry: {str(e)}")
            return None
    
    def _check_windows_device(self, device_id):
        """Helper to check if device is Windows"""
        if device_id not in self.devices:
            return False
            
        device = self.devices[device_id]
        
        # Check if device is Windows
        if "windows" not in device.get("platform", "").lower():
            logger.error(f"Device {device_id} is not a Windows machine")
            return False
            
        return True
    
    def write_registry_value(self, device_id, key_path, value_name, value, value_type="String"):
        """Write registry value to Windows device"""
        if not self._check_windows_device(device_id):
            return False
            
        try:
            # Escape PowerShell values
            key_path = key_path.replace('"', '\\"')
            value_name = value_name.replace('"', '\\"')
            
            # Format value based on type
            if value_type in ["String", "ExpandString", "MultiString"]:
                formatted_value = f"'{value}'"
            elif value_type in ["DWord", "QWord"]:
                formatted_value = str(value)
            elif value_type == "Binary":
                formatted_value = f"([byte[]]{value})"
            else:
                formatted_value = f"'{value}'"
            
            # Create PS command
            ps_command = (
                f'powershell "if (!(Test-Path -Path \'{key_path}\')) {{ '
                f'New-Item -Path \'{key_path}\' -Force | Out-Null }}; '
                f'New-ItemProperty -Path \'{key_path}\' -Name \'{value_name}\' '
                f'-PropertyType {value_type} -Value {formatted_value} -Force | Out-Null; '
                f'if ($?) {{ Write-Output \'SUCCESS\' }} else {{ Write-Output \'FAILED\' }}"'
            )
            
            result = self.execute_command(device_id, ps_command)
            return result and "SUCCESS" in result
            
        except Exception as e:
            logger.error(f"Error writing registry: {str(e)}")
            return False
    
    # === Service Management ===
    
    def list_services(self, device_id):
        """List services on a remote device"""
        if device_id not in self.devices:
            return None
            
        device = self.devices[device_id]
        is_windows = "windows" in device.get("platform", "").lower()
        
        try:
            if is_windows:
                # Windows services via PowerShell
                ps_command = 'powershell "Get-Service | Select-Object Name, DisplayName, Status | ConvertTo-Json"'
                result = self.execute_command(device_id, ps_command)
            else:
                # Linux services via systemctl
                result = self.execute_command(device_id, "systemctl list-units --type=service --all")
            
            if not result:
                return None
                
            if is_windows:
                try:
                    # Parse Windows JSON output
                    services = json.loads(result)
                    
                    # Handle both single service and multiple services
                    if isinstance(services, dict):
                        services = [services]
                    
                    return [{
                        "name": svc.get("Name"),
                        "display_name": svc.get("DisplayName"),
                        "status": svc.get("Status")
                    } for svc in services]
                except json.JSONDecodeError:
                    logger.error(f"Error parsing service list: {result[:200]}...")
                    return None
            else:
                # Parse Linux systemctl output
                services = []
                for line in result.strip().split("\n"):
                    if "not-found" not in line and ".service" in line:
                        parts = line.split()
                        if len(parts) >= 5:
                            status = parts[3]
                            name = parts[0].strip()
                            services.append({
                                "name": name,
                                "display_name": name,
                                "status": status
                            })
                return services
                
        except Exception as e:
            logger.error(f"Error listing services: {str(e)}")
            return None
    
    def list_services_async(self, device_id, callback=None):
        """List services asynchronously"""
        if device_id not in self.devices:
            if callback:
                callback(None)
            return False
            
        device = self.devices[device_id]
        is_windows = "windows" in device.get("platform", "").lower()
        
        # Execute in thread
        def services_thread():
            result = None
            try:
                if is_windows:
                    # Windows services via PowerShell
                    ps_command = 'powershell "Get-Service | Select-Object Name, DisplayName, Status | ConvertTo-Json"'
                    output = self.execute_command(device_id, ps_command)
                else:
                    # Linux services via systemctl
                    output = self.execute_command(device_id, "systemctl list-units --type=service --all")
                
                if output:
                    if is_windows:
                        try:
                            # Parse Windows JSON output
                            services = json.loads(output)
                            
                            # Handle both single service and multiple services
                            if isinstance(services, dict):
                                services = [services]
                            
                            result = [{
                                "name": svc.get("Name"),
                                "display_name": svc.get("DisplayName"),
                                "status": svc.get("Status")
                            } for svc in services]
                        except json.JSONDecodeError:
                            logger.error(f"Error parsing service list: {output[:200]}...")
                    else:
                        # Parse Linux systemctl output
                        services = []
                        for line in output.strip().split("\n"):
                            if "not-found" not in line and ".service" in line:
                                parts = line.split()
                                if len(parts) >= 5:
                                    status = parts[3]
                                    name = parts[0].strip()
                                    services.append({
                                        "name": name,
                                        "display_name": name,
                                        "status": status
                                    })
                        result = services
            except Exception as e:
                logger.error(f"Error listing services: {str(e)}")
            
            # Call callback with result
            if callback:
                try:
                    callback(result)
                except Exception as e:
                    logger.error(f"Error in list services callback: {e}")
        
        # Start thread
        thread = threading.Thread(target=services_thread, daemon=True)
        thread.start()
        
        return True
    
    def _control_service(self, device_id, service_name, action):
        """Helper for service control (start/stop/restart)"""
        if device_id not in self.devices:
            return False
            
        device = self.devices[device_id]
        is_windows = "windows" in device.get("platform", "").lower()
        
        try:
            if is_windows:
                # Windows service action via PowerShell
                ps_command = f'powershell "{action}-Service -Name \'{service_name}\' -ErrorAction SilentlyContinue -Force; $?"'
                result = self.execute_command(device_id, ps_command)
                return result and "True" in result
            else:
                # Linux service action via systemctl
                result = self.execute_command(device_id, f"sudo systemctl {action.lower()} {service_name}")
                # Usually no output means success
                return result is not None  # Even empty string is ok
                
        except Exception as e:
            logger.error(f"Error {action.lower()}ing service {service_name}: {str(e)}")
            return False
    
    def _control_service_async(self, device_id, service_name, action, callback=None):
        """Helper for asynchronous service control"""
        if device_id not in self.devices:
            if callback:
                callback(False)
            return False
            
        device = self.devices[device_id]
        is_windows = "windows" in device.get("platform", "").lower()
        
        # Execute in thread
        def service_thread():
            success = False
            try:
                if is_windows:
                    # Windows service action via PowerShell
                    ps_command = f'powershell "{action}-Service -Name \'{service_name}\' -ErrorAction SilentlyContinue -Force; $?"'
                    result = self.execute_command(device_id, ps_command)
                    success = result and "True" in result
                else:
                    # Linux service action via systemctl
                    result = self.execute_command(device_id, f"sudo systemctl {action.lower()} {service_name}")
                    # Usually no output means success
                    success = result is not None  # Even empty string is ok
            except Exception as e:
                logger.error(f"Error {action.lower()}ing service {service_name}: {str(e)}")
            
            # Call callback with result
            if callback:
                try:
                    callback(success)
                except Exception as e:
                    logger.error(f"Error in service control callback: {e}")
        
        # Start thread
        thread = threading.Thread(target=service_thread, daemon=True)
        thread.start()
        
        return True
    
    def start_service(self, device_id, service_name):
        """Start a service on a remote device"""
        return self._control_service(device_id, service_name, "Start")
    
    def start_service_async(self, device_id, service_name, callback=None):
        """Start a service asynchronously"""
        return self._control_service_async(device_id, service_name, "Start", callback)
    
    def stop_service(self, device_id, service_name):
        """Stop a service on a remote device"""
        return self._control_service(device_id, service_name, "Stop")
    
    def stop_service_async(self, device_id, service_name, callback=None):
        """Stop a service asynchronously"""
        return self._control_service_async(device_id, service_name, "Stop", callback)
    
    def restart_service(self, device_id, service_name):
        """Restart a service on a remote device"""
        return self._control_service(device_id, service_name, "Restart")
    
    def restart_service_async(self, device_id, service_name, callback=None):
        """Restart a service asynchronously"""
        return self._control_service_async(device_id, service_name, "Restart", callback)
    
    # === File Management ===
    
    def list_files(self, device_id, directory_path):
        """List files in a directory on a remote device"""
        if device_id not in self.devices:
            return None
            
        device = self.devices[device_id]
        is_windows = "windows" in device.get("platform", "").lower()
        
        try:
            if is_windows:
                # Windows path handling
                if len(directory_path) == 2 and directory_path[1] == ':':
                    # Add trailing backslash to drive root
                    directory_path = f"{directory_path}\\"
                
                # Windows file listing via PowerShell
                ps_command = (
                    f'powershell "Get-ChildItem -Path \'{directory_path}\' | '
                    f'Select-Object Name, LastWriteTime, Length, @{{Name=\'Type\';Expression={{if($_.PSIsContainer) {{\'Directory\'}} else {{\'File\'}}}}}} | '
                    f'ConvertTo-Json"'
                )
                result = self.execute_command(device_id, ps_command)
            else:
                # Linux file listing
                result = self.execute_command(device_id, f"ls -la {directory_path}")
            
            if not result:
                return None
                
            files = []
            
            if is_windows:
                try:
                    items = json.loads(result)
                    
                    # Handle both single item and array
                    if isinstance(items, dict):
                        items = [items]
                    
                    for item in items:
                        files.append({
                            "name": item.get("Name"),
                            "size": item.get("Length", 0),
                            "modified": item.get("LastWriteTime"),
                            "type": item.get("Type"),
                            "is_dir": item.get("Type") == "Directory"
                        })
                except json.JSONDecodeError:
                    logger.error(f"Error parsing file list: {result[:200]}...")
                    return None
            else:
                # Parse Linux ls output
                lines = result.strip().split("\n")
                
                for line in lines[1:]:  # Skip first line (total)
                    parts = line.split()
                    if len(parts) >= 9:
                        name = " ".join(parts[8:])
                        if name not in [".", ".."]:
                            is_dir = parts[0].startswith("d")
                            size = int(parts[4])
                            
                            files.append({
                                "name": name,
                                "size": size,
                                "modified": f"{parts[5]} {parts[6]} {parts[7]}",
                                "type": "Directory" if is_dir else "File",
                                "is_dir": is_dir
                            })
            
            return files
            
        except Exception as e:
            logger.error(f"Error listing files: {str(e)}")
            return None
    
    def list_files_async(self, device_id, directory_path, callback=None):
        """List files asynchronously"""
        if device_id not in self.devices:
            if callback:
                callback(None)
            return False
            
        device = self.devices[device_id]
        is_windows = "windows" in device.get("platform", "").lower()
        
        # Execute in thread
        def files_thread():
            result = None
            try:
                if is_windows:
                    # Windows path handling
                    if len(directory_path) == 2 and directory_path[1] == ':':
                        # Add trailing backslash to drive root
                        directory_path = f"{directory_path}\\"
                    
                    # Windows file listing via PowerShell
                    ps_command = (
                        f'powershell "Get-ChildItem -Path \'{directory_path}\' | '
                        f'Select-Object Name, LastWriteTime, Length, @{{Name=\'Type\';Expression={{if($_.PSIsContainer) {{\'Directory\'}} else {{\'File\'}}}}}} | '
                        f'ConvertTo-Json"'
                    )
                    output = self.execute_command(device_id, ps_command)
                else:
                    # Linux file listing
                    output = self.execute_command(device_id, f"ls -la {directory_path}")
                
                if output:
                    files = []
                    
                    if is_windows:
                        try:
                            items = json.loads(output)
                            
                            # Handle both single item and array
                            if isinstance(items, dict):
                                items = [items]
                            
                            for item in items:
                                files.append({
                                    "name": item.get("Name"),
                                    "size": item.get("Length", 0),
                                    "modified": item.get("LastWriteTime"),
                                    "type": item.get("Type"),
                                    "is_dir": item.get("Type") == "Directory"
                                })
                        except json.JSONDecodeError:
                            logger.error(f"Error parsing file list: {output[:200]}...")
                    else:
                        # Parse Linux ls output
                        lines = output.strip().split("\n")
                        
                        for line in lines[1:]:  # Skip first line (total)
                            parts = line.split()
                            if len(parts) >= 9:
                                name = " ".join(parts[8:])
                                if name not in [".", ".."]:
                                    is_dir = parts[0].startswith("d")
                                    size = int(parts[4])
                                    
                                    files.append({
                                        "name": name,
                                        "size": size,
                                        "modified": f"{parts[5]} {parts[6]} {parts[7]}",
                                        "type": "Directory" if is_dir else "File",
                                        "is_dir": is_dir
                                    })
                    
                    result = files
            except Exception as e:
                logger.error(f"Error listing files: {str(e)}")
            
            # Call callback with result
            if callback:
                try:
                    callback(result)
                except Exception as e:
                    logger.error(f"Error in list files callback: {e}")
        
        # Start thread
        thread = threading.Thread(target=files_thread, daemon=True)
        thread.start()
        
        return True
    
    def download_file(self, device_id, remote_path, local_path):
        """Download file from remote device to local system"""
        if device_id not in self.devices:
            return False
            
        device = self.devices[device_id]
        
        try:
            # Get file content in base64
            is_windows = "windows" in device.get("platform", "").lower()
            
            if is_windows:
                ps_command = f'powershell "[Convert]::ToBase64String([System.IO.File]::ReadAllBytes(\'{remote_path}\'))"'
                file_content_b64 = self.execute_command(device_id, ps_command)
            else:
                file_content_b64 = self.execute_command(device_id, f"base64 -w 0 '{remote_path}'")
            
            if not file_content_b64:
                logger.error(f"Failed to read file {remote_path} from device {device_id}")
                return False
            
            # Decode base64 content
            try:
                file_content = base64.b64decode(file_content_b64)
            except Exception as e:
                logger.error(f"Error decoding file content: {str(e)}")
                return False
            
            # Write to local file
            try:
                with open(local_path, 'wb') as f:
                    f.write(file_content)
                return True
            except Exception as e:
                logger.error(f"Error writing to local file {local_path}: {str(e)}")
                return False
                
        except Exception as e:
            logger.error(f"Error downloading file: {str(e)}")
            return False
    
    def download_file_async(self, device_id, remote_path, local_path, callback=None):
        """Download file asynchronously"""
        if device_id not in self.devices:
            if callback:
                callback(False)
            return False
            
        device = self.devices[device_id]
        
        # Execute in thread
        def download_thread():
            success = False
            try:
                # Get file content in base64
                is_windows = "windows" in device.get("platform", "").lower()
                
                if is_windows:
                    ps_command = f'powershell "[Convert]::ToBase64String([System.IO.File]::ReadAllBytes(\'{remote_path}\'))"'
                    file_content_b64 = self.execute_command(device_id, ps_command)
                else:
                    file_content_b64 = self.execute_command(device_id, f"base64 -w 0 '{remote_path}'")
                
                if not file_content_b64:
                    logger.error(f"Failed to read file {remote_path} from device {device_id}")
                else:
                    # Decode base64 content
                    try:
                        file_content = base64.b64decode(file_content_b64)
                        
                        # Write to local file
                        with open(local_path, 'wb') as f:
                            f.write(file_content)
                        success = True
                    except Exception as e:
                        logger.error(f"Error processing file content: {str(e)}")
            except Exception as e:
                logger.error(f"Error downloading file: {str(e)}")
            
            # Call callback with result
            if callback:
                try:
                    callback(success)
                except Exception as e:
                    logger.error(f"Error in download file callback: {e}")
        
        # Start thread
        thread = threading.Thread(target=download_thread, daemon=True)
        thread.start()
        
        return True
    
    def upload_file(self, device_id, local_path, remote_path):
        """Upload file from local system to remote device"""
        return self.send_file(device_id, local_path, remote_path)
    
    def upload_file_async(self, device_id, local_path, remote_path, callback=None):
        """Upload file asynchronously"""
        return self.send_file_async(device_id, local_path, remote_path, callback)
    
    def delete_file(self, device_id, file_path):
        """Delete file on remote device"""
        if device_id not in self.devices:
            return False
            
        device = self.devices[device_id]
        is_windows = "windows" in device.get("platform", "").lower()
        
        try:
            if is_windows:
                # Windows delete via PowerShell
                ps_command = f'powershell "Remove-Item -Path \'{file_path}\' -Force -ErrorAction SilentlyContinue; $?"'
                result = self.execute_command(device_id, ps_command)
                return result and "True" in result
            else:
                # Linux delete
                result = self.execute_command(device_id, f"rm -f '{file_path}'")
                return result is not None
                
        except Exception as e:
            logger.error(f"Error deleting file {file_path}: {str(e)}")
            return False

    # === Performance Monitoring ===

    def get_windows_performance_metrics(self, device_id):
        """Get performance metrics specifically for Windows machines"""
        try:
            device = self.devices[device_id]
            result = {}
            
            logger.info(f"Getting Windows performance metrics for {device_id}")
            
            # CPU usage - use simpler PowerShell approach to avoid complex parsing
            cpu_cmd = 'powershell "$cpu = (Get-WmiObject -Class Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average; Write-Output $cpu"'
            cpu_output = self.execute_command(device_id, cpu_cmd)
            
            cpu_usage = 0
            if cpu_output:
                try:
                    cpu_usage = float(cpu_output.strip())
                    result["cpu"] = {"usage_percent": cpu_usage}
                    logger.info(f"Windows CPU usage: {cpu_usage}%")
                except ValueError:
                    result["cpu"] = {"usage_percent": 0}
                    logger.error(f"Failed to parse CPU usage: {cpu_output}")
            else:
                result["cpu"] = {"usage_percent": 0}
                logger.error("No CPU data returned from Windows device")
            
            # Memory usage - use simplified direct commands
            memory_cmd = 'powershell "$mem = Get-WmiObject Win32_OperatingSystem; $total = [math]::Round($mem.TotalVisibleMemorySize * 1024); $free = [math]::Round($mem.FreePhysicalMemory * 1024); $used = $total - $free; $percent = [math]::Round(($used / $total) * 100, 2); Write-Output \\"$total,$free,$used,$percent\\""'
            memory_output = self.execute_command(device_id, memory_cmd)
            
            if memory_output:
                try:
                    parts = memory_output.strip().split(',')
                    if len(parts) >= 4:
                        total_bytes = float(parts[0])
                        free_bytes = float(parts[1])
                        used_bytes = float(parts[2])
                        percent = float(parts[3])
                        
                        result["memory"] = {
                            "total_bytes": total_bytes,
                            "free_bytes": free_bytes,
                            "used_bytes": used_bytes,
                            "usage_percent": percent
                        }
                        logger.info(f"Windows memory: {used_bytes/1024/1024:.1f}MB of {total_bytes/1024/1024:.1f}MB ({percent}%)")
                    else:
                        result["memory"] = {
                            "total_bytes": 0,
                            "free_bytes": 0,
                            "used_bytes": 0,
                            "usage_percent": 0
                        }
                        logger.error(f"Invalid memory output format: {memory_output}")
                except (ValueError, IndexError) as e:
                    result["memory"] = {
                        "total_bytes": 0,
                        "free_bytes": 0,
                        "used_bytes": 0,
                        "usage_percent": 0
                    }
                    logger.error(f"Error parsing memory values: {e}, output was: {memory_output}")
            else:
                result["memory"] = {
                    "total_bytes": 0,
                    "free_bytes": 0,
                    "used_bytes": 0,
                    "usage_percent": 0
                }
                logger.error("No memory data returned from Windows device")
            
            # Disk usage - use simplified command
            disk_cmd = 'powershell "Get-WmiObject Win32_LogicalDisk | Where-Object {$_.DriveType -eq 3} | ForEach-Object { $_.DeviceID + \',\' + $_.Size + \',\' + $_.FreeSpace }"'
            disk_output = self.execute_command(device_id, disk_cmd)
            
            if disk_output:
                try:
                    lines = disk_output.strip().split('\n')
                    disks = []
                    
                    for line in lines:
                        parts = line.strip().split(',')
                        if len(parts) >= 3:
                            device = parts[0]
                            try:
                                size = float(parts[1])
                                free = float(parts[2])
                                used = size - free
                                usage_percent = (used / size) * 100 if size > 0 else 0
                                
                                disks.append({
                                    "device": device,
                                    "total_bytes": size,
                                    "free_bytes": free,
                                    "used_bytes": used,
                                    "usage_percent": round(usage_percent, 2)
                                })
                                logger.info(f"Windows disk {device}: {usage_percent:.1f}% used")
                            except (ValueError, ZeroDivisionError):
                                continue
                    
                    if disks:
                        result["disk"] = disks
                    else:
                        result["disk"] = [{
                            "device": "Unknown",
                            "total_bytes": 0,
                            "free_bytes": 0,
                            "used_bytes": 0,
                            "usage_percent": 0
                        }]
                except Exception as e:
                    logger.error(f"Error parsing disk information: {e}")
                    result["disk"] = [{
                        "device": "Unknown",
                        "total_bytes": 0,
                        "free_bytes": 0,
                        "used_bytes": 0,
                        "usage_percent": 0
                    }]
            else:
                result["disk"] = [{
                    "device": "Unknown",
                    "total_bytes": 0,
                    "free_bytes": 0,
                    "used_bytes": 0,
                    "usage_percent": 0
                }]
                logger.error("No disk data returned from Windows device")
            
            logger.info(f"Windows performance metrics retrieval complete")
            return result
        except Exception as e:
            logger.error(f"Error in Windows performance metrics: {e}")
            return {
                "cpu": {"usage_percent": 0},
                "memory": {
                    "total_bytes": 0,
                    "free_bytes": 0,
                    "used_bytes": 0,
                    "usage_percent": 0
                },
                "disk": [{
                    "device": "Error",
                    "total_bytes": 0,
                    "free_bytes": 0,
                    "used_bytes": 0,
                    "usage_percent": 0
                }]
            }
    
    def get_performance_metrics(self, device_id, metrics=None):
        """
        Get performance metrics from a remote device with comprehensive error handling
        """
        if device_id not in self.devices:
            return None
            
        device = self.devices[device_id]
        is_windows = "windows" in device.get("platform", "").lower()
        
        # Log platform info for debugging
        try:
            os_info = self.execute_command(device_id, "uname -a" if not is_windows else "ver")
            logger.info(f"Device {device_id} OS: {os_info}")
        except Exception:
            pass

        # For Windows systems, use the specialized Windows metrics method
        if is_windows:
            return self.get_windows_performance_metrics(device_id)
        
        # For Linux/Unix systems, continue with the existing implementation
        try:
            if not metrics:
                metrics = ["cpu", "memory", "disk", "network"]
            
            result = {}
            
            for metric in metrics:
                # CPU metrics
                if metric == "cpu":
                    try:
                        cpu_data = self.execute_command(device_id, "top -bn1 | grep '%Cpu(s)'")
                        
                        if cpu_data:
                            match = re.search(r'(\d+\.\d+)\s+id', cpu_data)
                            if match:
                                idle = float(match.group(1))
                                usage = 100.0 - idle
                                result["cpu"] = {
                                    "usage_percent": usage
                                }
                            else:
                                # Default data if pattern not found
                                result["cpu"] = {"usage_percent": 0}
                        else:
                            # Default data if command failed
                            result["cpu"] = {"usage_percent": 0}
                    except Exception as e:
                        logger.error(f"Error getting CPU metrics: {e}")
                        result["cpu"] = {"usage_percent": 0}
                
                # Memory metrics
                elif metric == "memory":
                    try:
                        # First try /proc/meminfo which is more reliable
                        try:
                            memory_data = self.execute_command(device_id, "cat /proc/meminfo")
                            
                            if memory_data:
                                # Parse /proc/meminfo
                                mem_total = 0
                                mem_free = 0
                                mem_available = 0
                                
                                for line in memory_data.strip().split('\n'):
                                    if "MemTotal:" in line:
                                        parts = line.split()
                                        if len(parts) >= 2:
                                            try:
                                                mem_total = int(parts[1]) * 1024  # Convert KB to bytes
                                            except ValueError:
                                                pass
                                    elif "MemFree:" in line:
                                        parts = line.split()
                                        if len(parts) >= 2:
                                            try:
                                                mem_free = int(parts[1]) * 1024  # Convert KB to bytes
                                            except ValueError:
                                                pass
                                    elif "MemAvailable:" in line:
                                        parts = line.split()
                                        if len(parts) >= 2:
                                            try:
                                                mem_available = int(parts[1]) * 1024  # Convert KB to bytes
                                            except ValueError:
                                                pass
                                
                                # If we got valid data
                                if mem_total > 0:
                                    mem_used = mem_total - (mem_available if mem_available > 0 else mem_free)
                                    usage_percent = (mem_used / mem_total) * 100 if mem_total > 0 else 0
                                    
                                    result["memory"] = {
                                        "total_bytes": mem_total,
                                        "free_bytes": mem_available if mem_available > 0 else mem_free,
                                        "used_bytes": mem_used,
                                        "usage_percent": round(usage_percent, 2)
                                    }
                                    continue  # Skip the fallback mechanisms
                        except Exception as e:
                            logger.error(f"Error getting memory from /proc/meminfo: {e}")
                            # Continue to fallback method
                        
                        # Fallback to free command if /proc/meminfo didn't work
                        try:
                            # Use MB format which is less likely to cause parsing errors
                            memory_data = self.execute_command(device_id, "free -m")
                            
                            if memory_data:
                                # Clean up the output - remove any problematic lines
                                clean_lines = []
                                for line in memory_data.strip().split('\n'):
                                    # Only keep lines that start with expected headers
                                    if any(line.lstrip().startswith(prefix) for prefix in ["Mem:", "total", "Swap:", "-"]):
                                        clean_lines.append(line)
                                
                                memory_data = '\n'.join(clean_lines)
                                
                                lines = memory_data.strip().split('\n')
                                if len(lines) >= 2:
                                    # Look for line starting with "Mem:"
                                    for line in lines:
                                        if line.strip().startswith("Mem:"):
                                            mem_line = line.split()
                                            if len(mem_line) >= 4:
                                                try:
                                                    # Parse values in MB
                                                    total = int(mem_line[1]) * 1024 * 1024  # Convert MB to bytes
                                                    used = int(mem_line[2]) * 1024 * 1024
                                                    free = int(mem_line[3]) * 1024 * 1024
                                                    usage_percent = (used / total) * 100 if total > 0 else 0
                                                    
                                                    result["memory"] = {
                                                        "total_bytes": total,
                                                        "free_bytes": free,
                                                        "used_bytes": used,
                                                        "usage_percent": round(usage_percent, 2)
                                                    }
                                                    continue  # Skip to next metric
                                                except (ValueError, IndexError) as ve:
                                                    logger.error(f"Error parsing memory values: {ve}")
                                                    # Continue to default fallback
                        except Exception as e:
                            logger.error(f"Error getting memory from free -m: {e}")
                        
                        # If all approaches failed, provide default data
                        if "memory" not in result:
                            result["memory"] = {
                                "total_bytes": 0,
                                "free_bytes": 0,
                                "used_bytes": 0,
                                "usage_percent": 0
                            }
                    except Exception as e:
                        logger.error(f"Error getting memory metrics: {e}")
                        # Provide empty but valid memory structure
                        result["memory"] = {
                            "total_bytes": 0,
                            "free_bytes": 0,
                            "used_bytes": 0,
                            "usage_percent": 0
                        }
                
                # Disk metrics
                elif metric == "disk":
                    try:
                        # Use human-readable format for parsing
                        disk_data = self.execute_command(device_id, "df -h")
                        
                        if disk_data:
                            lines = disk_data.strip().split('\n')
                            disks = []
                            
                            for line in lines[1:]:  # Skip header
                                parts = line.split()
                                if len(parts) >= 5:
                                    try:
                                        device = parts[0]
                                        usage_percent_str = parts[4].rstrip('%')
                                        usage_percent = float(usage_percent_str)
                                        
                                        disks.append({
                                            "device": device,
                                            "total_bytes": 0,  # We don't parse exact bytes here
                                            "free_bytes": 0,
                                            "used_bytes": 0,
                                            "usage_percent": usage_percent
                                        })
                                    except (ValueError, IndexError):
                                        # Skip this entry on error
                                        continue
                            
                            if disks:
                                result["disk"] = disks
                            else:
                                # Default data if no valid disks found
                                result["disk"] = [{
                                    "device": "Unknown",
                                    "total_bytes": 0,
                                    "free_bytes": 0,
                                    "used_bytes": 0,
                                    "usage_percent": 0
                                }]
                        else:
                            # Default data if command failed
                            result["disk"] = [{
                                "device": "Unknown",
                                "total_bytes": 0,
                                "free_bytes": 0,
                                "used_bytes": 0,
                                "usage_percent": 0
                            }]
                    except Exception as e:
                        logger.error(f"Error getting disk metrics: {e}")
                        # Default disk data structure
                        result["disk"] = [{
                            "device": "Error",
                            "total_bytes": 0,
                            "free_bytes": 0,
                            "used_bytes": 0,
                            "usage_percent": 0
                        }]
            
            return result
            
        except Exception as e:
            logger.error(f"Error getting performance metrics: {str(e)}")
            # Return partial result even if overall error occurred
            return result
            
    # === SNMP Management ===
    
    def snmp_get(self, device_id, oid, community="public", version="2c"):
        """Perform SNMP GET operation"""
        if device_id not in self.devices:
            return None
            
        device = self.devices[device_id]
        is_windows = "windows" in device.get("platform", "").lower()
        
        try:
            if is_windows:
                ps_command = f'powershell "& snmpget.exe -v {version} -c {community} {device["ip"]} {oid}"'
                result = self.execute_command(device_id, ps_command)
            else:
                result = self.execute_command(device_id, f"snmpget -v {version} -c {community} {device['ip']} {oid}")
            
            if not result:
                return None
            
            # Parse SNMP output - extract value after OID
            match = re.search(r'{0}\s*=\s*(.+)'.format(re.escape(oid)), result)
            if match:
                return match.group(1).strip()
            
            return result  # Return raw result if parsing fails
            
        except Exception as e:
            logger.error(f"Error during SNMP GET: {str(e)}")
            return None

    # === XML Operations ===
    
    def parse_xml_file(self, device_id, file_path):
        """Parse XML file on remote device"""
        if device_id not in self.devices:
            return None
            
        # Download to temp location
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.xml')
        temp_file_path = temp_file.name
        temp_file.close()
        
        try:
            if not self.download_file(device_id, file_path, temp_file_path):
                logger.error(f"Failed to download XML file {file_path}")
                return None
            
            # Parse XML
            try:
                tree = ET.parse(temp_file_path)
                root = tree.getroot()
                
                # Convert XML to dictionary
                def xml_to_dict(element):
                    result = {}
                    
                    if element.attrib:
                        result["@attributes"] = element.attrib
                    
                    if len(element) == 0:
                        if element.text and element.text.strip():
                            return element.text
                    
                    for child in element:
                        child_data = xml_to_dict(child)
                        
                        if child.tag in result:
                            if not isinstance(result[child.tag], list):
                                result[child.tag] = [result[child.tag]]
                            result[child.tag].append(child_data)
                        else:
                            result[child.tag] = child_data
                    
                    return result
                
                return {root.tag: xml_to_dict(root)}
                
            except Exception as e:
                logger.error(f"Error parsing XML file: {str(e)}")
                return None
                
        finally:
            if os.path.exists(temp_file_path):
                os.unlink(temp_file_path)
    
    # === Remote SSH Management ===
    
    def execute_ssh_command(self, device_id, command, username, password=None, key_file=None):
        """Execute command over SSH on remote device"""
        if device_id not in self.devices:
            return None
            
        device = self.devices[device_id]
        
        try:
            # Construct SSH command
            ssh_command = f"ssh -o StrictHostKeyChecking=no "
            
            if key_file:
                ssh_command += f"-i {key_file} "
            
            ssh_command += f"{username}@{device['ip']} \"{command}\""
            
            if password and not key_file:
                ssh_command = f"sshpass -p '{password}' {ssh_command}"
            
            # Execute command through agent
            return self.execute_command(device_id, ssh_command)
            
        except Exception as e:
            logger.error(f"Error executing SSH command: {str(e)}")
            return None