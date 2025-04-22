"""
Device Manager for Remote Management
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

logger = logging.getLogger(__name__)

class DeviceManager:
    """Gestion des appareils distants via l'agent réseau"""
    
    CONFIG_FILE = "remote_devices.json"
    
    def __init__(self):
        """Initialiser le gestionnaire d'appareils"""
        self.devices = {}
        self.load_devices()
        
        # Démarrer un thread de vérification périodique
        self._running = True
        self._check_thread = threading.Thread(target=self._periodic_check, daemon=True)
        self._check_thread.start()
        
    def _periodic_check(self):
        """Vérifier périodiquement le statut des appareils"""
        while self._running:
            # Attendre 5 minutes
            time.sleep(300)
            
            try:
                # Ping chaque appareil
                devices_copy = self.devices.copy()
                for device_id in devices_copy:
                    self.ping_device(device_id)
            except Exception as e:
                logger.error(f"Erreur lors de la vérification périodique: {e}")
    
    def save_devices(self):
        """Sauvegarder les appareils dans le fichier de configuration"""
        try:
            with open(self.CONFIG_FILE, 'w') as f:
                json.dump(self.devices, f, indent=4)
            return True
        except Exception as e:
            logger.error(f"Erreur lors de la sauvegarde des appareils: {e}")
            return False
            
    def load_devices(self):
        """Charger les appareils depuis le fichier de configuration"""
        if os.path.exists(self.CONFIG_FILE):
            try:
                with open(self.CONFIG_FILE, 'r') as f:
                    self.devices = json.load(f)
                return True
            except Exception as e:
                logger.error(f"Erreur lors du chargement des appareils: {e}")
                return False
        return True
    
    def add_device(self, name, ip, port, token):
        """Ajouter un nouvel appareil"""
        device_id = f"{ip}:{port}"
        
        # Si l'appareil existe déjà, mettre à jour ses informations
        if device_id in self.devices:
            self.devices[device_id].update({
                "name": name,
                "token": token
            })
        else:
            # Sinon, créer une nouvelle entrée
            self.devices[device_id] = {
                "name": name,
                "ip": ip,
                "port": port,
                "token": token,
                "status": "unknown",
                "last_connected": ""
            }
        
        # Tenter de ping l'appareil pour vérifier la connexion
        success = self.ping_device(device_id)
        
        # Sauvegarder les modifications
        self.save_devices()
        
        return success
    
    def remove_device(self, device_id):
        """Supprimer un appareil"""
        if device_id in self.devices:
            del self.devices[device_id]
            self.save_devices()
            return True
        return False
    
    def get_devices(self):
        """Récupérer la liste des appareils"""
        return self.devices
    
    def ping_device(self, device_id):
        """Version simplifiée pour vérifier si un appareil est en ligne"""
        if device_id not in self.devices:
            logger.warning(f"Appareil {device_id} introuvable")
            return False
        
        device = self.devices[device_id]
        ip = device["ip"]
        port = device["port"]
        token = device["token"]
        
        print(f"Test de connexion direct à {ip}:{port}")
        
        try:
            # Méthode 1: Vérifier si le port est ouvert
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)  # Timeout plus long
            result = sock.connect_ex((ip, port))
            
            if result == 0:
                # Port ouvert, essayer d'envoyer un ping à l'agent
                try:
                    # Préparer le message JSON
                    message = {
                        "auth_token": token,
                        "command": "ping"
                    }
                    
                    # Envoyer et recevoir
                    sock.sendall(json.dumps(message).encode('utf-8'))
                    
                    # Attendre la réponse avec un timeout
                    sock.settimeout(5)
                    response_data = sock.recv(1024)
                    
                    if response_data:
                        try:
                            response = json.loads(response_data.decode('utf-8'))
                            if response.get("status") == "success":
                                # Mise à jour du statut
                                self.devices[device_id]["status"] = "online"
                                self.devices[device_id]["last_connected"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                self.save_devices()
                                print(f"Appareil {ip}:{port} en ligne (réponse ping)")
                                sock.close()
                                return True
                        except json.JSONDecodeError:
                            print(f"Réponse invalide de {ip}:{port}: {response_data}")
                except Exception as e:
                    print(f"Erreur lors du ping de l'agent: {e}")
                
                # Si on arrive ici, la connexion TCP a réussi mais pas le protocole
                # On considère l'appareil comme en ligne quand même
                self.devices[device_id]["status"] = "online"
                self.devices[device_id]["last_connected"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.save_devices()
                print(f"Appareil {ip}:{port} en ligne (port ouvert uniquement)")
                sock.close()
                return True
            else:
                # Port fermé
                print(f"Port {port} fermé sur {ip}, code erreur: {result}")
                self.devices[device_id]["status"] = "offline"
                self.save_devices()
                sock.close()
                return False
                
        except Exception as e:
            print(f"Erreur lors du test de connexion à {ip}:{port}: {str(e)}")
            self.devices[device_id]["status"] = "offline"
            self.save_devices()
            return False
    
    def get_system_info(self, device_id):
        """Récupérer les informations système d'un appareil distant"""
        if device_id not in self.devices:
            return None
        
        device = self.devices[device_id]
        
        try:
            # Créer la socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)  # Plus long pour laisser le temps de collecter les infos
            sock.connect((device["ip"], device["port"]))
            
            # Envoyer la commande
            message = {
                "auth_token": device["token"],
                "command": "system_info"
            }
            sock.sendall(json.dumps(message).encode('utf-8'))
            
            # Recevoir la réponse
            response_data = b""
            start_time = time.time()
            while time.time() - start_time < 10:  # Timeout de 10 secondes
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response_data += chunk
                    # Si la réponse se termine par un accolade, c'est probablement la fin du JSON
                    if chunk.endswith(b'}'):
                        break
                except socket.timeout:
                    break
            
            sock.close()
            
            # Analyser la réponse
            if response_data:
                try:
                    response = json.loads(response_data.decode('utf-8'))
                    if response.get("status") == "success":
                        return response.get("data", {})
                except json.JSONDecodeError as e:
                    logger.error(f"Erreur JSON: {e}, Data: {response_data[:100]}...")
            
            return None
            
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des infos système: {str(e)}")
            traceback.print_exc()
            return None
    
    def execute_command(self, device_id, command):
        """Exécuter une commande sur un appareil distant"""
        if device_id not in self.devices:
            return None
        
        device = self.devices[device_id]
        
        try:
            # Créer la socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)  # Plus long pour les commandes
            sock.connect((device["ip"], device["port"]))
            
            # Envoyer la commande
            message = {
                "auth_token": device["token"],
                "command": "execute",
                "params": {
                    "cmd": command
                }
            }
            sock.sendall(json.dumps(message).encode('utf-8'))
            
            # Recevoir la réponse
            response_data = b""
            start_time = time.time()
            while time.time() - start_time < 30:  # Timeout de 30 secondes
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response_data += chunk
                    # Si la réponse se termine par un accolade, c'est probablement la fin du JSON
                    if chunk.endswith(b'}'):
                        break
                except socket.timeout:
                    break
            
            sock.close()
            
            # Analyser la réponse
            if response_data:
                try:
                    response = json.loads(response_data.decode('utf-8'))
                    if response.get("status") == "success":
                        return response.get("data", {}).get("output", "")
                except json.JSONDecodeError:
                    pass
            
            return None
            
        except Exception as e:
            logger.error(f"Erreur lors de l'exécution de la commande: {str(e)}")
            return None
    
    def send_file(self, device_id, local_file_path, remote_directory):
        """Envoyer un fichier à un appareil distant"""
        if device_id not in self.devices:
            logger.error(f"Appareil {device_id} inconnu")
            return False
        
        device = self.devices[device_id]
        
        try:
            # Vérifier que le fichier existe
            if not os.path.isfile(local_file_path):
                logger.error(f"Le fichier {local_file_path} n'existe pas")
                return False
            
            # Lire le contenu du fichier
            with open(local_file_path, 'rb') as f:
                file_content = f.read()
            
            # Obtenir le nom du fichier
            file_name = os.path.basename(local_file_path)
            
            # Informations de débogage
            file_size = len(file_content)
            if file_size > 1024*1024:
                logger.warning(f"Fichier volumineux: {file_size} octets. Risque d'échec.")
            logger.info(f"Envoi du fichier {file_name} à {device_id}, taille: {file_size} octets")
            
            # Utiliser base64 au lieu de hex
            content_b64 = base64.b64encode(file_content).decode('ascii')
            
            # Créer la socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(60)  # Plus long pour les transferts de fichiers
            
            try:
                sock.connect((device["ip"], device["port"]))
            except socket.error as e:
                logger.error(f"Erreur de socket lors de la connexion à {device_id}: {str(e)}")
                sock.close()
                return False
            
            # Envoyer la commande
            try:
                message = {
                    "auth_token": device["token"],
                    "command": "upload_file",
                    "params": {
                        "file_name": file_name,
                        "directory": remote_directory,
                        "encoding": "base64",  # Indiquer l'encodage utilisé
                        "content": content_b64
                    }
                }
                
                # Sérialiser et envoyer
                json_data = json.dumps(message).encode('utf-8')
                sock.sendall(json_data)
                logger.info(f"Données envoyées à {device_id}, taille JSON: {len(json_data)} octets")
                
            except Exception as e:
                logger.error(f"Erreur lors de l'envoi à {device_id}: {str(e)}")
                sock.close()
                return False
            
            # Recevoir la réponse
            try:
                response_data = b""
                sock.settimeout(60)
                try:
                    response_data = sock.recv(4096)
                except socket.timeout:
                    logger.error("Timeout en attendant la réponse")
                    sock.close()
                    return False
                
                sock.close()
                
                # Analyser la réponse
                if response_data:
                    try:
                        response = json.loads(response_data.decode('utf-8'))
                        success = response.get("status") == "success"
                        logger.info(f"Réponse reçue: {success}")
                        return success
                    except json.JSONDecodeError as e:
                        logger.error(f"Erreur JSON dans la réponse: {str(e)}")
                        return False
                else:
                    logger.error("Aucune réponse reçue")
                    return False
                    
            except Exception as e:
                logger.error(f"Erreur lors de la réception: {str(e)}")
                return False
                
        except Exception as e:
            logger.error(f"Erreur générale: {str(e)}")
            return False

    def shutdown_device(self, device_id, delay=0):
        """Arrêter un appareil distant"""
        if device_id not in self.devices:
            return False
        
        device = self.devices[device_id]
        
        try:
            # Créer la socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((device["ip"], device["port"]))
            
            # Envoyer la commande
            message = {
                "auth_token": device["token"],
                "command": "shutdown",
                "params": {
                    "delay": delay
                }
            }
            sock.sendall(json.dumps(message).encode('utf-8'))
            
            # Recevoir la réponse
            response_data = b""
            try:
                response_data = sock.recv(4096)
            except socket.timeout:
                pass
            
            sock.close()
            
            # Analyser la réponse
            if response_data:
                try:
                    response = json.loads(response_data.decode('utf-8'))
                    return response.get("status") == "success"
                except json.JSONDecodeError:
                    pass
            
            return False
            
        except Exception as e:
            logger.error(f"Erreur lors de l'arrêt de l'appareil: {str(e)}")
            return False
    
    def restart_device(self, device_id, delay=0):
        """Redémarrer un appareil distant"""
        if device_id not in self.devices:
            return False
        
        device = self.devices[device_id]
        
        try:
            # Créer la socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((device["ip"], device["port"]))
            
            # Envoyer la commande
            message = {
                "auth_token": device["token"],
                "command": "restart",
                "params": {
                    "delay": delay
                }
            }
            sock.sendall(json.dumps(message).encode('utf-8'))
            
            # Recevoir la réponse
            response_data = b""
            try:
                response_data = sock.recv(4096)
            except socket.timeout:
                pass
            
            sock.close()
            
            # Analyser la réponse
            if response_data:
                try:
                    response = json.loads(response_data.decode('utf-8'))
                    return response.get("status") == "success"
                except json.JSONDecodeError:
                    pass
            
            return False
            
        except Exception as e:
            logger.error(f"Erreur lors du redémarrage de l'appareil: {str(e)}")
            return False
    
    def wake_on_lan(self, mac_address, broadcast_ip=None):
        """Envoyer un paquet Wake-on-LAN"""
        try:
            # Formater l'adresse MAC
            mac = mac_address.replace(':', '').replace('-', '').replace('.', '')
            if len(mac) != 12:
                logger.error(f"Format d'adresse MAC invalide: {mac_address}")
                return False
            
            # Construire le paquet "Magic Packet"
            mac_bytes = bytes.fromhex(mac)
            magic_packet = b'\xff' * 6 + mac_bytes * 16
            
            # Adresse de broadcast par défaut
            if not broadcast_ip:
                broadcast_ip = '255.255.255.255'
            
            # Envoyer le paquet
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.sendto(magic_packet, (broadcast_ip, 9))
            sock.close()
            
            logger.info(f"Paquet Wake-on-LAN envoyé à {mac_address}")
            return True
            
        except Exception as e:
            logger.error(f"Erreur lors de l'envoi du paquet Wake-on-LAN: {str(e)}")
            return False
    
    def cleanup(self):
        """Nettoyer les ressources"""
        self._running = False
        if hasattr(self, '_check_thread'):
            self._check_thread.join(1)