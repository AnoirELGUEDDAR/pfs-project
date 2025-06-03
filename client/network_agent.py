#!/usr/bin/env python3
"""
Agent réseau pour Network Scanner
Permet le contrôle à distance de cette machine
"""

import os
import sys
import socket
import json
import subprocess
import threading
import platform
import time
import logging
import uuid
import shutil
import argparse
import base64
from datetime import datetime

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='network_agent.log'
)

# Version de l'agent
VERSION = "1.0.0"

# Configuration par défaut
DEFAULT_PORT = 9877
DEFAULT_TOKEN = "change_this_token_immediately"  # À changer lors de l'installation

class NetworkAgent:
    """Agent pour la gestion à distance"""
    
    def __init__(self, port=DEFAULT_PORT, token=DEFAULT_TOKEN):
        self.port = port
        self.token = token
        self.running = False
        self.socket = None
        self.connections = []
        
    def start(self):
        """Démarrer l'agent"""
        self.running = True
        
        # Créer le socket serveur
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(('0.0.0.0', self.port))
            self.socket.listen(5)
            logging.info(f"Agent démarré sur le port {self.port}")
            print(f"Agent démarré sur le port {self.port}")
            
            # Accepter les connexions entrantes
            while self.running:
                try:
                    client_socket, address = self.socket.accept()
                    logging.info(f"Connexion acceptée de {address[0]}:{address[1]}")
                    print(f"Connexion acceptée de {address[0]}:{address[1]}")
                    
                    # Gérer la connexion dans un thread séparé
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, address),
                        daemon=True
                    )
                    client_thread.start()
                    self.connections.append(client_thread)
                    
                except Exception as e:
                    if self.running:
                        logging.error(f"Erreur lors de l'acceptation d'une connexion: {e}")
                        print(f"Erreur lors de l'acceptation d'une connexion: {e}")
                    break
                    
        except Exception as e:
            logging.error(f"Erreur lors du démarrage de l'agent: {e}")
            print(f"Erreur lors du démarrage de l'agent: {e}")
            return False
            
        finally:
            if self.socket:
                self.socket.close()
                
        return True
        
    def stop(self):
        """Arrêter l'agent"""
        self.running = False
        
        # Fermer le socket principal
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
                
        logging.info("Agent arrêté")
        print("Agent arrêté")
        
    def _handle_client(self, client_socket, address):
        """Gérer une connexion client"""
        try:
            # Recevoir les données avec une meilleure gestion pour les fichiers volumineux
            data = b""
            client_socket.settimeout(5)  # Timeout initial
            
            # Première lecture
            chunk = client_socket.recv(8192)  # Buffer plus grand
            if not chunk:
                return
                
            data += chunk
            
            # Si le message est potentiellement plus grand (fichier)
            if len(chunk) >= 8190 or (b'"command": "upload_file"' in chunk):
                print(f"Message volumineux détecté, utilisation du mode de réception étendu")
                client_socket.settimeout(30)  # Timeout plus long pour les fichiers
                
                # Continuez à lire jusqu'à ce que vous obteniez une fin de JSON ou un timeout
                while True:
                    try:
                        chunk = client_socket.recv(16384)  # Encore plus grand
                        if not chunk:
                            break
                        data += chunk
                        # Essayez de détecter la fin du message JSON (un peu simpliste mais efficace)
                        if chunk.endswith(b'"}}') or chunk.endswith(b'}}'):
                            print(f"Fin probable du message JSON détectée")
                            break
                    except socket.timeout:
                        print("Timeout lors de la réception - considéré comme fin de données")
                        break
                        
            print(f"Message reçu, longueur totale: {len(data)} octets")
            
            # Décoder le message JSON
            try:
                message = json.loads(data.decode('utf-8'))
            except json.JSONDecodeError as e:
                logging.warning(f"Message invalide reçu de {address[0]}: {e}")
                print(f"ERREUR JSON: {e}, Première partie des données: {data[:100]}...")
                self._send_response(client_socket, {"status": "error", "message": "Format de message invalide"})
                return
                
            # Vérifier le token d'authentification
            if message.get("auth_token") != self.token:
                logging.warning(f"Tentative d'accès non autorisée depuis {address[0]}")
                self._send_response(client_socket, {"status": "error", "message": "Token d'authentification invalide"})
                return
                
            # Traiter la commande
            command = message.get("command", "")
            params = message.get("params", {})
            
            logging.info(f"Commande reçue: {command}")
            print(f"Commande reçue: {command}")
            
            # Exécuter la commande
            if command == "ping":
                response = {"status": "success", "message": "pong", "agent_version": VERSION}
                
            elif command == "system_info":
                response = {"status": "success", "data": self._get_system_info()}
                
            elif command == "execute":
                cmd = params.get("cmd", "")
                if not cmd:
                    response = {"status": "error", "message": "Commande manquante"}
                else:
                    output = self._execute_command(cmd)
                    response = {"status": "success", "data": {"output": output}}
                    
            elif command == "shutdown":
                delay = params.get("delay", 0)
                self._send_response(client_socket, {"status": "success", "message": f"Arrêt programmé dans {delay} secondes"})
                client_socket.close()
                threading.Thread(target=self._shutdown_system, args=(delay,), daemon=True).start()
                return
                
            elif command == "restart":
                delay = params.get("delay", 0)
                self._send_response(client_socket, {"status": "success", "message": f"Redémarrage programmé dans {delay} secondes"})
                client_socket.close()
                threading.Thread(target=self._restart_system, args=(delay,), daemon=True).start()
                return
                
            elif command == "upload_file":
                file_name = params.get("file_name", "")
                directory = params.get("directory", "")
                content_encoded = params.get("content", "")
                encoding = params.get("encoding", "hex")  # Par défaut: hex pour compatibilité
                
                if not file_name or not directory or not content_encoded:
                    response = {"status": "error", "message": "Paramètres de fichier manquants"}
                else:
                    # Décoder le contenu selon l'encodage
                    try:
                        if encoding == "base64":
                            content = base64.b64decode(content_encoded)
                        else:  # Par défaut: hex
                            content = bytes.fromhex(content_encoded)
                            
                        success = self._save_file(directory, file_name, content)
                        if success:
                            response = {"status": "success", "message": "Fichier sauvegardé"}
                        else:
                            response = {"status": "error", "message": "Erreur lors de l'enregistrement du fichier"}
                    except Exception as e:
                        print(f"Erreur lors du traitement du fichier: {e}")
                        import traceback
                        traceback.print_exc()
                        response = {"status": "error", "message": f"Erreur de décodage: {str(e)}"}
                        
            else:
                response = {"status": "error", "message": f"Commande inconnue: {command}"}
                
            # Envoyer la réponse
            self._send_response(client_socket, response)
            
        except Exception as e:
            logging.error(f"Erreur lors du traitement de la connexion: {e}")
            print(f"Erreur de traitement: {e}")
            import traceback
            traceback.print_exc()
            try:
                self._send_response(client_socket, {"status": "error", "message": f"Erreur interne: {str(e)}"})
            except:
                pass
                
        finally:
            try:
                client_socket.close()
            except:
                pass
                
    def _send_response(self, client_socket, response):
        """Envoyer une réponse au client"""
        try:
            response_data = json.dumps(response).encode('utf-8')
            client_socket.sendall(response_data)
        except Exception as e:
            logging.error(f"Erreur lors de l'envoi de la réponse: {e}")
            
    def _get_system_info(self):
        """Récupérer les informations système"""
        info = {
            "hostname": socket.gethostname(),
            "platform": platform.system(),
            "platform_version": platform.version(),
            "architecture": platform.architecture()[0],
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        try:
            # Informations CPU
            if platform.system() == "Windows":
                import winreg
                registry = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
                key = winreg.OpenKey(registry, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0")
                info["cpu_name"] = winreg.QueryValueEx(key, "ProcessorNameString")[0]
                winreg.CloseKey(key)
            elif platform.system() == "Linux":
                with open("/proc/cpuinfo", "r") as f:
                    for line in f:
                        if "model name" in line:
                            info["cpu_name"] = line.split(":")[1].strip()
                            break
            elif platform.system() == "Darwin":  # macOS
                info["cpu_name"] = subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"]).decode().strip()
        except:
            info["cpu_name"] = "Inconnu"
            
        try:
            # Informations mémoire
            if platform.system() == "Windows":
                import ctypes
                kernel32 = ctypes.windll.kernel32
                c_ulonglong = ctypes.c_ulonglong
                class MEMORYSTATUSEX(ctypes.Structure):
                    _fields_ = [
                        ("dwLength", ctypes.c_ulong),
                        ("dwMemoryLoad", ctypes.c_ulong),
                        ("ullTotalPhys", c_ulonglong),
                        ("ullAvailPhys", c_ulonglong),
                        ("ullTotalPageFile", c_ulonglong),
                        ("ullAvailPageFile", c_ulonglong),
                        ("ullTotalVirtual", c_ulonglong),
                        ("ullAvailVirtual", c_ulonglong),
                        ("ullAvailExtendedVirtual", c_ulonglong),
                    ]
                    
                stat = MEMORYSTATUSEX()
                stat.dwLength = ctypes.sizeof(stat)
                kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
                info["total_memory_mb"] = int(stat.ullTotalPhys / (1024 * 1024))
                
            elif platform.system() == "Linux":
                with open("/proc/meminfo", "r") as f:
                    for line in f:
                        if "MemTotal" in line:
                            info["total_memory_mb"] = int(int(line.split()[1]) / 1024)
                            break
                            
            elif platform.system() == "Darwin":  # macOS
                info["total_memory"] = subprocess.check_output(["sysctl", "-n", "hw.memsize"]).decode().strip()
        except:
            info["total_memory"] = "Inconnu"
            
        try:
            # Informations disques
            info["disks"] = []
            
            if platform.system() == "Windows":
                import ctypes
                drives = []
                bitmask = ctypes.windll.kernel32.GetLogicalDrives()
                for letter in range(65, 91):
                    if bitmask & 1:
                        drives.append(chr(letter))
                    bitmask >>= 1
                    
                for drive in drives:
                    try:
                        drive_path = f"{drive}:\\"
                        total, used, free = shutil.disk_usage(drive_path)
                        info["disks"].append({
                            "drive": drive_path,
                            "size_gb": round(total / (1024 * 1024 * 1024), 2),
                            "free_gb": round(free / (1024 * 1024 * 1024), 2),
                        })
                    except:
                        pass
                        
            elif platform.system() == "Linux" or platform.system() == "Darwin":
                df = subprocess.check_output(["df", "-h"]).decode().strip().split('\n')
                for i in range(1, len(df)):
                    parts = df[i].split()
                    if len(parts) >= 6:
                        mount = parts[5]
                        if mount == "/" or mount.startswith("/home"):
                            info["disks"].append({
                                "drive": mount,
                                "size": parts[1],
                                "used": parts[2],
                                "free": parts[3],
                            })
        except:
            pass
            
        return info
        
    def _execute_command(self, command):
        """Exécuter une commande système"""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(["cmd", "/c", command], capture_output=True, text=True)
                return result.stdout + result.stderr
            else:
                result = subprocess.run(["bash", "-c", command], capture_output=True, text=True)
                return result.stdout + result.stderr
        except Exception as e:
            return f"Erreur lors de l'exécution de la commande: {str(e)}"
            
    def _shutdown_system(self, delay=0):
        """Arrêter le système"""
        try:
            time.sleep(delay)
            if platform.system() == "Windows":
                os.system(f"shutdown /s /t 0")
            else:
                os.system("sudo shutdown -h now")
        except Exception as e:
            logging.error(f"Erreur lors de l'arrêt du système: {e}")
            
    def _restart_system(self, delay=0):
        """Redémarrer le système"""
        try:
            time.sleep(delay)
            if platform.system() == "Windows":
                os.system(f"shutdown /r /t 0")
            else:
                os.system("sudo reboot")
        except Exception as e:
            logging.error(f"Erreur lors du redémarrage du système: {e}")
            
    def _save_file(self, directory, filename, content):
        """Sauvegarder un fichier"""
        try:
            print(f">>> Tentative d'enregistrement du fichier {filename} dans {directory}")
            print(f">>> Taille du contenu: {len(content)} octets")
            
            # S'assurer que le répertoire existe
            try:
                os.makedirs(directory, exist_ok=True)
                print(f">>> Dossier {directory} pret")
            except Exception as e:
                print(f">>> ERREUR: Creation du dossier {directory} impossible: {e}")
                return False
            
            # Chemin complet du fichier
            file_path = os.path.join(directory, filename)
            print(f">>> Chemin complet du fichier: {file_path}")
            
            # Écrire le contenu
            with open(file_path, 'wb') as f:
                f.write(content)
                
            # Vérifier que le fichier a bien été créé
            if os.path.exists(file_path):
                file_size = os.path.getsize(file_path)
                print(f">>> Fichier sauvegarde avec succes: {file_path} ({file_size} octets)")
                logging.info(f"Fichier sauvegarde: {file_path} ({file_size} octets)")
                return True
            else:
                print(f">>> ERREUR: Le fichier n'a pas ete cree, mais aucune exception levee")
                return False
                
        except Exception as e:
            print(f">>> ERREUR lors de la sauvegarde: {str(e)}")
            import traceback
            traceback.print_exc()
            logging.error(f"Erreur lors de la sauvegarde du fichier: {e}")
            return False

def run_as_service():
    """Exécuter l'agent en tant que service"""
    import servicemanager
    import win32service
    import win32serviceutil
    
    class NetworkAgentService(win32serviceutil.ServiceFramework):
        _svc_name_ = "NetworkAgent"
        _svc_display_name_ = "Network Scanner Agent"
        _svc_description_ = "Agent réseau pour Network Scanner"
        
        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self.stop_event = threading.Event()
            self.agent = None
            
        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            if self.agent:
                self.agent.stop()
            self.stop_event.set()
            
        def SvcDoRun(self):
            self.ReportServiceStatus(win32service.SERVICE_RUNNING)
            self.agent = NetworkAgent()
            self.agent.start()
            
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(NetworkAgentService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(NetworkAgentService)

def main():
    """Point d'entrée principal"""
    parser = argparse.ArgumentParser(description='Agent réseau pour Network Scanner')
    parser.add_argument('-p', '--port', type=int, default=DEFAULT_PORT, help='Port d\'écoute')
    parser.add_argument('-t', '--token', type=str, default=DEFAULT_TOKEN, help='Token d\'authentification')
    parser.add_argument('-s', '--service', action='store_true', help='Installer en tant que service Windows')
    
    args = parser.parse_args()
    
    if args.service and platform.system() == "Windows":
        try:
            import win32serviceutil
            run_as_service()
        except ImportError:
            print("Bibliothèque pywin32 requise pour l'installation en tant que service")
            print("Installez-la avec: pip install pywin32")
            return
    else:
        agent = NetworkAgent(port=args.port, token=args.token)
        try:
            agent.start()
        except KeyboardInterrupt:
            print("Arrêt de l'agent...")
            agent.stop()

if __name__ == "__main__":
    main()