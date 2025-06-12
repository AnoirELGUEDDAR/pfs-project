#!/usr/bin/env python3
"""
Relais de Messages - Détecte automatiquement les messages dans la console et les transmet
Auteur: AnoirELGUEDDAR
Date: 2025-06-10 01:55:00
"""
import re
import socket
import json
import time
import threading
import subprocess
import argparse
import os
import sys
import logging
from datetime import datetime

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='message_relay.log'
)

# Expression régulière pour détecter les messages
MESSAGE_PATTERN = re.compile(r'INFO: Message sent to (\d+\.\d+\.\d+\.\d+): (.*?)(?:\.\.\.|\n|$)')

class MessageRelay:
    """Relais de messages automatique"""
    
    def __init__(self, client_port=9877, token="change_this_token_immediately"):
        self.client_port = client_port
        self.token = token
        self.running = False
        self.processed_messages = set()  # Pour éviter les doublons
    
    def start(self):
        """Démarrer le relais"""
        self.running = True
        print(f"Relais de messages démarré. Écoute sur le port {self.client_port}.")
        logging.info("Relais de messages démarré")
    
    def stop(self):
        """Arrêter le relais"""
        self.running = False
        logging.info("Relais de messages arrêté")
    
    def process_line(self, line):
        """Traiter une ligne pour y détecter un message"""
        match = MESSAGE_PATTERN.search(line)
        if match:
            ip = match.group(1)
            message = match.group(2)
            
            # Créer un identifiant unique pour ce message
            message_id = f"{ip}:{message}:{datetime.now().timestamp()}"
            
            # Vérifier si le message a déjà été traité (éviter les doublons)
            if message_id in self.processed_messages:
                return
            
            self.processed_messages.add(message_id)
            
            # Envoyer le message au client
            print(f"Message détecté: '{message}' pour {ip}")
            logging.info(f"Message détecté: '{message}' pour {ip}")
            
            # Envoyer dans un thread séparé pour ne pas bloquer
            threading.Thread(
                target=self.send_message,
                args=(ip, message),
                daemon=True
            ).start()
    
    def send_message(self, ip, message):
        """Envoyer un message au client"""
        try:
            # Créer une connexion socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            # Se connecter au client
            sock.connect((ip, self.client_port))
            
            # Préparer le message
            data = {
                "auth_token": self.token,
                "command": "message",
                "params": {
                    "type": "send",
                    "text": message,
                    "sender": "Serveur",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
            }
            
            # Envoyer le message
            sock.sendall(json.dumps(data).encode('utf-8'))
            
            # Recevoir la réponse (juste pour info, on ne traite pas)
            try:
                sock.settimeout(2)
                response = sock.recv(4096)
                if response:
                    response_data = json.loads(response.decode('utf-8'))
                    if response_data.get("status") == "success":
                        print(f"✅ Message envoyé avec succès à {ip}")
                        logging.info(f"Message envoyé avec succès à {ip}")
                    else:
                        print(f"⚠️ Message envoyé mais erreur: {response_data.get('message', 'Inconnue')}")
                        logging.warning(f"Message envoyé mais erreur: {response_data.get('message', 'Inconnue')}")
            except:
                # On ignore les timeouts/erreurs ici car on veut juste une communication one-way
                print(f"✅ Message envoyé à {ip} (pas de confirmation)")
                logging.info(f"Message envoyé à {ip} (pas de confirmation)")
            
            # Fermer la connexion
            sock.close()
            
        except Exception as e:
            print(f"❌ Erreur lors de l'envoi du message à {ip}: {e}")
            logging.error(f"Erreur lors de l'envoi du message à {ip}: {e}")
    
    def monitor_stdin(self):
        """Surveiller l'entrée standard"""
        while self.running:
            try:
                line = sys.stdin.readline()
                if not line:  # EOF
                    break
                self.process_line(line)
            except KeyboardInterrupt:
                break
            except Exception as e:
                logging.error(f"Erreur lors de la surveillance de stdin: {e}")
    
    def monitor_command_output(self, command):
        """Exécuter une commande et surveiller sa sortie"""
        try:
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True
            )
            
            for line in iter(process.stdout.readline, ''):
                print(line, end='')  # Afficher la sortie originale
                self.process_line(line)
                
                if not self.running:
                    break
            
            process.wait()
            
        except Exception as e:
            print(f"Erreur lors de l'exécution de la commande: {e}")
            logging.error(f"Erreur lors de l'exécution de la commande: {e}")
    
    def monitor_logfile(self, logfile):
        """Surveiller un fichier de log"""
        try:
            # Démarrer à la fin du fichier
            file_size = os.path.getsize(logfile) if os.path.exists(logfile) else 0
            
            while self.running:
                if os.path.exists(logfile):
                    current_size = os.path.getsize(logfile)
                    
                    if current_size > file_size:
                        with open(logfile, 'r') as f:
                            f.seek(file_size)
                            for line in f:
                                self.process_line(line)
                        file_size = current_size
                
                time.sleep(0.1)  # Petite pause pour économiser le CPU
                
        except Exception as e:
            print(f"Erreur lors de la surveillance du fichier de log: {e}")
            logging.error(f"Erreur lors de la surveillance du fichier de log: {e}")

def main():
    parser = argparse.ArgumentParser(description="Relais de messages automatique")
    parser.add_argument("--port", type=int, default=9877, help="Port des agents clients")
    parser.add_argument("--token", default="change_this_token_immediately", help="Token d'authentification")
    parser.add_argument("--logfile", help="Fichier de log à surveiller au lieu de stdin")
    parser.add_argument("--command", help="Commande à exécuter et surveiller")
    
    args = parser.parse_args()
    
    relay = MessageRelay(args.port, args.token)
    relay.start()
    
    try:
        if args.command:
            # Mode surveillance de commande
            relay.monitor_command_output(args.command)
        elif args.logfile:
            # Mode surveillance de fichier log
            relay.monitor_logfile(args.logfile)
        else:
            # Mode surveillance de stdin
            print("En attente des messages sur l'entrée standard (stdin)...")
            print("Tapez Ctrl+C pour arrêter.")
            relay.monitor_stdin()
    
    except KeyboardInterrupt:
        print("\nArrêt du relais...")
    finally:
        relay.stop()

if __name__ == "__main__":
    main()