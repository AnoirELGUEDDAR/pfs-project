#!/usr/bin/env python3
"""
Relais minimaliste - Version ultra-simplifiée pour votre serveur
Auteur: AnoirELGUEDDAR
Date: 2025-06-10 02:18:55
"""
import sys
import socket
import json
import time
import threading

def send_message(ip, text):
    """Envoyer un message à l'IP spécifiée sur le port 9878"""
    print(f"\n[RELAIS] Message détecté pour {ip}: {text}")
    
    try:
        # Créer le socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        print(f"[RELAIS] Connexion à {ip}:9878...")
        
        # Connexion
        sock.connect((ip, 9878))
        print(f"[RELAIS] Connecté!")
        
        # Préparer le message
        data = {
            "auth_token": "change_this_token_immediately",
            "command": "message",
            "params": {
                "type": "send",
                "text": text,
                "sender": "Serveur",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }
        }
        
        # Envoyer
        sock.sendall(json.dumps(data).encode('utf-8'))
        print(f"[RELAIS] Message envoyé!")
        
        # Attendre la réponse
        try:
            sock.settimeout(2)
            response = sock.recv(4096)
            print(f"[RELAIS] Réponse reçue: {response.decode('utf-8')}")
        except socket.timeout:
            print(f"[RELAIS] Pas de réponse, mais le message a été envoyé")
        except Exception as e:
            print(f"[RELAIS] Erreur lors de la réception de la réponse: {e}")
            
        # Fermer
        sock.close()
        print(f"[RELAIS] Connexion fermée")
        
    except Exception as e:
        print(f"[RELAIS] ERREUR: {e}")

# Boucle principale qui lit ligne par ligne
print("[RELAIS] Démarrage du relais minimaliste")
print("[RELAIS] En attente des messages dans la sortie console...")

for line in sys.stdin:
    # Afficher la ligne originale (pour le debugging)
    print(line, end='', flush=True)
    
    # Détection simplifiée avec juste une condition "if"
    if "INFO: Message sent to " in line and not "broadcast" in line:
        # Extraction directe avec split
        parts = line.split("INFO: Message sent to ")
        if len(parts) > 1:
            ip_and_msg = parts[1].strip()
            ip_parts = ip_and_msg.split(":", 1)
            if len(ip_parts) > 1:
                ip = ip_parts[0].strip()
                message = ip_parts[1].strip()
                
                # Enlever les points de suspension à la fin
                if message.endswith("..."):
                    message = message[:-3]
                
                # Envoyer le message dans un thread séparé
                threading.Thread(
                    target=send_message,
                    args=(ip, message),
                    daemon=True
                ).start()