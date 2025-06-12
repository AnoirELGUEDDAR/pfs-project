#!/usr/bin/env python3
"""
Script d'envoi de message au client Network Agent
Auteur: AnoirELGUEDDAR
Date: 2025-06-10
"""
import socket
import json
import time
import argparse
import sys

def send_message(host, port, token, text, sender="Serveur"):
    """Envoie un message à un agent distant"""
    print(f"Envoi d'un message à {host}:{port}...")
    
    try:
        # Créer une connexion socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((host, port))
        
        # Préparer le message
        message_data = {
            "auth_token": token,
            "command": "message",
            "params": {
                "type": "send",
                "text": text,
                "sender": sender,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }
        }
        
        # Envoyer le message
        sock.sendall(json.dumps(message_data).encode('utf-8'))
        
        # Recevoir la réponse
        response_data = sock.recv(4096)
        sock.close()
        
        # Analyser la réponse
        if response_data:
            response = json.loads(response_data.decode('utf-8'))
            if response.get("status") == "success":
                print(f"✅ Message envoyé avec succès!")
                print(f"ID du message: {response.get('data', {}).get('message_id', 'Inconnu')}")
                return True
            else:
                print(f"❌ Erreur: {response.get('message', 'Erreur inconnue')}")
        else:
            print("❌ Pas de réponse reçue.")
            
        return False
        
    except Exception as e:
        print(f"❌ Erreur de communication: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Envoi de message à un agent réseau")
    parser.add_argument("--host", default="192.168.100.24", help="Adresse IP de l'agent")
    parser.add_argument("--port", type=int, default=9877, help="Port de l'agent")
    parser.add_argument("--token", default="change_this_token_immediately", help="Token d'authentification")
    parser.add_argument("--sender", default="Serveur", help="Expéditeur du message")
    parser.add_argument("message", nargs="?", help="Message à envoyer")
    
    args = parser.parse_args()
    
    if not args.message:
        args.message = input("Entrez votre message: ")
    
    success = send_message(args.host, args.port, args.token, args.message, args.sender)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()