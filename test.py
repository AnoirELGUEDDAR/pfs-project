# direct_tester.py - à exécuter sur le serveur Windows
import socket
import json
import argparse

def test_direct(ip, message, port=9878):
    """Teste la connexion directement avec l'agent distant"""
    print(f"Test de connexion directe vers {ip}:{port}")
    print(f"Message: {message}")
    
    try:
        # Créer socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        
        # Connexion
        print(f"Tentative de connexion à {ip}:{port}...")
        sock.connect((ip, port))
        print("✅ Connexion établie!")
        
        # Créer message
        data = {
            "auth_token": "change_this_token_immediately",
            "command": "message",
            "params": {
                "type": "send",
                "text": message,
                "sender": "Test Direct",
            }
        }
        
        # Envoi du message
        print("Envoi du message...")
        sock.sendall(json.dumps(data).encode('utf-8'))
        
        # Réception de la réponse
        print("Attente de la réponse...")
        try:
            response = sock.recv(4096)
            print(f"Réponse reçue: {response.decode('utf-8')}")
            return True
        except socket.timeout:
            print("❌ Pas de réponse (timeout)")
            return False
    except Exception as e:
        print(f"❌ Erreur: {e}")
        return False
    finally:
        sock.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test direct de connexion")
    parser.add_argument("ip", help="Adresse IP du client")
    parser.add_argument("message", help="Message à envoyer")
    parser.add_argument("--port", type=int, default=9878, help="Port à utiliser")
    
    args = parser.parse_args()
    test_direct(args.ip, args.message, args.port)