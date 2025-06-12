import subprocess
import re
import socket
import sys

# --- Paramètres ---
# La commande pour lancer votre script principal.
COMMAND_TO_RUN = [sys.executable, "main.py"]

# Le port sur lequel les clients écouteront.
CLIENT_LISTEN_PORT = 9999

# L'expression régulière pour trouver l'IP et le message.
LOG_REGEX = re.compile(r"INFO: Message sent to ([\d\.]+): (.*)")

# --- Code principal ---

def start_server():
    """
    Lance le processus à surveiller et traite sa sortie ligne par ligne.
    """
    print(f"INFO: Lancement du serveur de surveillance...")
    print(f"INFO: Exécution de la commande : {' '.join(COMMAND_TO_RUN)}")

    try:
        # Lance le script main.py en tant que sous-processus.
        process = subprocess.Popen(
            COMMAND_TO_RUN,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            # ---- CORRECTION APPLIQUÉE ICI ----
            # Utiliser 'latin-1' pour éviter les erreurs de décodage si la sortie
            # de main.py contient des caractères accentués non-UTF-8.
            encoding='latin-1',
            bufsize=1
        )

        # Lit la sortie du processus ligne par ligne et en temps réel.
        for line in iter(process.stdout.readline, ''):
            # Affiche la ligne originale du log dans ce terminal aussi (optionnel)
            print(f"LOG | {line.strip()}")

            # Cherche une correspondance avec notre regex.
            match = LOG_REGEX.search(line)
            if match:
                # Si ça correspond, on extrait les groupes capturés.
                ip_address = match.group(1)
                message = match.group(2)

                print(f"MATCH | IP détectée: {ip_address}, Message: {message}")

                # On envoie le message extrait au client concerné.
                send_message_to_client(ip_address, message)

        # Attendre la fin du processus pour récupérer le code de sortie.
        process.wait()
        print(f"INFO: Le processus '{' '.join(COMMAND_TO_RUN)}' s'est terminé.")

    except FileNotFoundError:
        print(f"ERREUR: La commande '{COMMAND_TO_RUN[0]}' est introuvable.")
        print("Vérifiez que Python est bien installé et dans votre PATH.")
    except Exception as e:
        print(f"Une erreur inattendue est survenue: {e}")


def send_message_to_client(ip, message):
    """
    Se connecte à un client à l'IP et au port donnés, et envoie un message.
    """
    try:
        # Crée un nouveau socket pour chaque message à envoyer.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            print(f"SEND | Connexion à {ip}:{CLIENT_LISTEN_PORT}...")
            s.connect((ip, CLIENT_LISTEN_PORT))
            # Envoie le message, correctement encodé en UTF-8 pour le réseau.
            s.sendall(message.encode('utf-8'))
            print(f"SEND | Message envoyé avec succès à {ip}.")
    except socket.timeout:
        print(f"ERREUR | Timeout lors de la connexion à {ip}. Le client est-il joignable ?")
    except ConnectionRefusedError:
        print(f"ERREUR | Connexion refusée par {ip}. Le script client est-il lancé ?")
    except Exception as e:
        print(f"ERREUR | Impossible d'envoyer le message à {ip}: {e}")


if __name__ == "__main__":
    start_server()