# MyLanManager: Outil de Gestion et Surveillance de Réseau Local

*MyLanManager est un outil de gestion et de surveillance de réseau local développé en Python. Il est conçu pour répondre au besoin croissant de visibilité et de sécurité au sein des réseaux domestiques et professionnels. Le projet vise à combler le fossé entre les outils professionnels complexes et les applications grand public souvent limitées, en offrant une solution complète et accessible.*

## *Interface Principale*:

![image](https://github.com/AnoirELGUEDDAR/pfs-project/blob/main/main_interface.png?raw=true)

## *Interface de Scan*:

![image](https://github.com/AnoirELGUEDDAR/pfs-project/blob/main/image.png?raw=true)
## *Dashboard pour monitoring*:

![image](https://github.com/AnoirELGUEDDAR/pfs-project/blob/main/grafana_dash.png?raw=true)
# ✨ Fonctionnalités Clés
### Scan Réseau Complet : 
Découverte rapide de tous les appareils connectés sur le réseau local en utilisant des techniques comme les requêtes ARP.
### Informations Détaillées :
Collecte d'informations précises sur chaque appareil, incluant l'adresse IP, l'adresse MAC, le nom d'hôte et le fabricant.
### Surveillance Continue : 
Observation du réseau en temps réel pour identifier instantanément les nouvelles connexions et les déconnexions.
### Système d'Alerte Intégré : 
Notification de l'utilisateur en cas de connexion d'un appareil inconnu ou non autorisé, agissant comme une première ligne de défense contre les intrusions.
### Notifications par E-mail : 
Intégration avec Prometheus et Alertmanager pour envoyer des alertes robustes par e-mail, même lorsque l'application n'est pas active.
### Interface Graphique Intuitive :
Une interface utilisateur claire et accessible développée avec PyQt5 pour une prise en main facile.
# 🛠️ Écosystème Technologique
### *Langage* : Python (3.9+) 
### *Analyse Réseau* : Scapy, Socket 
### *Interface Graphique* : PyQt5 
### *DevOps & Monitoring* : Prometheus, Grafana, Alertmanager, NSSM 
### *Base de Données* : SQLite 
### *Contrôle de Version* : Git 
# 🏗️ Architecture
L'application repose sur une architecture modulaire qui sépare clairement les responsabilités en quatre composants principaux:

### *Module de Découverte Réseau* : 
Responsable des scans ponctuels pour détecter les appareils.
### *Module de Surveillance* : 
Observe le réseau en continu pour détecter les changements en temps réel.
### *Module de Gestion des Données* :
Gère la persistance des informations dans une base de données SQLite locale.
### *Interface Utilisateur* : 
Présente les données et permet l'interaction avec l'utilisateur.
# 🚀 Guide d'Installation
## 1. Prérequis
### -Python 3.9 ou supérieur 
### -Git 
### -pip (généralement inclus avec Python) 
## 2. Installation de MyLanManager
### 1. Clonez le dépôt:
*git clone https://gitlab.com/pfs-abtal/pfs-project.git*

### 2. Accédez au répertoire du projet
*cd pfs-project*

### 3. Créez et activez un environnement virtuel (recommandé)
*python -m venv venv*
#### Sur Windows (CMD)
venv\Scripts\activate.bat 
#### Sur Linux/macOS
source venv/bin/activate 

## 4. Installez les dépendances Python
### *pip install -r requirements.txt*
## 3. Installation des Outils de Surveillance (Prometheus, Grafana, Alertmanager)
#### -*Créez un dossier monitoring à la racine de votre projet.*
#### -*Téléchargez les dernières versions de Prometheus, Grafana, et Alertmanager.*
#### -*Extrayez les exécutables (prometheus.exe, grafana-server.exe, alertmanager.exe) et placez-les dans le dossier monitoring.*
#### -*Placez les fichiers de configuration (prometheus.yml, alerts.yml, alertmanager.yml, windows_targets.json, linux_targets.json) dans le dossier monitoring. Assurez-vous que les chemins relatifs dans prometheus.yml sont corrects.*
#### *(Pour Windows) Installez les outils comme services avec NSSM pour une exécution en arrière-plan.
#### *PowerShell
*nssm install Prometheus*<br>
*nssm install Grafana*<br>
*nssm install Alertmanager*<br>
-Configurez le chemin de chaque exécutable et les arguments (--config.file=...) dans les fenêtres de NSSM.


## 4. Lancement
### Lancez les services de surveillance (via services.msc sur Windows ou en les démarrant manuellement sur Linux). 
*-Prometheus sera accessible sur http://localhost:9090.* <br>
*-Grafana sera accessible sur http://localhost:3000.* <br>
*-Alertmanager sera accessible sur http://localhost:9093.* <br>
### Lancez l'application MyLanManager en exécutant le script principal Python.
*python main.py*
## 🧑‍💻 Auteurs
Ce projet a été réalisé par :<br>
### EL GUEDDAR Anoir
### LMEQDEM Asmaa
### KADA Otman

