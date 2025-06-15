MyLanManager
Outil de Gestion et Surveillance de Réseau Local

MyLanManager est un outil de gestion et de surveillance de réseau local développé en Python. Il est conçu pour répondre au besoin croissant de visibilité et de sécurité au sein des réseaux domestiques et professionnels. Le projet vise à combler le fossé entre les outils professionnels complexes et les applications grand public souvent limitées, en offrant une solution complète et accessible.


📸 Captures d'écran
&lt;table>
&lt;tr>
&lt;td>&lt;img src="file:///C:/Users/pc/Desktop/presentation/logo.png" alt="Interface Principale">&lt;/td>
&lt;td>&lt;img src="URL_VERS_FIGURE_3.2" alt="Interface de Scan">&lt;/td>
&lt;td>&lt;img src="URL_VERS_FIGURE_3.3" alt="Liste des Appareils">&lt;/td>
&lt;/tr>
&lt;tr>
&lt;td align="center">&lt;em>Figure 3.1: Interface Principale &lt;/em>&lt;/td>
&lt;td align="center">&lt;em>Figure 3.2: Interface de Scan Réseau &lt;/em>&lt;/td>
&lt;td align="center">&lt;em>Figure 3.3: Liste des Appareils Détectés &lt;/em>&lt;/td>
&lt;/tr>
&lt;/table>



✨ Fonctionnalités Clés
Scan Réseau Complet : Découverte rapide de tous les appareils connectés sur le réseau local en utilisant des techniques comme les requêtes ARP.
Informations Détaillées : Collecte d'informations précises sur chaque appareil, incluant l'adresse IP, l'adresse MAC, le nom d'hôte et le fabricant.
Surveillance Continue : Observation du réseau en temps réel pour identifier instantanément les nouvelles connexions et les déconnexions.
Système d'Alerte Intégré : Notification de l'utilisateur en cas de connexion d'un appareil inconnu ou non autorisé, agissant comme une première ligne de défense contre les intrusions.
Notifications par E-mail : Intégration avec Prometheus et Alertmanager pour envoyer des alertes robustes par e-mail, même lorsque l'application n'est pas active.
Interface Graphique Intuitive : Une interface utilisateur claire et accessible développée avec PyQt5 pour une prise en main facile.
🛠️ Écosystème Technologique
Langage : Python (3.9+) 
Analyse Réseau : Scapy, Socket 

Interface Graphique : PyQt5 
DevOps & Monitoring : Prometheus, Grafana, Alertmanager, NSSM 


Base de Données : SQLite 
Contrôle de Version : Git 
🏗️ Architecture
L'application repose sur une architecture modulaire qui sépare clairement les responsabilités en quatre composants principaux:

Module de Découverte Réseau : Responsable des scans ponctuels pour détecter les appareils.
Module de Surveillance : Observe le réseau en continu pour détecter les changements en temps réel.
Module de Gestion des Données : Gère la persistance des informations dans une base de données SQLite locale.
Interface Utilisateur : Présente les données et permet l'interaction avec l'utilisateur.
&lt;p align="center">
&lt;img src="URL_VERS_FIGURE_2.1" alt="Architecture Générale" width="600">
&lt;br>
&lt;em>Figure 2.1: Architecture générale de MyLanManager &lt;/em>
&lt;/p>

🚀 Guide d'Installation
1. Prérequis
Python 3.9 ou supérieur 
Git 
pip (généralement inclus avec Python) 
2. Installation de MyLanManager
Bash

# 1. Clonez le dépôt (utilisez l'URL de votre dépôt GitHub)
# L'URL ci-dessous provient du rapport, à adapter si nécessaire
git clone https://gitlab.com/pfs-abtal/pfs-project.git 

# 2. Accédez au répertoire du projet
cd pfs-project

# 3. Créez et activez un environnement virtuel (recommandé)
python -m venv venv 
# Sur Windows (CMD)
venv\Scripts\activate.bat 
# Sur Linux/macOS
source venv/bin/activate 

# 4. Installez les dépendances Python
pip install -r requirements.txt 
3. Installation des Outils de Surveillance (Prometheus, Grafana, Alertmanager)
Ces outils sont nécessaires pour la surveillance continue et les alertes par e-mail.

Créez un dossier monitoring à la racine de votre projet.
Téléchargez les dernières versions de Prometheus, Grafana, et Alertmanager.
Extrayez les exécutables (prometheus.exe, grafana-server.exe, alertmanager.exe) et placez-les dans le dossier monitoring.
Placez les fichiers de configuration (prometheus.yml, alerts.yml, alertmanager.yml, windows_targets.json, linux_targets.json) dans le dossier monitoring. Assurez-vous que les chemins relatifs dans prometheus.yml sont corrects.
(Pour Windows) Installez les outils comme services avec NSSM pour une exécution en arrière-plan.
PowerShell

# Exécutez en tant qu'administrateur
nssm install Prometheus
nssm install Grafana
nssm install Alertmanager
Configurez le chemin de chaque exécutable et les arguments (--config.file=...) dans les fenêtres de NSSM.


4. Lancement
Lancez les services de surveillance (via services.msc sur Windows ou en les démarrant manuellement sur Linux). 

Prometheus sera accessible sur http://localhost:9090.
Grafana sera accessible sur http://localhost:3000.
Alertmanager sera accessible sur http://localhost:9093.
Lancez l'application MyLanManager en exécutant le script principal Python.
Bash

python main.py
🧑‍💻 Auteurs
Ce projet a été réalisé par :

EL GUEDDAR Anoir
LMEQDEM Asmaa
KADA Otman
Sous la supervision de Dr. BOULOUIRD Mohamed, dans le cadre de la formation à l'École Nationale des Sciences Appliquées de Marrakech.

