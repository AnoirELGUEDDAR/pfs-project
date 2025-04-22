"""
Onglet de gestion à distance des appareils
"""
import logging
import threading
import json
import socket
import time
from datetime import datetime

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QLabel, QLineEdit, QFormLayout, QSpinBox,
    QDialog, QFileDialog, QMessageBox, QAction,
    QMenu, QInputDialog
)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QIcon, QColor, QBrush

from core.remote.device_manager import DeviceManager

logger = logging.getLogger(__name__)

class AddDeviceDialog(QDialog):
    """Dialogue pour ajouter un appareil distant"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Ajouter un appareil distant")
        self.resize(400, 200)
        self._setup_ui()
        
    def _setup_ui(self):
        """Configurer l'interface utilisateur"""
        layout = QVBoxLayout(self)
        
        # Formulaire
        form_layout = QFormLayout()
        
        self.name_input = QLineEdit()
        form_layout.addRow("Nom de l'appareil:", self.name_input)
        
        self.ip_input = QLineEdit()
        self.ip_input.setText("192.168.1.")
        form_layout.addRow("Adresse IP:", self.ip_input)
        
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(9877)  # Port par défaut de l'agent
        form_layout.addRow("Port:", self.port_input)
        
        self.token_input = QLineEdit()
        self.token_input.setText("change_this_token_immediately")  # Token par défaut
        form_layout.addRow("Token d'authentification:", self.token_input)
        
        layout.addLayout(form_layout)
        
        # Boutons
        buttons_layout = QHBoxLayout()
        
        self.cancel_button = QPushButton("Annuler")
        self.cancel_button.clicked.connect(self.reject)
        
        self.add_button = QPushButton("Ajouter")
        self.add_button.clicked.connect(self.accept)
        
        buttons_layout.addWidget(self.cancel_button)
        buttons_layout.addWidget(self.add_button)
        
        layout.addLayout(buttons_layout)
        
    def get_values(self):
        """Récupérer les valeurs saisies"""
        return {
            "name": self.name_input.text(),
            "ip": self.ip_input.text(),
            "port": self.port_input.value(),
            "token": self.token_input.text()
        }

class WakeOnLANDialog(QDialog):
    """Dialogue pour Wake-on-LAN"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Wake-on-LAN")
        self.resize(350, 150)
        self._setup_ui()
        
    def _setup_ui(self):
        """Configurer l'interface utilisateur"""
        layout = QVBoxLayout(self)
        
        # Formulaire
        form_layout = QFormLayout()
        
        self.mac_input = QLineEdit()
        self.mac_input.setPlaceholderText("00:11:22:33:44:55")
        form_layout.addRow("Adresse MAC:", self.mac_input)
        
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("255.255.255.255 (broadcast)")
        self.ip_input.setText("255.255.255.255")
        form_layout.addRow("Adresse IP (broadcast):", self.ip_input)
        
        layout.addLayout(form_layout)
        
        # Boutons
        buttons_layout = QHBoxLayout()
        
        self.cancel_button = QPushButton("Annuler")
        self.cancel_button.clicked.connect(self.reject)
        
        self.wake_button = QPushButton("Réveiller")
        self.wake_button.clicked.connect(self.accept)
        
        buttons_layout.addWidget(self.cancel_button)
        buttons_layout.addWidget(self.wake_button)
        
        layout.addLayout(buttons_layout)
        
    def get_values(self):
        """Récupérer les valeurs saisies"""
        return {
            "mac": self.mac_input.text(),
            "ip": self.ip_input.text()
        }

class RemoteTab(QWidget):
    """Onglet de gestion à distance des appareils"""
    
    # Signaux standard
    update_device_status = pyqtSignal(str, str)
    
    # Nouveaux signaux pour la communication thread-UI sécurisée
    file_transfer_success = pyqtSignal(str)  # Paramètre: device_name
    file_transfer_error = pyqtSignal(str)    # Paramètre: device_name
    progress_dialog_close = pyqtSignal()     # Signal sans paramètre
    system_info_success = pyqtSignal(str, str)  # Paramètres: title, message
    command_execution_success = pyqtSignal(str, str)  # Paramètres: title, message
    command_execution_error = pyqtSignal(str)  # Paramètre: message
    shutdown_success = pyqtSignal(str, str)  # Paramètres: device_name, delay
    shutdown_error = pyqtSignal(str)  # Paramètre: device_name
    restart_success = pyqtSignal(str, str)  # Paramètres: device_name, delay
    restart_error = pyqtSignal(str)  # Paramètre: device_name
    
    def __init__(self):
        super().__init__()
        
        # Créer le gestionnaire de périphériques
        self.device_manager = DeviceManager()
        
        # Variable pour stocker la référence à la boîte de dialogue de progression
        self.current_progress_dialog = None
        
        # Configurer l'interface
        self._setup_ui()
        
        # Connecter les signaux standard
        self.update_device_status.connect(self._update_device_status_slot)
        
        # Connecter les nouveaux signaux pour la communication thread-UI
        self.file_transfer_success.connect(self._show_transfer_success)
        self.file_transfer_error.connect(self._show_transfer_error)
        self.progress_dialog_close.connect(self._close_progress_dialog)
        self.system_info_success.connect(self._show_info_message)
        self.command_execution_success.connect(self._show_info_message)
        self.command_execution_error.connect(self._show_error_message)
        self.shutdown_success.connect(self._show_shutdown_success)
        self.shutdown_error.connect(self._show_shutdown_error)
        self.restart_success.connect(self._show_restart_success)
        self.restart_error.connect(self._show_restart_error)
        
        # Remplir le tableau avec les appareils déjà connus
        self._update_devices_table()
    
    def _setup_ui(self):
        """Configurer l'interface utilisateur"""
        layout = QVBoxLayout(self)
        
        # En-tête et contrôles
        header_layout = QHBoxLayout()
        
        header_label = QLabel("<h2>Gestion à Distance</h2>")
        header_layout.addWidget(header_label)
        header_layout.addStretch(1)
        
        self.add_button = QPushButton("Ajouter un Appareil")
        self.add_button.clicked.connect(self._add_device)
        header_layout.addWidget(self.add_button)
        
        self.wol_button = QPushButton("Wake-on-LAN")
        self.wol_button.clicked.connect(self._wake_on_lan)
        header_layout.addWidget(self.wol_button)
        
        layout.addLayout(header_layout)
        
        # Message d'information
        info_label = QLabel(
            "Cette fonctionnalité permet de gérer à distance les appareils sur lesquels "
            "vous avez installé l'agent réseau."
        )
        info_label.setWordWrap(True)
        layout.addWidget(info_label)
        
        # Tableau des appareils
        self.devices_table = QTableWidget(0, 5)
        self.devices_table.setHorizontalHeaderLabels([
            "Nom", "Adresse IP", "Port", "Statut", "Dernière Connexion"
        ])
        self.devices_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.devices_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.devices_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.devices_table.customContextMenuRequested.connect(self._show_context_menu)
        
        layout.addWidget(self.devices_table, 1)  # 1 est le facteur d'étirement
        
        # Contrôles du bas
        bottom_layout = QHBoxLayout()
        
        self.refresh_button = QPushButton("Rafraîchir les Statuts")
        self.refresh_button.clicked.connect(self._refresh_statuses)
        bottom_layout.addWidget(self.refresh_button)
        
        self.force_online_button = QPushButton("Forcer le Statut Online")
        self.force_online_button.clicked.connect(self._force_online)
        bottom_layout.addWidget(self.force_online_button)
        
        self.force_refresh_button = QPushButton("Test direct connexion")
        self.force_refresh_button.clicked.connect(self.force_refresh_statuses)
        bottom_layout.addWidget(self.force_refresh_button)
        
        self.remove_button = QPushButton("Supprimer l'Appareil")
        self.remove_button.clicked.connect(self._remove_device)
        bottom_layout.addWidget(self.remove_button)

        self.delete_all_button = QPushButton("Supprimer tous les appareils")
        self.delete_all_button.clicked.connect(self._delete_all_devices)
        bottom_layout.addWidget(self.delete_all_button)
        
        bottom_layout.addStretch(1)
        
        layout.addLayout(bottom_layout)
    
    # Méthodes utilitaires pour gérer les dialogues
    def _close_progress_dialog(self):
        """Fermer la boîte de dialogue de progression"""
        if self.current_progress_dialog:
            self.current_progress_dialog.close()
            self.current_progress_dialog = None
    
    def _show_info_message(self, title, message):
        """Afficher un message d'information"""
        QMessageBox.information(self, title, message)

    def _show_error_message(self, message):
        """Afficher un message d'erreur"""
        QMessageBox.warning(self, "Erreur", message)
    
    # Méthodes pour afficher les résultats de transfert de fichier
    def _show_transfer_success(self, device_name):
        """Afficher un message de succès après le transfert"""
        QMessageBox.information(
            self,
            "Fichier Envoyé",
            f"Le fichier a été envoyé avec succès à {device_name}."
        )

    def _show_transfer_error(self, device_name):
        """Afficher un message d'erreur après le transfert"""
        QMessageBox.warning(
            self,
            "Erreur",
            f"Impossible d'envoyer le fichier à {device_name}.\n"
            f"Vérifiez que l'appareil est en ligne et que l'agent a les permissions nécessaires."
        )
    
    # Méthodes pour afficher les résultats d'arrêt/redémarrage
    def _show_shutdown_success(self, device_name, delay):
        """Afficher un message de succès après l'arrêt"""
        QMessageBox.information(
            self,
            "Arrêt Programmé",
            f"L'arrêt de {device_name} a été programmé dans {delay} secondes."
        )
    
    def _show_shutdown_error(self, device_name):
        """Afficher un message d'erreur après l'arrêt"""
        QMessageBox.warning(
            self,
            "Erreur",
            f"Impossible d'arrêter {device_name}.\n"
            f"Vérifiez que l'appareil est en ligne et que l'agent a les permissions nécessaires."
        )
    
    def _show_restart_success(self, device_name, delay):
        """Afficher un message de succès après le redémarrage"""
        QMessageBox.information(
            self,
            "Redémarrage Programmé",
            f"Le redémarrage de {device_name} a été programmé dans {delay} secondes."
        )
    
    def _show_restart_error(self, device_name):
        """Afficher un message d'erreur après le redémarrage"""
        QMessageBox.warning(
            self,
            "Erreur",
            f"Impossible de redémarrer {device_name}.\n"
            f"Vérifiez que l'appareil est en ligne et que l'agent a les permissions nécessaires."
        )
    
    def _force_online(self):
        """Force le statut de l'appareil sélectionné à 'online'"""
        selected_rows = self.devices_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.information(self, "Sélection", "Sélectionnez d'abord un appareil")
            return
        
        row = selected_rows[0].row()
        ip = self.devices_table.item(row, 1).text()
        port = int(self.devices_table.item(row, 2).text())
        device_id = f"{ip}:{port}"
        
        # Forcer le statut à online dans le dictionnaire
        self.device_manager.devices[device_id]["status"] = "online"
        
        # Mettre à jour l'interface
        status_item = QTableWidgetItem("online")
        status_item.setForeground(QBrush(QColor("green")))
        self.devices_table.setItem(row, 3, status_item)
        
        # Mettre à jour la date
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.devices_table.setItem(row, 4, QTableWidgetItem(now))
        
        # Sauvegarder l'état
        self.device_manager.save_devices()
        
        QMessageBox.information(self, "Statut forcé", "Le statut de l'appareil a été forcé à 'online'")
    
    def force_refresh_statuses(self):
        """Force le rafraîchissement des statuts de tous les appareils"""
        devices = self.device_manager.get_devices()
        
        for device_id, device in devices.items():
            ip = device["ip"]
            port = device["port"]
            
            # Vérifier directement si le port est ouvert
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)  # Timeout court
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    # Port ouvert, mettre immédiatement l'appareil en ligne
                    self.update_device_status.emit(device_id, "online")
                    self.device_manager.devices[device_id]["status"] = "online"
                    self.device_manager.devices[device_id]["last_connected"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                else:
                    # Port fermé, mettre hors ligne
                    self.update_device_status.emit(device_id, "offline")
                    self.device_manager.devices[device_id]["status"] = "offline"
            except Exception as e:
                print(f"Erreur de connexion: {str(e)}")
                # En cas d'erreur, mettre hors ligne
                self.update_device_status.emit(device_id, "offline")
                self.device_manager.devices[device_id]["status"] = "offline"
        
        # Sauvegarder les changements
        self.device_manager.save_devices()
        
        # Mettre à jour la table
        self._update_devices_table()
        
        QMessageBox.information(self, "Test terminé", 
                               f"Test de connexion terminé pour {len(devices)} appareils.\n\n"
                               "Les appareils accessibles sont marqués comme 'online'.")

    def _delete_all_devices(self):
        """Supprimer tous les appareils"""
        devices = self.device_manager.get_devices()
        if not devices:
            QMessageBox.information(self, "Information", "Aucun appareil à supprimer")
            return
            
        reply = QMessageBox.question(
            self,
            "Confirmation",
            f"Êtes-vous sûr de vouloir supprimer TOUS les appareils ({len(devices)}) ?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # Supprimer tous les appareils
            self.device_manager.devices.clear()
            self.device_manager.save_devices()
            
            # Mettre à jour l'interface
            self.devices_table.setRowCount(0)
            
            QMessageBox.information(self, "Suppression", "Tous les appareils ont été supprimés")
            
    def _add_device(self):
        """Ajouter un appareil distant"""
        dialog = AddDeviceDialog(self)
        if dialog.exec_():
            values = dialog.get_values()
            
            # Vérifier les entrées
            if not values["name"] or not values["ip"] or not values["token"]:
                QMessageBox.warning(
                    self,
                    "Entrées manquantes",
                    "Veuillez remplir tous les champs obligatoires (nom, IP, token)"
                )
                return
            
            # Ajouter l'appareil
            device_id = f"{values['ip']}:{values['port']}"
            success = self.device_manager.add_device(
                values["name"],
                values["ip"],
                values["port"],
                values["token"]
            )
            
            print(f"Ajout de l'appareil {device_id}: {'succès' if success else 'échec'}")
            
            # Ajouter au tableau et mettre à jour l'interface
            self._update_devices_table()
            
            if success:
                QMessageBox.information(
                    self,
                    "Appareil Ajouté",
                    f"L'appareil {values['name']} a été ajouté et connecté avec succès"
                )
            else:
                QMessageBox.warning(
                    self,
                    "Erreur de Connexion",
                    f"L'appareil {values['name']} a été ajouté mais n'a pas pu être contacté.\n"
                    f"Vérifiez l'adresse IP, le port et le token d'authentification."
                )
    
    def _remove_device(self):
        """Supprimer un appareil sélectionné"""
        selected_rows = self.devices_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.information(self, "Sélection", "Sélectionnez d'abord un appareil")
            return
        
        row = selected_rows[0].row()
        ip = self.devices_table.item(row, 1).text()
        port = int(self.devices_table.item(row, 2).text())
        device_id = f"{ip}:{port}"
        
        reply = QMessageBox.question(
            self,
            "Confirmation",
            f"Voulez-vous vraiment supprimer l'appareil {self.devices_table.item(row, 0).text()}?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.device_manager.remove_device(device_id)
            self.devices_table.removeRow(row)
    
    def _wake_on_lan(self):
        """Envoyer un paquet Wake-on-LAN"""
        dialog = WakeOnLANDialog(self)
        if dialog.exec_():
            values = dialog.get_values()
            
            if not values["mac"]:
                QMessageBox.warning(self, "Entrée manquante", "Veuillez saisir l'adresse MAC")
                return
                
            # Envoyer le paquet
            success = self.device_manager.wake_on_lan(
                values["mac"],
                values["ip"] if values["ip"] else None
            )
            
            if success:
                QMessageBox.information(
                    self,
                    "Wake-on-LAN",
                    f"Paquet Wake-on-LAN envoyé à {values['mac']}"
                )
            else:
                QMessageBox.warning(
                    self,
                    "Erreur",
                    f"Erreur lors de l'envoi du paquet Wake-on-LAN"
                )
    
    def _refresh_statuses(self):
        """Rafraîchir le statut de tous les appareils"""
        devices = self.device_manager.get_devices()
        
        if not devices:
            QMessageBox.information(self, "Information", "Aucun appareil à rafraîchir")
            return
            
        # Créer un dialogue de progression
        progress_dialog = QMessageBox()
        progress_dialog.setWindowTitle("Rafraîchissement")
        progress_dialog.setText(f"Rafraîchissement des statuts en cours pour {len(devices)} appareil(s)...")
        progress_dialog.setStandardButtons(QMessageBox.NoButton)
        progress_dialog.show()
        
        # Mettre à jour l'interface pour montrer que quelque chose se passe
        QMessageBox.information(
            self,
            "Rafraîchissement",
            f"Rafraîchissement des statuts lancé pour {len(devices)} appareil(s).\n"
            f"Les résultats seront mis à jour dans quelques secondes."
        )
        
        # Exécuter le rafraîchissement dans un thread
        refresh_thread = threading.Thread(target=self._refresh_thread, args=(devices,))
        refresh_thread.daemon = True
        refresh_thread.start()
        
    def _refresh_thread(self, devices):
        """Thread pour rafraîchir les statuts"""
        for device_id in devices:
            # Tenter de ping chaque appareil
            self._ping_device_thread(device_id)
            # Petite pause pour éviter de surcharger le réseau
            time.sleep(0.5)
            
        # Mettre à jour l'interface une fois tous les pings terminés
        self._update_devices_table()
    
    def _ping_device_thread(self, device_id):
        """Thread pour ping d'un appareil"""
        try:
            # Obtenir les informations sur l'appareil
            device = self.device_manager.get_devices()[device_id]
            ip = device["ip"]
            port = device["port"]
            token = device["token"]
            
            print(f"DEBUG: Tentative de ping vers {ip}:{port}")
            
            # Test direct de la connexion TCP pour vérifier si le port est accessible
            try:
                # Simplement test de connexion TCP
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)  # Timeout plus long
                result = sock.connect_ex((ip, port))
                
                if result == 0:
                    print(f"DEBUG: Port {port} ouvert sur {ip} - appareil probablement en ligne")
                    # Envoyer un ping à l'agent
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
                                    self.update_device_status.emit(device_id, "online")
                                    self.device_manager.devices[device_id]["status"] = "online"
                                    self.device_manager.devices[device_id]["last_connected"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                    self.device_manager.save_devices()
                                    print(f"DEBUG: Ping réussi à {ip}:{port}")
                                    sock.close()
                                    return True
                            except json.JSONDecodeError:
                                print(f"DEBUG: Réponse invalide de {ip}:{port}: {response_data}")
                    except Exception as e:
                        print(f"DEBUG: Erreur lors du ping de l'agent: {e}")
                    
                    # Si on arrive ici, la connexion TCP a réussi mais pas le protocole
                    # On considère l'appareil comme en ligne quand même
                    self.update_device_status.emit(device_id, "online")
                    self.device_manager.devices[device_id]["status"] = "online"
                    self.device_manager.devices[device_id]["last_connected"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    self.device_manager.save_devices()
                    sock.close()
                    return True
                else:
                    print(f"DEBUG: Port {port} fermé sur {ip} - code {result}")
                    sock.close()
            except Exception as e:
                print(f"DEBUG: Erreur de connexion TCP: {str(e)}")
                
            # Si on arrive ici, l'appareil est considéré comme hors ligne
            self.update_device_status.emit(device_id, "offline")
            self.device_manager.devices[device_id]["status"] = "offline"
            self.device_manager.save_devices()
            return False
        except Exception as e:
            print(f"DEBUG: Erreur générale: {str(e)}")
            self.update_device_status.emit(device_id, "offline")
            return False
    
    def _update_device_status_slot(self, device_id, status):
        """Mettre à jour le statut d'un appareil dans l'interface"""
        # Ajouter un log pour le débogage
        print(f"Signal reçu: mise à jour de {device_id} à {status}")
        logger.info(f"Signal reçu: mise à jour de {device_id} à {status}")
        
        devices = self.device_manager.get_devices()
        if device_id not in devices:
            print(f"Appareil {device_id} introuvable dans la liste des appareils")
            logger.warning(f"Appareil {device_id} introuvable dans la liste des appareils")
            return
            
        # Trouver la ligne correspondante
        found = False
        for row in range(self.devices_table.rowCount()):
            ip = self.devices_table.item(row, 1).text()
            port = self.devices_table.item(row, 2).text()
            current_id = f"{ip}:{port}"
            
            if current_id == device_id:
                # Mise à jour du statut avec un style visuel
                status_item = QTableWidgetItem(status)
                
                # Appliquer une couleur selon le statut
                if status == "online":
                    status_item.setForeground(QBrush(QColor("green")))
                else:
                    status_item.setForeground(QBrush(QColor("red")))
                    
                self.devices_table.setItem(row, 3, status_item)
                
                # Mettre à jour la dernière connexion si en ligne
                if status == "online":
                    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    self.devices_table.setItem(row, 4, QTableWidgetItem(now))
                
                print(f"Statut mis à jour pour la ligne {row}")
                logger.info(f"Statut mis à jour pour la ligne {row}")
                found = True
                break
        
        if not found:
            print(f"Aucune ligne correspondante trouvée pour l'appareil {device_id}")
            logger.warning(f"Aucune ligne correspondante trouvée pour l'appareil {device_id}")
    
    def _update_devices_table(self):
        """Mettre à jour le tableau des appareils"""
        devices = self.device_manager.get_devices()
        
        # Effacer le tableau
        self.devices_table.setRowCount(0)
        
        # Remplir avec les appareils
        for device_id, info in devices.items():
            row = self.devices_table.rowCount()
            self.devices_table.insertRow(row)
            
            self.devices_table.setItem(row, 0, QTableWidgetItem(info.get("name", "")))
            self.devices_table.setItem(row, 1, QTableWidgetItem(info.get("ip", "")))
            self.devices_table.setItem(row, 2, QTableWidgetItem(str(info.get("port", ""))))
            
            # Statut avec mise en forme
            status = info.get("status", "unknown")
            status_item = QTableWidgetItem(status)
            
            if status == "online":
                status_item.setForeground(QBrush(QColor("green")))
            elif status == "offline":
                status_item.setForeground(QBrush(QColor("red")))
                
            self.devices_table.setItem(row, 3, status_item)
            
            # Dernière connexion
            self.devices_table.setItem(row, 4, QTableWidgetItem(info.get("last_connected", "")))
    
    def _show_context_menu(self, position):
        """Afficher le menu contextuel pour les appareils"""
        selected_rows = self.devices_table.selectionModel().selectedRows()
        if not selected_rows:
            return
            
        row = selected_rows[0].row()
        ip = self.devices_table.item(row, 1).text()
        port = int(self.devices_table.item(row, 2).text())
        device_id = f"{ip}:{port}"
        device_name = self.devices_table.item(row, 0).text()
        
        # Créer le menu
        context_menu = QMenu()
        
        # Actions principales
        ping_action = context_menu.addAction("Ping")
        ping_action.triggered.connect(lambda: self._ping_selected(device_id))
        
        info_action = context_menu.addAction("Informations Système")
        info_action.triggered.connect(lambda: self._get_system_info(device_id, device_name))
        
        cmd_action = context_menu.addAction("Exécuter une Commande")
        cmd_action.triggered.connect(lambda: self._execute_command(device_id, device_name))
        
        # Sous-menu d'alimentation
        power_menu = context_menu.addMenu("Alimentation")
        
        shutdown_action = power_menu.addAction("Arrêter")
        shutdown_action.triggered.connect(lambda: self._shutdown_selected(device_id, device_name))
        
        restart_action = power_menu.addAction("Redémarrer")
        restart_action.triggered.connect(lambda: self._restart_selected(device_id, device_name))
        
        # Transfert de fichiers
        transfer_action = context_menu.addAction("Envoyer un Fichier")
        transfer_action.triggered.connect(lambda: self._send_file(device_id, device_name))
        
        # Afficher le menu
        context_menu.exec_(self.devices_table.viewport().mapToGlobal(position))
    
    def _ping_selected(self, device_id):
        """Ping l'appareil sélectionné"""
        threading.Thread(
            target=self._ping_device_thread,
            args=(device_id,),
            daemon=True
        ).start()
        
        QMessageBox.information(
            self,
            "Ping",
            f"Ping envoyé à l'appareil. Le statut sera mis à jour."
        )
    
    def _get_system_info(self, device_id, device_name):
        """Récupérer les informations système"""
        # Afficher un message de chargement
        wait_msg = QMessageBox(self)
        wait_msg.setIcon(QMessageBox.Information)
        wait_msg.setText("Récupération des informations système en cours...")
        wait_msg.setStandardButtons(QMessageBox.NoButton)
        
        # Stocker la référence
        self.current_progress_dialog = wait_msg
        wait_msg.show()
        
        # Récupérer les informations dans un thread
        def get_info_thread():
            info = self.device_manager.get_system_info(device_id)
            
            # Émettre le signal pour fermer le dialogue d'attente
            self.progress_dialog_close.emit()
            
            if info:
                # Créer un message avec les infos
                message = f"Informations système pour {device_name}:\n\n"
                
                message += f"Nom d'hôte: {info.get('hostname', 'N/A')}\n"
                message += f"Plateforme: {info.get('platform', 'N/A')} {info.get('platform_version', '')}\n"
                message += f"Architecture: {info.get('architecture', 'N/A')}\n"
                
                if info.get('cpu_name'):
                    message += f"Processeur: {info.get('cpu_name')}\n"
                
                if info.get('total_memory_mb'):
                    message += f"Mémoire totale: {info.get('total_memory_mb')} Mo\n"
                elif info.get('total_memory'):
                    message += f"Mémoire totale: {info.get('total_memory')}\n"
                    
                if info.get('disks'):
                    message += "\nDisques:\n"
                    for disk in info.get('disks', []):
                        message += f"  {disk.get('drive')}: {disk.get('size_gb', 'N/A')} Go (libre: {disk.get('free_gb', 'N/A')} Go)\n"
                
                message += f"\nHeure locale: {info.get('time', 'N/A')}"
                
                # Émettre le signal avec les informations
                self.system_info_success.emit(f"Informations Système - {device_name}", message)
            else:
                # Émettre un signal d'erreur
                self.command_execution_error.emit(
                    f"Impossible de récupérer les informations système pour {device_name}.\n"
                    f"Vérifiez que l'appareil est en ligne et que l'agent fonctionne correctement."
                )
        
        # Démarrer le thread
        threading.Thread(target=get_info_thread, daemon=True).start()
    
    def _execute_command(self, device_id, device_name):
        """Exécuter une commande sur l'appareil sélectionné"""
        command, ok = QInputDialog.getText(
            self,
            f"Exécuter une commande sur {device_name}",
            "Entrez la commande à exécuter:",
            text=""
        )
        
        if not ok or not command:
            return
            
        # Afficher un message de chargement
        wait_msg = QMessageBox(self)
        wait_msg.setIcon(QMessageBox.Information)
        wait_msg.setText("Exécution de la commande en cours...")
        wait_msg.setStandardButtons(QMessageBox.NoButton)
        
        # Stocker la référence
        self.current_progress_dialog = wait_msg
        wait_msg.show()
        
        # Exécuter la commande dans un thread
        def execute_thread():
            output = self.device_manager.execute_command(device_id, command)
            
            # Fermer la boîte de dialogue
            self.progress_dialog_close.emit()
            
            if output is not None:
                # Afficher le résultat
                result_message = f"Commande: {command}\n\nRésultat:\n{output}"
                self.command_execution_success.emit(f"Résultat de la commande - {device_name}", result_message)
            else:
                # Afficher une erreur
                self.command_execution_error.emit(
                    f"Impossible d'exécuter la commande sur {device_name}.\n"
                    f"Vérifiez que l'appareil est en ligne et que l'agent a les permissions nécessaires."
                )
        
        # Démarrer le thread
        threading.Thread(target=execute_thread, daemon=True).start()
    
    def _shutdown_selected(self, device_id, device_name):
        """Arrêter l'appareil sélectionné"""
        # Demander confirmation
        reply = QMessageBox.question(
            self,
            "Confirmation",
            f"Voulez-vous vraiment arrêter l'appareil {device_name}?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # Demander un délai
            delay, ok = QInputDialog.getInt(
                self,
                "Délai d'arrêt",
                "Délai avant arrêt (secondes):",
                0, 0, 3600
            )
            
            if ok:
                # Afficher un message de chargement
                wait_msg = QMessageBox(self)
                wait_msg.setIcon(QMessageBox.Information)
                wait_msg.setText("Envoi de la commande d'arrêt...")
                wait_msg.setStandardButtons(QMessageBox.NoButton)
                
                # Stocker la référence
                self.current_progress_dialog = wait_msg
                wait_msg.show()
                
                # Exécuter dans un thread
                def shutdown_thread():
                    success = self.device_manager.shutdown_device(device_id, delay)
                    
                    # Fermer la boîte de dialogue
                    self.progress_dialog_close.emit()
                    
                    if success:
                        # Afficher le résultat
                        self.shutdown_success.emit(device_name, str(delay))
                    else:
                        # Afficher une erreur
                        self.shutdown_error.emit(device_name)
                
                # Démarrer le thread
                threading.Thread(target=shutdown_thread, daemon=True).start()
    
    def _restart_selected(self, device_id, device_name):
        """Redémarrer l'appareil sélectionné"""
        # Demander confirmation
        reply = QMessageBox.question(
            self,
            "Confirmation",
            f"Voulez-vous vraiment redémarrer l'appareil {device_name}?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # Demander un délai
            delay, ok = QInputDialog.getInt(
                self,
                "Délai de redémarrage",
                "Délai avant redémarrage (secondes):",
                0, 0, 3600
            )
            
            if ok:
                # Afficher un message de chargement
                wait_msg = QMessageBox(self)
                wait_msg.setIcon(QMessageBox.Information)
                wait_msg.setText("Envoi de la commande de redémarrage...")
                wait_msg.setStandardButtons(QMessageBox.NoButton)
                
                # Stocker la référence
                self.current_progress_dialog = wait_msg
                wait_msg.show()
                
                # Exécuter dans un thread
                def restart_thread():
                    success = self.device_manager.restart_device(device_id, delay)
                    
                    # Fermer la boîte de dialogue
                    self.progress_dialog_close.emit()
                    
                    if success:
                        # Afficher le résultat
                        self.restart_success.emit(device_name, str(delay))
                    else:
                        # Afficher une erreur
                        self.restart_error.emit(device_name)
                
                # Démarrer le thread
                threading.Thread(target=restart_thread, daemon=True).start()
    
    def _send_file(self, device_id, device_name):
        """Envoyer un fichier à l'appareil sélectionné"""
        # Demander le fichier à envoyer
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            f"Sélectionner un fichier à envoyer à {device_name}",
            "",
            "Tous les fichiers (*)"
        )
        
        if not file_path:
            return
            
        # Demander le dossier de destination
        if self.device_manager.get_devices()[device_id]["ip"].startswith("192.168"):
            # Probablement un système Windows
            default_path = "C:\\Temp"
        else:
            # Probablement un système Linux/Mac
            default_path = "/tmp"
            
        remote_path, ok = QInputDialog.getText(
            self,
            "Dossier de destination",
            "Entrez le chemin du dossier de destination:",
            text=default_path
        )
        
        if not ok or not remote_path:
            return
        
        # Créer la boîte de dialogue de progression
        progress_dialog = QMessageBox(self)
        progress_dialog.setWindowTitle("Envoi de fichier")
        progress_dialog.setText(f"Envoi du fichier en cours vers {device_name}...")
        progress_dialog.setStandardButtons(QMessageBox.Cancel)
        progress_dialog.setModal(False)
        
        # Stocker la référence
        self.current_progress_dialog = progress_dialog
        progress_dialog.show()
        
        # Transfert dans un thread
        def transfer_thread():
            try:
                # Effectuer le transfert
                result = self.device_manager.send_file(device_id, file_path, remote_path)
                
                # Émettre le signal pour fermer la boîte de dialogue
                self.progress_dialog_close.emit()
                
                # Émettre le signal approprié en fonction du résultat
                if result:
                    self.file_transfer_success.emit(device_name)
                else:
                    self.file_transfer_error.emit(device_name)
            except Exception as e:
                print(f"Erreur dans le thread de transfert: {str(e)}")
                self.progress_dialog_close.emit()
                self.file_transfer_error.emit(device_name)
        
        # Démarrer le thread
        transfer_thread = threading.Thread(target=transfer_thread, daemon=True)
        transfer_thread.start()
        
        # Connecter le bouton Cancel pour interrompre l'opération
        progress_dialog.buttonClicked.connect(lambda _: progress_dialog.close())