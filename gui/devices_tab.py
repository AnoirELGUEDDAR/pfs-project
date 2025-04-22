"""
Onglet de gestion des appareils découverts
"""
import logging
import os
import csv
import json
from datetime import datetime
from typing import Dict, List

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTableWidget,
    QTableWidgetItem, QHeaderView, QLabel, QFileDialog, QMessageBox,
    QLineEdit, QComboBox, QDialog, QFormLayout
)
from PyQt5.QtCore import Qt, pyqtSignal, pyqtSlot, QTimer

logger = logging.getLogger(__name__)

class DeviceDetailsDialog(QDialog):
    """Dialogue pour afficher ou éditer les détails d'un appareil"""
    
    def __init__(self, device_data: Dict, parent=None, edit_mode=False):
        super().__init__(parent)
        
        self.device_data = device_data.copy()
        self.edit_mode = edit_mode
        
        self.setWindowTitle("Détails de l'appareil" if not edit_mode else "Modifier l'appareil")
        self.resize(500, 400)
        
        self._setup_ui()
        
    def _setup_ui(self):
        """Configurer l'interface utilisateur"""
        layout = QVBoxLayout(self)
        
        # Formulaire
        form_layout = QFormLayout()
        
        # Champ IP (non éditable)
        self.ip_field = QLineEdit(self.device_data.get('ip', ''))
        self.ip_field.setReadOnly(True)
        form_layout.addRow("Adresse IP:", self.ip_field)
        
        # Champ MAC (non éditable si présent)
        self.mac_field = QLineEdit(self.device_data.get('mac', ''))
        self.mac_field.setReadOnly(not self.edit_mode or bool(self.device_data.get('mac', '')))
        form_layout.addRow("Adresse MAC:", self.mac_field)
        
        # Champ Nom
        self.name_field = QLineEdit(self.device_data.get('name', ''))
        self.name_field.setReadOnly(not self.edit_mode)
        form_layout.addRow("Nom:", self.name_field)
        
        # Champ Type
        self.type_field = QLineEdit(self.device_data.get('type', ''))
        self.type_field.setReadOnly(not self.edit_mode)
        form_layout.addRow("Type d'appareil:", self.type_field)
        
        # Champ Fabricant
        self.vendor_field = QLineEdit(self.device_data.get('vendor', ''))
        self.vendor_field.setReadOnly(not self.edit_mode)
        form_layout.addRow("Fabricant:", self.vendor_field)
        
        # Champ Description
        self.description_field = QLineEdit(self.device_data.get('description', ''))
        self.description_field.setReadOnly(not self.edit_mode)
        form_layout.addRow("Description:", self.description_field)
        
        # Champ Location
        self.location_field = QLineEdit(self.device_data.get('location', ''))
        self.location_field.setReadOnly(not self.edit_mode)
        form_layout.addRow("Emplacement:", self.location_field)
        
        # Champ Ports
        ports_str = ', '.join(map(str, self.device_data.get('open_ports', [])))
        self.ports_field = QLineEdit(ports_str)
        self.ports_field.setReadOnly(True)  # Toujours en lecture seule
        form_layout.addRow("Ports ouverts:", self.ports_field)
        
        # Autres champs
        if self.device_data.get('last_seen'):
            last_seen_field = QLineEdit(self.device_data.get('last_seen', ''))
            last_seen_field.setReadOnly(True)
            form_layout.addRow("Dernière détection:", last_seen_field)
        
        layout.addLayout(form_layout)
        
        # Boutons
        buttons_layout = QHBoxLayout()
        
        if self.edit_mode:
            save_button = QPushButton("Enregistrer")
            save_button.clicked.connect(self.accept)
            buttons_layout.addWidget(save_button)
        
        close_button = QPushButton("Fermer")
        close_button.clicked.connect(self.reject)
        buttons_layout.addWidget(close_button)
        
        layout.addLayout(buttons_layout)
        
    def get_updated_data(self) -> Dict:
        """Récupérer les données mises à jour"""
        if not self.edit_mode:
            return self.device_data
            
        # Mettre à jour les données
        self.device_data['name'] = self.name_field.text()
        self.device_data['type'] = self.type_field.text()
        self.device_data['vendor'] = self.vendor_field.text()
        self.device_data['description'] = self.description_field.text()
        self.device_data['location'] = self.location_field.text()
        
        # Si le champ MAC était vide et est maintenant rempli
        if not self.device_data.get('mac') and self.mac_field.text():
            self.device_data['mac'] = self.mac_field.text()
            
        return self.device_data

class DevicesTab(QWidget):
    """Onglet de gestion des appareils découverts"""
    
    # Signaux
    scan_request = pyqtSignal(str)
    port_scan_request = pyqtSignal(str, list)
    
    def __init__(self):
        super().__init__()
        
        self.devices = {}  # Dictionnaire des appareils (clé = adresse IP)
        self.devices_file = "devices.json"
        
        self._setup_ui()
        self._load_devices()
        
        # Configurer un timer pour sauvegarder périodiquement
        self.save_timer = QTimer()
        self.save_timer.timeout.connect(self._save_devices)
        self.save_timer.start(60000)  # Sauvegarder toutes les minutes
        
    def _setup_ui(self):
        """Configurer l'interface utilisateur"""
        layout = QVBoxLayout(self)
        
        # En-tête et contrôles de recherche
        header_layout = QHBoxLayout()
        
        header_label = QLabel("Appareils du Réseau")
        header_layout.addWidget(header_label)
        
        header_layout.addStretch(1)
        
        self.search_field = QLineEdit()
        self.search_field.setPlaceholderText("Rechercher un appareil...")
        self.search_field.setClearButtonEnabled(True)
        self.search_field.textChanged.connect(self._filter_devices)
        header_layout.addWidget(self.search_field)
        
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["Tous", "En ligne", "Hors ligne", "PC", "Mobile", "IoT", "Réseau"])
        self.filter_combo.currentTextChanged.connect(self._filter_devices)
        header_layout.addWidget(self.filter_combo)
        
        layout.addLayout(header_layout)
        
        # Tableau des appareils
        self.devices_table = QTableWidget()
        self.devices_table.setColumnCount(6)
        self.devices_table.setHorizontalHeaderLabels(["IP", "MAC", "Nom", "Type", "Fabricant", "Dernière activité"])
        self.devices_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.devices_table.horizontalHeader().setStretchLastSection(True)
        self.devices_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.devices_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.devices_table.doubleClicked.connect(self._show_device_details)
        
        layout.addWidget(self.devices_table)
        
        # Boutons d'action
        buttons_layout = QHBoxLayout()
        
        self.details_button = QPushButton("Détails")
        self.details_button.clicked.connect(self._show_device_details)
        buttons_layout.addWidget(self.details_button)
        
        self.edit_button = QPushButton("Modifier")
        self.edit_button.clicked.connect(self._edit_device)
        buttons_layout.addWidget(self.edit_button)
        
        self.scan_button = QPushButton("Scanner")
        self.scan_button.clicked.connect(self._scan_selected)
        buttons_layout.addWidget(self.scan_button)
        
        self.port_scan_button = QPushButton("Scan des ports")
        self.port_scan_button.clicked.connect(self._scan_ports_of_selected)
        buttons_layout.addWidget(self.port_scan_button)
        
        self.remove_button = QPushButton("Supprimer")
        self.remove_button.clicked.connect(self._remove_selected)
        buttons_layout.addWidget(self.remove_button)
        
        buttons_layout.addStretch(1)
        
        self.export_button = QPushButton("Exporter")
        self.export_button.clicked.connect(self._export_devices)
        buttons_layout.addWidget(self.export_button)
        
        layout.addLayout(buttons_layout)
    
    def _load_devices(self):
        """Charger les appareils depuis le fichier"""
        if os.path.exists(self.devices_file):
            try:
                with open(self.devices_file, 'r') as f:
                    self.devices = json.load(f)
                    self._update_devices_table()
                    logger.info(f"Chargement de {len(self.devices)} appareils depuis {self.devices_file}")
            except Exception as e:
                logger.error(f"Erreur lors du chargement des appareils: {e}")
                QMessageBox.warning(
                    self,
                    "Erreur de chargement",
                    f"Impossible de charger les appareils: {str(e)}"
                )
    
    def _save_devices(self):
        """Sauvegarder les appareils dans le fichier"""
        try:
            with open(self.devices_file, 'w') as f:
                json.dump(self.devices, f, indent=4)
                logger.info(f"Sauvegarde de {len(self.devices)} appareils dans {self.devices_file}")
        except Exception as e:
            logger.error(f"Erreur lors de la sauvegarde des appareils: {e}")
    
    def _update_devices_table(self):
        """Mettre à jour le tableau des appareils"""
        # Sauvegarder la sélection actuelle
        current_row = -1
        if self.devices_table.selectionModel().hasSelection():
            current_row = self.devices_table.selectionModel().selectedRows()[0].row()
        
        # Vider le tableau
        self.devices_table.setRowCount(0)
        
        # Remplir avec les appareils filtrés
        filtered_devices = self._get_filtered_devices()
        
        for ip, device in filtered_devices.items():
            row = self.devices_table.rowCount()
            self.devices_table.insertRow(row)
            
            self.devices_table.setItem(row, 0, QTableWidgetItem(ip))
            self.devices_table.setItem(row, 1, QTableWidgetItem(device.get('mac', '')))
            self.devices_table.setItem(row, 2, QTableWidgetItem(device.get('name', '')))
            self.devices_table.setItem(row, 3, QTableWidgetItem(device.get('type', '')))
            self.devices_table.setItem(row, 4, QTableWidgetItem(device.get('vendor', '')))
            self.devices_table.setItem(row, 5, QTableWidgetItem(device.get('last_seen', '')))
        
        # Restaurer la sélection si possible
        if current_row >= 0 and current_row < self.devices_table.rowCount():
            self.devices_table.selectRow(current_row)
        
        # Ajuster les colonnes
        self.devices_table.resizeColumnsToContents()
    
    def _get_filtered_devices(self) -> Dict:
        """Récupérer les appareils filtrés selon les critères de recherche"""
        search_text = self.search_field.text().lower()
        filter_type = self.filter_combo.currentText()
        
        filtered = {}
        
        for ip, device in self.devices.items():
            # Vérifier le texte de recherche
            if search_text:
                found = False
                # Chercher dans tous les champs textuels
                for field in ['ip', 'mac', 'name', 'type', 'vendor', 'description']:
                    if search_text in str(device.get(field, '')).lower():
                        found = True
                        break
                if not found:
                    continue
            
            # Vérifier le filtre de type
            if filter_type != "Tous":
                if filter_type == "En ligne":
                    if not device.get('online', False):
                        continue
                elif filter_type == "Hors ligne":
                    if device.get('online', False):
                        continue
                elif filter_type == "PC":
                    if device.get('type', '').lower() not in ['pc', 'ordinateur', 'desktop', 'laptop', 'serveur']:
                        continue
                elif filter_type == "Mobile":
                    if device.get('type', '').lower() not in ['smartphone', 'mobile', 'tablette', 'phone']:
                        continue
                elif filter_type == "IoT":
                    if device.get('type', '').lower() not in ['iot', 'domotique', 'smart device', 'object connecté']:
                        continue
                elif filter_type == "Réseau":
                    if device.get('type', '').lower() not in ['routeur', 'switch', 'hub', 'modem', 'ap', 'access point']:
                        continue
            
            # Ajouter à la liste filtrée
            filtered[ip] = device
            
        return filtered
    
    def _filter_devices(self):
        """Filtrer les appareils selon les critères de recherche"""
        self._update_devices_table()
    
    def _show_device_details(self):
        """Afficher les détails d'un appareil sélectionné"""
        selected_rows = self.devices_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.information(self, "Sélection", "Sélectionnez d'abord un appareil")
            return
            
        row = selected_rows[0].row()
        ip = self.devices_table.item(row, 0).text()
        
        if ip not in self.devices:
            QMessageBox.warning(self, "Erreur", f"Appareil {ip} introuvable")
            return
            
        # Afficher le dialogue de détails
        dialog = DeviceDetailsDialog(self.devices[ip], self)
        dialog.exec_()
    
    def _edit_device(self):
        """Modifier un appareil sélectionné"""
        selected_rows = self.devices_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.information(self, "Sélection", "Sélectionnez d'abord un appareil")
            return
            
        row = selected_rows[0].row()
        ip = self.devices_table.item(row, 0).text()
        
        if ip not in self.devices:
            QMessageBox.warning(self, "Erreur", f"Appareil {ip} introuvable")
            return
            
        # Afficher le dialogue de modification
        dialog = DeviceDetailsDialog(self.devices[ip], self, edit_mode=True)
        if dialog.exec_() == QDialog.Accepted:
            # Mettre à jour les données
            self.devices[ip] = dialog.get_updated_data()
            self._update_devices_table()
            self._save_devices()
    
    def _scan_selected(self):
        """Scanner un appareil sélectionné"""
        selected_rows = self.devices_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.information(self, "Sélection", "Sélectionnez d'abord un appareil")
            return
            
        row = selected_rows[0].row()
        ip = self.devices_table.item(row, 0).text()
        
        # Émettre le signal pour demander un scan
        self.scan_request.emit(ip)
    
    def _scan_ports_of_selected(self):
        """Scanner les ports d'un appareil sélectionné"""
        selected_rows = self.devices_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.information(self, "Sélection", "Sélectionnez d'abord un appareil")
            return
            
        row = selected_rows[0].row()
        ip = self.devices_table.item(row, 0).text()
        
        # Liste des ports communs à scanner
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 123, 143, 443,
            445, 993, 995, 3306, 3389, 5900, 8080, 8443
        ]
        
        # Émettre le signal pour demander un scan de ports
        self.port_scan_request.emit(ip, common_ports)
    
    def _remove_selected(self):
        """Supprimer un appareil sélectionné"""
        selected_rows = self.devices_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.information(self, "Sélection", "Sélectionnez d'abord un appareil")
            return
            
        row = selected_rows[0].row()
        ip = self.devices_table.item(row, 0).text()
        
        reply = QMessageBox.question(
            self,
            "Confirmation",
            f"Voulez-vous vraiment supprimer l'appareil {ip} de la liste?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            if ip in self.devices:
                del self.devices[ip]
                self._update_devices_table()
                self._save_devices()
    
    def _export_devices(self):
        """Exporter les appareils vers un fichier CSV ou JSON"""
        # Demander le type d'export
        export_type = QMessageBox.question(
            self,
            "Type d'export",
            "Comment souhaitez-vous exporter les appareils?",
            "CSV", "JSON"
        )
        
        # Demander le fichier de destination
        file_filter = "Fichiers CSV (*.csv)" if export_type == 0 else "Fichiers JSON (*.json)"
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Exporter les appareils",
            "",
            file_filter
        )
        
        if not file_path:
            return
            
        try:
            if export_type == 0:  # CSV
                with open(file_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(["IP", "MAC", "Nom", "Type", "Fabricant", "Description", "Emplacement", "Ports", "Dernière activité"])
                    
                    for ip, device in self.devices.items():
                        writer.writerow([
                            ip,
                            device.get('mac', ''),
                            device.get('name', ''),
                            device.get('type', ''),
                            device.get('vendor', ''),
                            device.get('description', ''),
                            device.get('location', ''),
                            ','.join(map(str, device.get('open_ports', []))),
                            device.get('last_seen', '')
                        ])
            else:  # JSON
                with open(file_path, 'w') as f:
                    json.dump(self.devices, f, indent=4)
                    
            QMessageBox.information(
                self,
                "Export réussi",
                f"Les appareils ont été exportés avec succès vers {file_path}"
            )
        except Exception as e:
            logger.error(f"Erreur lors de l'export des appareils: {e}")
            QMessageBox.warning(
                self,
                "Erreur d'export",
                f"Impossible d'exporter les appareils: {str(e)}"
            )
    
    def save_devices(self):
        """Sauvegarder explicitement les appareils"""
        self._save_devices()
        
    @pyqtSlot(dict)
    def add_device_from_scan(self, device_data: Dict):
        """Ajouter ou mettre à jour un appareil depuis un scan"""
        ip = device_data.get('ip')
        if not ip:
            logger.warning("Tentative d'ajout d'un appareil sans adresse IP")
            return
        
        # Mettre à jour un appareil existant ou en ajouter un nouveau
        if ip in self.devices:
            # Mettre à jour les champs sans écraser les données ajoutées par l'utilisateur
            for key, value in device_data.items():
                if key not in ['name', 'type', 'description', 'location'] or not self.devices[ip].get(key):
                    self.devices[ip][key] = value
        else:
            # Ajouter un nouvel appareil
            self.devices[ip] = device_data
            
        # Mettre à jour le champ "last_seen"
        self.devices[ip]['last_seen'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.devices[ip]['online'] = True
        
        # Mettre à jour l'interface
        self._update_devices_table()
        
        # Sauvegarder les changements
        self._save_devices()
    def _delete_all_devices(self):
        """Supprimer tous les appareils enregistrés"""
        if not self.devices:
            QMessageBox.information(self, "Information", "Aucun appareil à supprimer")
            return
        
        reply = QMessageBox.question(
        self,
        "Confirmation",
        f"Êtes-vous sûr de vouloir supprimer TOUS les appareils ({len(self.devices)}) ?",
        QMessageBox.Yes | QMessageBox.No,
        QMessageBox.No
        )
    
        if reply == QMessageBox.Yes:
            # Effacer le dictionnaire et le fichier
            self.devices.clear()
            self._save_devices()
            # Mettre à jour l'interface
            self.results_table.setRowCount(0)
            self.devices_count_label.setText("0 appareil(s) trouvé(s)")
            QMessageBox.information(self, "Succès", "Tous les appareils ont été supprimés")