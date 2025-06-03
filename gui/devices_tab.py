"""
Module for managing discovered network devices with white text message boxes
Current Date and Time (UTC): 2025-06-02 20:01:51
Current User's Login: AnoirELGUEDDAR
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
    QLineEdit, QDialog, QFormLayout
)
from PyQt5.QtCore import Qt, pyqtSignal, pyqtSlot, QTimer
from PyQt5.QtGui import QPalette, QColor

logger = logging.getLogger(__name__)

# Custom white text message box
class WhiteTextMessageBox(QMessageBox):
    """Message box with white text"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self._force_white_text()
    
    def _force_white_text(self):
        # Set white text palette
        palette = self.palette()
        palette.setColor(QPalette.WindowText, QColor(255, 255, 255))
        palette.setColor(QPalette.Text, QColor(255, 255, 255))
        palette.setColor(QPalette.ButtonText, QColor(255, 255, 255))
        self.setPalette(palette)
        
        # Apply white text stylesheet
        self.setStyleSheet("""
            QMessageBox {
                background-color: #1a2633;
                color: white;
            }
            
            QLabel {
                color: white;
            }
            
            QPushButton {
                color: white;
                background-color: #2c4a63;
                border: none;
                padding: 6px 12px;
                border-radius: 3px;
            }
            
            QPushButton:hover {
                background-color: #375a7f;
            }
        """)
        
        # Force attribute that ensures stylesheet applies correctly
        self.setAttribute(Qt.WA_StyledBackground, True)

# Custom information, warning, question message boxes
def show_information(parent, title, message):
    """Show information message box with white text"""
    msg_box = WhiteTextMessageBox(parent)
    msg_box.setIcon(QMessageBox.Information)
    msg_box.setWindowTitle(title)
    msg_box.setText(message)
    msg_box.setStandardButtons(QMessageBox.Ok)
    return msg_box.exec_()

def show_warning(parent, title, message):
    """Show warning message box with white text"""
    msg_box = WhiteTextMessageBox(parent)
    msg_box.setIcon(QMessageBox.Warning)
    msg_box.setWindowTitle(title)
    msg_box.setText(message)
    msg_box.setStandardButtons(QMessageBox.Ok)
    return msg_box.exec_()

def show_question(parent, title, message, default_button=QMessageBox.No):
    """Show question message box with white text"""
    msg_box = WhiteTextMessageBox(parent)
    msg_box.setIcon(QMessageBox.Question)
    msg_box.setWindowTitle(title)
    msg_box.setText(message)
    msg_box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
    msg_box.setDefaultButton(default_button)
    return msg_box.exec_()

class DeviceDetailsDialog(QDialog):
    def __init__(self, device_data: Dict, parent=None, edit_mode=False):
        super().__init__(parent)
        
        self.device_data = device_data.copy()
        self.edit_mode = edit_mode
        
        self.setWindowTitle("Détails de l'appareil" if not edit_mode else "Modifier l'appareil")
        self.resize(500, 400)
        
        self._setup_ui()
        self._force_white_text()  # Add white text fixing
        
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        form_layout = QFormLayout()
        
        self.ip_field = QLineEdit(self.device_data.get('ip', ''))
        self.ip_field.setReadOnly(True)
        form_layout.addRow("Adresse IP:", self.ip_field)
        
        self.mac_field = QLineEdit(self.device_data.get('mac', ''))
        self.mac_field.setReadOnly(not self.edit_mode or bool(self.device_data.get('mac', '')))
        form_layout.addRow("Adresse MAC:", self.mac_field)
        
        self.name_field = QLineEdit(self.device_data.get('name', ''))
        self.name_field.setReadOnly(not self.edit_mode)
        form_layout.addRow("Nom:", self.name_field)
        
        self.type_field = QLineEdit(self.device_data.get('type', ''))
        self.type_field.setReadOnly(not self.edit_mode)
        form_layout.addRow("Type d'appareil:", self.type_field)
        
        self.vendor_field = QLineEdit(self.device_data.get('vendor', ''))
        self.vendor_field.setReadOnly(not self.edit_mode)
        form_layout.addRow("Fabricant:", self.vendor_field)
        
        self.description_field = QLineEdit(self.device_data.get('description', ''))
        self.description_field.setReadOnly(not self.edit_mode)
        form_layout.addRow("Description:", self.description_field)
        
        self.location_field = QLineEdit(self.device_data.get('location', ''))
        self.location_field.setReadOnly(not self.edit_mode)
        form_layout.addRow("Emplacement:", self.location_field)
        
        ports_str = ', '.join(map(str, self.device_data.get('open_ports', [])))
        self.ports_field = QLineEdit(ports_str)
        self.ports_field.setReadOnly(True)
        form_layout.addRow("Ports ouverts:", self.ports_field)
        
        if self.device_data.get('last_seen'):
            last_seen_field = QLineEdit(self.device_data.get('last_seen', ''))
            last_seen_field.setReadOnly(True)
            form_layout.addRow("Dernière détection:", last_seen_field)
        
        layout.addLayout(form_layout)
        
        buttons_layout = QHBoxLayout()
        
        if self.edit_mode:
            save_button = QPushButton("Enregistrer")
            save_button.clicked.connect(self.accept)
            buttons_layout.addWidget(save_button)
        
        close_button = QPushButton("Fermer")
        close_button.clicked.connect(self.reject)
        buttons_layout.addWidget(close_button)
        
        layout.addLayout(buttons_layout)
        
    def _force_white_text(self):
        """Force white text on all elements in the dialog"""
        # Apply white text styling to the dialog
        self.setStyleSheet("""
            QDialog {
                background-color: #1a2633;
            }
            
            QLabel {
                color: white !important;
            }
            
            QLineEdit {
                color: white !important;
                background-color: #213243;
                border: 1px solid #324a5f;
            }
            
            QPushButton {
                color: white !important;
                background-color: #2c4a63;
                border: none;
                padding: 6px 12px;
            }
        """)
        
        # Set white text palette
        palette = self.palette()
        palette.setColor(QPalette.WindowText, QColor(255, 255, 255))
        palette.setColor(QPalette.Text, QColor(255, 255, 255))
        palette.setColor(QPalette.ButtonText, QColor(255, 255, 255))
        self.setPalette(palette)
        
        # Force white text for each field
        for field in [self.ip_field, self.mac_field, self.name_field, 
                     self.type_field, self.vendor_field, self.description_field,
                     self.location_field, self.ports_field]:
            field.setStyleSheet("color: white !important; background-color: #213243;")
            
            # Set palette for each field
            field_palette = field.palette()
            field_palette.setColor(QPalette.Text, QColor(255, 255, 255))
            field_palette.setColor(QPalette.HighlightedText, QColor(255, 255, 255))
            field.setPalette(field_palette)
    
    def get_updated_data(self) -> Dict:
        if not self.edit_mode:
            return self.device_data
            
        self.device_data['name'] = self.name_field.text()
        self.device_data['type'] = self.type_field.text()
        self.device_data['vendor'] = self.vendor_field.text()
        self.device_data['description'] = self.description_field.text()
        self.device_data['location'] = self.location_field.text()
        
        if not self.device_data.get('mac') and self.mac_field.text():
            self.device_data['mac'] = self.mac_field.text()
            
        return self.device_data


class DevicesTab(QWidget):
    scan_request = pyqtSignal(str)
    port_scan_request = pyqtSignal(str, list)
    
    def __init__(self):
        super().__init__()
        
        self.devices = {}
        self.devices_file = "devices.json"
        
        self._setup_ui()
        self._load_devices()
        
        self.save_timer = QTimer()
        self.save_timer.timeout.connect(self._save_devices)
        self.save_timer.start(60000)
        
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        
        header_layout = QHBoxLayout()
        
        header_label = QLabel("Appareils du Réseau")
        header_layout.addWidget(header_label)
        
        header_layout.addStretch(1)
        
        self.search_field = QLineEdit()
        self.search_field.setPlaceholderText("Rechercher par IP ou MAC...")
        self.search_field.setClearButtonEnabled(True)
        self.search_field.textChanged.connect(self._filter_devices)
        header_layout.addWidget(self.search_field)
        
        layout.addLayout(header_layout)
        
        self.devices_table = QTableWidget()
        self.devices_table.setColumnCount(6)
        self.devices_table.setHorizontalHeaderLabels(["IP", "MAC", "Nom", "Type", "Fabricant", "Dernière activité"])
        self.devices_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.devices_table.horizontalHeader().setStretchLastSection(True)
        self.devices_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.devices_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.devices_table.doubleClicked.connect(self._show_device_details)
        
        layout.addWidget(self.devices_table)
        
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
        
        self.delete_all_button = QPushButton("Supprimer tout")
        self.delete_all_button.clicked.connect(self._delete_all_devices)
        buttons_layout.addWidget(self.delete_all_button)
        
        buttons_layout.addStretch(1)
        
        self.export_button = QPushButton("Exporter")
        self.export_button.clicked.connect(self._export_devices)
        buttons_layout.addWidget(self.export_button)
        
        layout.addLayout(buttons_layout)
    
    def _load_devices(self):
        if os.path.exists(self.devices_file):
            try:
                with open(self.devices_file, 'r') as f:
                    self.devices = json.load(f)
                    self._update_devices_table()
                    logger.info(f"Chargement de {len(self.devices)} appareils depuis {self.devices_file}")
            except Exception as e:
                logger.error(f"Erreur lors du chargement des appareils: {e}")
                show_warning(self, "Erreur de chargement", f"Impossible de charger les appareils: {str(e)}")
    
    def _save_devices(self):
        try:
            with open(self.devices_file, 'w') as f:
                json.dump(self.devices, f, indent=4)
                logger.info(f"Sauvegarde de {len(self.devices)} appareils dans {self.devices_file}")
        except Exception as e:
            logger.error(f"Erreur lors de la sauvegarde des appareils: {e}")
    
    def _update_devices_table(self):
        current_row = -1
        if self.devices_table.selectionModel().hasSelection():
            current_row = self.devices_table.selectionModel().selectedRows()[0].row()
        
        self.devices_table.setRowCount(0)
        
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
        
        if current_row >= 0 and current_row < self.devices_table.rowCount():
            self.devices_table.selectRow(current_row)
        
        self.devices_table.resizeColumnsToContents()
    
    def _get_filtered_devices(self) -> Dict:
        search_text = self.search_field.text().lower()
        
        if not search_text:
            return self.devices
            
        filtered = {}
        for ip, device in self.devices.items():
            if (search_text in ip.lower() or 
                search_text in device.get('mac', '').lower()):
                filtered[ip] = device
                
        return filtered
    
    def _filter_devices(self):
        self._update_devices_table()
    
    def _show_device_details(self):
        selected_rows = self.devices_table.selectionModel().selectedRows()
        if not selected_rows:
            # Replace standard QMessageBox with our custom white text version
            show_information(self, "Sélection", "Sélectionnez d'abord un appareil")
            return
            
        row = selected_rows[0].row()
        ip = self.devices_table.item(row, 0).text()
        
        if ip not in self.devices:
            show_warning(self, "Erreur", f"Appareil {ip} introuvable")
            return
            
        dialog = DeviceDetailsDialog(self.devices[ip], self)
        dialog.exec_()
    
    def _edit_device(self):
        selected_rows = self.devices_table.selectionModel().selectedRows()
        if not selected_rows:
            show_information(self, "Sélection", "Sélectionnez d'abord un appareil")
            return
            
        row = selected_rows[0].row()
        ip = self.devices_table.item(row, 0).text()
        
        if ip not in self.devices:
            show_warning(self, "Erreur", f"Appareil {ip} introuvable")
            return
            
        dialog = DeviceDetailsDialog(self.devices[ip], self, edit_mode=True)
        if dialog.exec_() == QDialog.Accepted:
            self.devices[ip] = dialog.get_updated_data()
            self._update_devices_table()
            self._save_devices()
    
    def _scan_selected(self):
        selected_rows = self.devices_table.selectionModel().selectedRows()
        if not selected_rows:
            show_information(self, "Sélection", "Sélectionnez d'abord un appareil")
            return
            
        row = selected_rows[0].row()
        ip = self.devices_table.item(row, 0).text()
        self.scan_request.emit(ip)
    
    def _scan_ports_of_selected(self):
        selected_rows = self.devices_table.selectionModel().selectedRows()
        if not selected_rows:
            show_information(self, "Sélection", "Sélectionnez d'abord un appareil")
            return
            
        row = selected_rows[0].row()
        ip = self.devices_table.item(row, 0).text()
        
        common_ports = [21, 22, 23, 25, 53, 80, 110, 123, 143, 443, 445, 993, 995, 3306, 3389, 5900, 8080, 8443]
        self.port_scan_request.emit(ip, common_ports)
    
    def _remove_selected(self):
        selected_rows = self.devices_table.selectionModel().selectedRows()
        if not selected_rows:
            show_information(self, "Sélection", "Sélectionnez d'abord un appareil")
            return
            
        row = selected_rows[0].row()
        ip = self.devices_table.item(row, 0).text()
        
        reply = show_question(
            self, 
            "Confirmation", 
            f"Voulez-vous vraiment supprimer l'appareil {ip} de la liste?",
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            if ip in self.devices:
                del self.devices[ip]
                self._update_devices_table()
                self._save_devices()
    
    def _export_devices(self):
        msg_box = WhiteTextMessageBox(self)
        msg_box.setWindowTitle("Type d'export")
        msg_box.setText("Comment souhaitez-vous exporter les appareils?")
        csv_button = msg_box.addButton("CSV", QMessageBox.ActionRole)
        json_button = msg_box.addButton("JSON", QMessageBox.ActionRole)
        cancel_button = msg_box.addButton("Annuler", QMessageBox.RejectRole)
        msg_box.exec_()

        if msg_box.clickedButton() == csv_button:
            export_type = 0  # CSV
        elif msg_box.clickedButton() == json_button:
            export_type = 1  # JSON
        else:
            return  # User cancelled
        
        file_filter = "Fichiers CSV (*.csv)" if export_type == 0 else "Fichiers JSON (*.json)"
        file_path, _ = QFileDialog.getSaveFileName(self, "Exporter les appareils", "", file_filter)
        
        if not file_path:
            return
            
        try:
            if export_type == 0:
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
            else:
                with open(file_path, 'w') as f:
                    json.dump(self.devices, f, indent=4)
                    
            show_information(self, "Export réussi", 
                           f"Les appareils ont été exportés avec succès vers {file_path}")
        except Exception as e:
            logger.error(f"Erreur lors de l'export des appareils: {e}")
            show_warning(self, "Erreur d'export", 
                      f"Impossible d'exporter les appareils: {str(e)}")
    
    def save_devices(self):
        self._save_devices()
        
    @pyqtSlot(dict)
    def add_device_from_scan(self, device_data: Dict):
        ip = device_data.get('ip')
        if not ip:
            logger.warning("Tentative d'ajout d'un appareil sans adresse IP")
            return
        
        if ip in self.devices:
            for key, value in device_data.items():
                if key not in ['name', 'type', 'description', 'location'] or not self.devices[ip].get(key):
                    self.devices[ip][key] = value
        else:
            self.devices[ip] = device_data
            
        self.devices[ip]['last_seen'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.devices[ip]['online'] = True
        
        self._update_devices_table()
        self._save_devices()

    def _delete_all_devices(self):
        if not self.devices:
            show_information(self, "Information", "Aucun appareil à supprimer")
            return
        
        reply = show_question(
            self, 
            "Confirmation",
            f"Êtes-vous sûr de vouloir supprimer TOUS les appareils ({len(self.devices)}) ?",
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.devices.clear()
            self._save_devices()
            self._update_devices_table()
            show_information(self, "Succès", "Tous les appareils ont été supprimés")