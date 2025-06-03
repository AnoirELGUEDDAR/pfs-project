"""
File Browser Dialog for remote devices
"""
import os
import logging
import threading
from datetime import datetime

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QLineEdit, QComboBox, QHeaderView, QMessageBox,
    QMenu, QFileDialog, QInputDialog, QLabel
)
from PyQt5.QtCore import Qt, pyqtSignal, QTimer
from PyQt5.QtGui import QIcon, QColor, QBrush

logger = logging.getLogger(__name__)

class FileBrowserDialog(QDialog):
    """Dialog for browsing files on a remote device"""
    
    def __init__(self, parent, device_manager, device_id):
        super().__init__(parent)
        self.device_manager = device_manager
        self.device_id = device_id
        
        # Get device info
        if device_id in self.device_manager.devices:
            self.device_info = self.device_manager.devices[device_id]
            self.device_name = self.device_info.get("name", "Unknown Device")
            # Improved Windows detection
            self.is_windows = "windows" in str(self.device_info.get("platform", "")).lower() or "WIN" in self.device_name.upper()
            
            # Debug logging
            logger.info(f"Platform info: {self.device_info.get('platform')}")
            logger.info(f"Device name: {self.device_name}")
            logger.info(f"Is Windows: {self.is_windows}")
        else:
            self.device_info = {}
            self.device_name = "Unknown Device"
            self.is_windows = False
        
        # Set the correct initial path based on the system
        self.current_path = "C:\\" if self.is_windows else "/"
        
        # Create a dedicated downloads folder in the user's Documents
        self.downloads_folder = os.path.join(os.path.expanduser("~"), "Documents", "RemoteAgentDownloads")
        if not os.path.exists(self.downloads_folder):
            try:
                os.makedirs(self.downloads_folder)
                logger.info(f"Created downloads folder: {self.downloads_folder}")
            except Exception as e:
                logger.error(f"Failed to create downloads folder: {e}")
                self.downloads_folder = os.path.join(os.path.expanduser("~"), "Documents")  # fallback to Documents directory
                
        # Setup UI
        self.setWindowTitle(f"Explorateur de Fichiers - {self.device_name}")
        self.resize(800, 600)
        self._setup_ui()
        
        # Initial directory listing
        self._refresh_directory()
        
    def _setup_ui(self):
        """Setup the UI components"""
        layout = QVBoxLayout(self)
        
        # Path navigation
        nav_layout = QHBoxLayout()
        
        # Common paths dropdown
        self.paths_combo = QComboBox()
        if self.is_windows:
            logger.info("Using Windows paths for dropdown")
            self.paths_combo.addItems(["C:\\", "C:\\Users", "C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)"])
        else:
            logger.info("Using Linux paths for dropdown")
            self.paths_combo.addItems(["/", "/home", "/usr", "/etc", "/var", "/tmp"])
        self.paths_combo.currentTextChanged.connect(self._on_path_changed)
        nav_layout.addWidget(self.paths_combo)
        
        # Path bar
        self.path_edit = QLineEdit(self.current_path)
        self.path_edit.returnPressed.connect(self._on_path_entered)
        nav_layout.addWidget(self.path_edit, 1)
        
        # Go button
        self.go_button = QPushButton("Aller")
        self.go_button.clicked.connect(self._on_path_entered)
        nav_layout.addWidget(self.go_button)
        
        # Refresh button
        self.refresh_button = QPushButton("Rafraîchir")
        self.refresh_button.clicked.connect(self._refresh_directory)
        nav_layout.addWidget(self.refresh_button)
        
        layout.addLayout(nav_layout)
        
        # Files table
        self.files_table = QTableWidget(0, 4)
        self.files_table.setHorizontalHeaderLabels(["Nom", "Taille", "Type", "Modifié"])
        self.files_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.files_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.files_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.files_table.customContextMenuRequested.connect(self._show_context_menu)
        self.files_table.doubleClicked.connect(self._on_item_double_clicked)
        
        layout.addWidget(self.files_table)
        
        # Status label
        self.status_label = QLabel("Prêt")
        layout.addWidget(self.status_label)
        
        # Bottom buttons
        buttons_layout = QHBoxLayout()
        
        self.upload_button = QPushButton("Envoyer un Fichier")
        self.upload_button.clicked.connect(self._upload_file)
        buttons_layout.addWidget(self.upload_button)
        
        self.download_button = QPushButton("Télécharger")
        self.download_button.clicked.connect(self._download_file)
        buttons_layout.addWidget(self.download_button)
        
        self.mkdir_button = QPushButton("Nouveau Dossier")
        self.mkdir_button.clicked.connect(self._create_directory)
        buttons_layout.addWidget(self.mkdir_button)
        
        self.delete_button = QPushButton("Supprimer")
        self.delete_button.clicked.connect(self._delete_selected)
        buttons_layout.addWidget(self.delete_button)
        
        self.close_button = QPushButton("Fermer")
        self.close_button.clicked.connect(self.close)
        buttons_layout.addWidget(self.close_button)
        
        layout.addLayout(buttons_layout)
    
    def _on_path_changed(self, path):
        """Handle path changed in dropdown"""
        self.path_edit.setText(path)
        self._refresh_directory()
    
    def _on_path_entered(self):
        """Handle path entered manually"""
        new_path = self.path_edit.text()
        # Ensure path has trailing slash for Windows or Linux
        if self.is_windows:
            if not new_path.endswith('\\'):
                new_path += '\\'
        else:
            if not new_path.endswith('/'):
                new_path += '/'
                
        self.current_path = new_path
        self._refresh_directory()
    
    def _refresh_directory(self):
        """Refresh the current directory listing"""
        self.status_label.setText("Chargement...")
        logger.info(f"Listing files in: {self.current_path}")
        
        def worker_thread():
            try:
                # For Windows, use proper command escaping
                if self.is_windows:
                    files = self._list_files_windows()
                else:
                    # Use standard method for non-Windows systems
                    files = self.device_manager.list_files(self.device_id, self.current_path)
                
                # Update UI in main thread
                QTimer.singleShot(0, lambda: self._update_files_list(files if files else []))
            except Exception as e:
                logger.error(f"Error listing files: {e}")
                QTimer.singleShot(0, lambda: self._show_error(str(e)))
        
        threading.Thread(target=worker_thread, daemon=True).start()
    
    def _list_files_windows(self):
        """List files on Windows using PowerShell"""
        try:
            # Properly escape path for PowerShell
            escaped_path = self.current_path.replace('\\', '\\\\')
            
            # Try PowerShell first (most reliable)
            ps_cmd = f'powershell -Command "Get-ChildItem -Path \'{escaped_path}\' -Force | Select-Object Name, @{{Name=\'Size\';Expression={{$_.Length}}}}, @{{Name=\'IsDirectory\';Expression={{$_.PSIsContainer}}}}, @{{Name=\'LastWriteTime\';Expression={{$_.LastWriteTime}}}} | ConvertTo-Json"'
            
            result = self.device_manager.execute_command(self.device_id, ps_cmd)
            if result and "{" in result:
                # Try to parse JSON
                import json
                try:
                    # Clean the result in case there's extra text
                    json_start = result.find('[')
                    json_end = result.rfind(']') + 1
                    if json_start >= 0 and json_end > json_start:
                        json_text = result[json_start:json_end]
                        data = json.loads(json_text)
                        
                        # Convert to our format
                        files = []
                        for item in data:
                            files.append({
                                'name': item.get('Name', ''),
                                'is_dir': item.get('IsDirectory', False),
                                'size': item.get('Size', 0) or 0,  # Handle None values
                                'modified': str(item.get('LastWriteTime', ''))
                            })
                        return files
                except Exception as e:
                    logger.error(f"Error parsing PowerShell JSON: {e}")
            
            # If PowerShell fails, try simpler commands
            # Method 2: Use cmd dir with special formatting
            cmd_path = self.current_path
            if cmd_path.endswith('\\'):
                cmd_path = cmd_path[:-1]
            
            cmd = f'cmd /c "dir /a "{cmd_path}""'
            result = self.device_manager.execute_command(self.device_id, cmd)
            
            # Parse dir output
            files = []
            if result:
                lines = result.strip().split('\n')
                for line in lines[5:]:  # Skip header lines
                    line = line.strip()
                    if not line or 'bytes free' in line or '<DIR>' not in line and '/' not in line:
                        continue
                    
                    try:
                        is_dir = '<DIR>' in line
                        
                        # Parse the line based on dir's format
                        if is_dir:
                            parts = line.split('<DIR>')
                            date_part = parts[0].strip()
                            name_part = parts[1].strip()
                            size = 0
                        else:
                            parts = line.split(' ')
                            date_part = ' '.join(parts[:2])
                            
                            # Find size which is a numeric field
                            size_part = None
                            name_start_idx = 0
                            for i, part in enumerate(parts):
                                if part.strip() and part.strip().replace(',', '').isdigit():
                                    size_part = part.strip().replace(',', '')
                                    name_start_idx = i + 1
                                    break
                            
                            size = int(size_part) if size_part else 0
                            name_part = ' '.join(parts[name_start_idx:]).strip()
                        
                        # Skip . and .. entries
                        if name_part in ['.', '..']:
                            continue
                        
                        files.append({
                            'name': name_part,
                            'is_dir': is_dir,
                            'size': size,
                            'modified': date_part
                        })
                    except Exception as e:
                        logger.error(f"Error parsing dir line: {line} - {e}")
            
            return files
        except Exception as e:
            logger.error(f"Error in Windows file listing: {e}")
            return []
    
    def _update_files_list(self, files):
        """Update the files table with the directory listing"""
        if files is None:
            self.status_label.setText("Erreur: Impossible de lister les fichiers")
            return
            
        # Clear table
        self.files_table.setRowCount(0)
        
        # Add parent directory entry if not at root
        if self.is_windows:
            is_root = self.current_path.rstrip('\\').endswith(':')
        else:
            is_root = self.current_path == "/"
            
        if not is_root:
            row = self.files_table.rowCount()
            self.files_table.insertRow(row)
            
            # Create name item with blue color for directory
            name_item = QTableWidgetItem("..")
            name_item.setForeground(QBrush(QColor("blue")))
            
            self.files_table.setItem(row, 0, name_item)
            self.files_table.setItem(row, 1, QTableWidgetItem(""))
            self.files_table.setItem(row, 2, QTableWidgetItem("Dossier parent"))
            self.files_table.setItem(row, 3, QTableWidgetItem(""))
            
            # Store directory flag
            name_item.setData(Qt.UserRole, {
                "is_dir": True,
                "name": "..",
                "path": self._get_parent_path(),
                "size": 0
            })
        
        # Sort files - directories first, then files
        sorted_files = sorted(files, key=lambda x: (not x.get('is_dir', False), x.get('name', '').lower()))
        
        # Add files and directories
        for file_info in sorted_files:
            row = self.files_table.rowCount()
            self.files_table.insertRow(row)
            
            name = file_info.get('name', '')
            size = file_info.get('size', 0)
            is_dir = file_info.get('is_dir', False)
            modified = file_info.get('modified', '')
            
            # Format size
            if is_dir:
                size_str = ""
                type_str = "Dossier"
            else:
                if size < 1024:
                    size_str = f"{size} o"
                elif size < 1024 * 1024:
                    size_str = f"{size/1024:.1f} Ko"
                elif size < 1024 * 1024 * 1024:
                    size_str = f"{size/1024/1024:.1f} Mo"
                else:
                    size_str = f"{size/1024/1024/1024:.1f} Go"
                
                # Try to determine file type
                if name.endswith('.txt'):
                    type_str = "Fichier texte"
                elif name.endswith(('.jpg', '.jpeg', '.png', '.gif', '.bmp')):
                    type_str = "Image"
                elif name.endswith(('.mp3', '.wav', '.ogg')):
                    type_str = "Audio"
                elif name.endswith(('.mp4', '.avi', '.mkv')):
                    type_str = "Vidéo"
                elif name.endswith(('.pdf')):
                    type_str = "PDF"
                elif name.endswith(('.zip', '.tar', '.gz', '.7z', '.rar')):
                    type_str = "Archive"
                elif name.endswith(('.exe', '.msi')):
                    type_str = "Exécutable"
                elif name.endswith(('.doc', '.docx')):
                    type_str = "Document Word"
                elif name.endswith(('.xls', '.xlsx')):
                    type_str = "Feuille Excel"
                elif name.endswith(('.ppt', '.pptx')):
                    type_str = "Présentation"
                else:
                    type_str = "Fichier"
            
            # Create name item
            name_item = QTableWidgetItem(name)
            if is_dir:
                name_item.setForeground(QBrush(QColor("blue")))
            
            self.files_table.setItem(row, 0, name_item)
            self.files_table.setItem(row, 1, QTableWidgetItem(size_str))
            self.files_table.setItem(row, 2, QTableWidgetItem(type_str))
            self.files_table.setItem(row, 3, QTableWidgetItem(modified))
            
            # Store metadata for quick access
            file_path = self._join_path(self.current_path, name)
            name_item.setData(Qt.UserRole, {
                "is_dir": is_dir,
                "name": name,
                "path": file_path,
                "size": size
            })
            
        self.status_label.setText(f"{self.files_table.rowCount()} élément(s)")
    
    def _join_path(self, path, name):
        """Join path and name properly based on OS"""
        if self.is_windows:
            # Handle Windows paths
            return os.path.join(path, name).replace('/', '\\')
        else:
            # Handle Unix paths
            return os.path.join(path, name).replace('\\', '/')
    
    def _get_parent_path(self):
        """Get parent directory path"""
        if self.is_windows:
            # Handle Windows paths
            if self.current_path.rstrip('\\').endswith(':'):
                # Root of a drive, nowhere to go up
                return self.current_path
            else:
                path = self.current_path.rstrip('\\')
                parent = os.path.dirname(path)
                if parent.endswith(':'):
                    parent += '\\'
                return parent
        else:
            # Handle Unix paths
            if self.current_path == "/":
                return "/"
            else:
                return os.path.dirname(self.current_path.rstrip("/")) + "/"
    
    def _on_item_double_clicked(self, index):
        """Handle double click on item"""
        row = index.row()
        item = self.files_table.item(row, 0)
        if item:
            data = item.data(Qt.UserRole)
            if data["is_dir"]:
                # Navigate to directory
                self.current_path = data["path"]
                self.path_edit.setText(self.current_path)
                self._refresh_directory()
                
                # Log the navigation
                logger.info(f"Navigating to: {self.current_path}")
    
    def _show_context_menu(self, position):
        """Show context menu for file operations"""
        selected_rows = self.files_table.selectionModel().selectedRows()
        if not selected_rows:
            return
            
        row = selected_rows[0].row()
        item = self.files_table.item(row, 0)
        if not item:
            return
            
        data = item.data(Qt.UserRole)
        if not data:
            return
        
        menu = QMenu()
        
        if data["is_dir"]:
            open_action = menu.addAction("Ouvrir")
            open_action.triggered.connect(lambda: self._on_item_double_clicked(selected_rows[0]))
        else:
            download_action = menu.addAction("Télécharger")
            download_action.triggered.connect(self._download_file)
        
        # Don't allow deletion of parent directory
        if data["name"] != "..":
            delete_action = menu.addAction("Supprimer")
            delete_action.triggered.connect(self._delete_selected)
        
        menu.exec_(self.files_table.viewport().mapToGlobal(position))
    
    def _show_error(self, message):
        """Show error message"""
        QMessageBox.warning(self, "Erreur", f"Une erreur s'est produite:\n{message}")
        self.status_label.setText("Erreur")
    
    def _upload_file(self):
        """Upload a file to the current directory"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Sélectionner un fichier à envoyer", "", "Tous les fichiers (*)"
        )
        
        if not file_path:
            return
            
        self.status_label.setText(f"Envoi de {os.path.basename(file_path)}...")
        
        def worker_thread():
            try:
                success = self.device_manager.send_file(self.device_id, file_path, self.current_path)
                
                if success:
                    QTimer.singleShot(0, lambda: self._show_upload_success(file_path))
                else:
                    QTimer.singleShot(0, lambda: self._show_error("Échec de l'envoi du fichier"))
            except Exception as e:
                logger.error(f"Error uploading file: {e}")
                QTimer.singleShot(0, lambda: self._show_error(str(e)))
        
        threading.Thread(target=worker_thread, daemon=True).start()
    
    def _show_upload_success(self, file_path):
        """Show upload success message and refresh directory"""
        self.status_label.setText("Fichier envoyé avec succès")
        QMessageBox.information(
            self, "Succès", f"Le fichier {os.path.basename(file_path)} a été envoyé avec succès"
        )
        self._refresh_directory()
    
    def _download_file(self):
        """Download selected file"""
        selected_rows = self.files_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.information(self, "Information", "Sélectionnez d'abord un fichier")
            return
            
        row = selected_rows[0].row()
        item = self.files_table.item(row, 0)
        if not item:
            return
            
        data = item.data(Qt.UserRole)
        if not data or data["is_dir"]:
            QMessageBox.information(self, "Information", "Sélectionnez un fichier pour le télécharger (pas un dossier)")
            return
        
        # Get save location - use the dedicated downloads folder as default
        default_save_path = os.path.join(self.downloads_folder, data["name"])
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Enregistrer le fichier sous", default_save_path, "Tous les fichiers (*)"
        )
        
        if not file_path:
            return
            
        self.status_label.setText(f"Téléchargement de {data['name']}...")
        
        def worker_thread():
            try:
                # Make sure the directory exists
                save_dir = os.path.dirname(file_path)
                if save_dir and not os.path.exists(save_dir):
                    try:
                        os.makedirs(save_dir)
                    except Exception as e:
                        logger.error(f"Error creating directory: {e}")
                        # Try using downloads folder as fallback
                        file_path = os.path.join(self.downloads_folder, data["name"])
                        
                success = self.device_manager.download_file(self.device_id, data["path"], file_path)
                
                if success:
                    QTimer.singleShot(0, lambda: self._show_download_success(data["name"], file_path))
                else:
                    QTimer.singleShot(0, lambda: self._show_error("Échec du téléchargement du fichier"))
            except Exception as e:
                logger.error(f"Error downloading file: {e}")
                QTimer.singleShot(0, lambda: self._show_error(str(e)))
        
        threading.Thread(target=worker_thread, daemon=True).start()
    
    def _show_download_success(self, file_name, file_path):
        """Show download success message"""
        self.status_label.setText("Fichier téléchargé avec succès")
        
        message = f"Le fichier {file_name} a été téléchargé avec succès"
        message += f"\n\nChemin: {file_path}"
        
        QMessageBox.information(self, "Succès", message)
    
    def _create_directory(self):
        """Create new directory"""
        dir_name, ok = QInputDialog.getText(
            self, "Nouveau dossier", "Nom du dossier:"
        )
        
        if not ok or not dir_name:
            return
            
        dir_path = self._join_path(self.current_path, dir_name)
        self.status_label.setText(f"Création du dossier {dir_name}...")
        
        def worker_thread():
            try:
                if self.is_windows:
                    cmd = f'mkdir "{dir_path}"'
                else:
                    cmd = f'mkdir -p "{dir_path}"'
                    
                result = self.device_manager.execute_command(self.device_id, cmd)
                
                # Refresh directory after creating folder
                QTimer.singleShot(0, self._refresh_directory)
                QTimer.singleShot(0, lambda: self.status_label.setText("Dossier créé"))
            except Exception as e:
                logger.error(f"Error creating directory: {e}")
                QTimer.singleShot(0, lambda: self._show_error(str(e)))
        
        threading.Thread(target=worker_thread, daemon=True).start()
    
    def _delete_selected(self):
        """Delete selected file or directory"""
        selected_rows = self.files_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.information(self, "Information", "Sélectionnez d'abord un élément")
            return
            
        row = selected_rows[0].row()
        item = self.files_table.item(row, 0)
        if not item:
            return
            
        data = item.data(Qt.UserRole)
        if not data or data["name"] == "..":
            return
        
        # Confirm deletion
        msg_type = "dossier" if data["is_dir"] else "fichier"
        reply = QMessageBox.question(
            self,
            "Confirmation",
            f"Voulez-vous vraiment supprimer le {msg_type} {data['name']}?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply != QMessageBox.Yes:
            return
            
        self.status_label.setText(f"Suppression de {data['name']}...")
        
        def worker_thread():
            try:
                if self.is_windows:
                    if data["is_dir"]:
                        cmd = f'rmdir /s /q "{data["path"]}"'
                    else:
                        cmd = f'del /f /q "{data["path"]}"'
                else:
                    if data["is_dir"]:
                        cmd = f'rm -rf "{data["path"]}"'
                    else:
                        cmd = f'rm -f "{data["path"]}"'
                        
                result = self.device_manager.execute_command(self.device_id, cmd)
                
                # Refresh directory after deleting
                QTimer.singleShot(0, self._refresh_directory)
                QTimer.singleShot(0, lambda: self.status_label.setText("Élément supprimé"))
            except Exception as e:
                logger.error(f"Error deleting: {e}")
                QTimer.singleShot(0, lambda: self._show_error(str(e)))
        
        threading.Thread(target=worker_thread, daemon=True).start()