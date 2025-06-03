"""
Files Tab for file transfer and management
Current Date: 2025-05-10 12:02:05
Author: AnoirELGUEDDAR
"""
import os
import logging
from datetime import datetime
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView, QComboBox,
    QLineEdit, QFileDialog, QMessageBox, QProgressBar,
    QGroupBox, QFormLayout, QMenu, QCheckBox, QSplitter,
    QTreeView, QToolBar
)
from PyQt5.QtCore import Qt, QSize, pyqtSignal, QThread, pyqtSlot, QTimer
from PyQt5.QtGui import QIcon, QStandardItemModel, QStandardItem

from core.file_transfer.file_transfer_thread import FileTransferThread, TransferType
from core.messaging.message import Message, MessageType

logger = logging.getLogger(__name__)

class FilesTab(QWidget):
    """Files Tab for file transfer and management"""
    
    # Custom signals
    file_transfer_started = pyqtSignal(str, str, int)  # filename, destination, size
    file_transfer_progress = pyqtSignal(str, int)  # filename, progress percentage
    file_transfer_completed = pyqtSignal(str, bool, str)  # filename, success, message
    
    def __init__(self, device_manager, file_service, message_service):
        """Initialize the Files Tab"""
        super().__init__()
        
        self.device_manager = device_manager
        self.file_service = file_service
        self.message_service = message_service
        
        # Track active transfers
        self.active_transfers = {}  # {filename: transfer_thread}
        
        # Setup the UI
        self._setup_ui()
        
        # Connect signals
        if self.message_service:
            self.message_service.message_received.connect(self._on_message_received)
            
        # Initialize file list timer for periodic refresh
        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self._refresh_files_list)
        self.refresh_timer.start(30000)  # Refresh every 30 seconds
        
        logger.info("Files Tab initialized")
        
    def _setup_ui(self):
        """Setup the user interface"""
        # Main layout
        main_layout = QVBoxLayout(self)
        
        # Toolbar
        toolbar = QToolBar("File Actions")
        toolbar.setIconSize(QSize(16, 16))
        
        # Toolbar actions
        upload_action = QPushButton("Upload")
        upload_action.clicked.connect(self._upload_file)
        toolbar.addWidget(upload_action)
        
        download_action = QPushButton("Download")
        download_action.clicked.connect(self._download_selected)
        toolbar.addWidget(download_action)
        
        toolbar.addSeparator()
        
        refresh_action = QPushButton("Refresh")
        refresh_action.clicked.connect(self._refresh_files_list)
        toolbar.addWidget(refresh_action)
        
        # Device selector
        self.device_selector = QComboBox()
        self.device_selector.setMinimumWidth(200)
        self.device_selector.currentIndexChanged.connect(self._device_changed)
        toolbar.addWidget(QLabel("Device:"))
        toolbar.addWidget(self.device_selector)
        
        # Add search box
        toolbar.addSeparator()
        toolbar.addWidget(QLabel("Search:"))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search files...")
        self.search_input.returnPressed.connect(self.search_files)
        toolbar.addWidget(self.search_input)
        
        search_button = QPushButton("Search")
        search_button.clicked.connect(self.search_files)
        toolbar.addWidget(search_button)
        
        main_layout.addWidget(toolbar)
        
        # Main splitter widget
        splitter = QSplitter(Qt.Horizontal)
        
        # Left side: Device file system
        file_system_group = QGroupBox("Remote File System")
        file_system_layout = QVBoxLayout(file_system_group)
        
        # Path navigation
        path_layout = QHBoxLayout()
        self.path_label = QLabel("Path: /")
        path_layout.addWidget(self.path_label)
        
        self.up_button = QPushButton("Up")
        self.up_button.clicked.connect(self._go_up_directory)
        path_layout.addWidget(self.up_button)
        
        file_system_layout.addLayout(path_layout)
        
        # File list
        self.file_list = QTableWidget(0, 4)
        self.file_list.setHorizontalHeaderLabels(["Name", "Size", "Modified", "Type"])
        self.file_list.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.file_list.setSelectionBehavior(QTableWidget.SelectRows)
        self.file_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.file_list.customContextMenuRequested.connect(self._show_context_menu)
        self.file_list.doubleClicked.connect(self._on_file_double_clicked)
        file_system_layout.addWidget(self.file_list)
        
        splitter.addWidget(file_system_group)
        
        # Right side: Transfers and shared files
        transfers_group = QGroupBox("File Transfers")
        transfers_layout = QVBoxLayout(transfers_group)
        
        # Active transfers
        self.transfers_table = QTableWidget(0, 4)
        self.transfers_table.setHorizontalHeaderLabels(["Filename", "Target", "Progress", "Status"])
        self.transfers_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        transfers_layout.addWidget(self.transfers_table)
        
        # Shared files
        shared_group = QGroupBox("Shared Files")
        shared_layout = QVBoxLayout(shared_group)
        
        # TODO: Implement shared files UI
        self.shared_list = QTableWidget(0, 3)
        self.shared_list.setHorizontalHeaderLabels(["Filename", "Shared With", "Access"])
        self.shared_list.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        shared_layout.addWidget(self.shared_list)
        
        # Add buttons for shared files
        shared_buttons = QHBoxLayout()
        
        share_button = QPushButton("Share Files")
        share_button.clicked.connect(self._share_files)
        shared_buttons.addWidget(share_button)
        
        unshare_button = QPushButton("Stop Sharing")
        unshare_button.clicked.connect(self._unshare_files)
        shared_buttons.addWidget(unshare_button)
        
        shared_layout.addLayout(shared_buttons)
        
        # Add shared group to transfers layout
        transfers_layout.addWidget(shared_group)
        
        splitter.addWidget(transfers_group)
        
        # Set initial splitter sizes
        splitter.setSizes([500, 500])
        
        main_layout.addWidget(splitter)
        
        # Status bar
        status_layout = QHBoxLayout()
        self.status_label = QLabel("Ready")
        status_layout.addWidget(self.status_label, 1)
        main_layout.addLayout(status_layout)
        
        # Populate device selector
        self._populate_device_selector()
        
    def _populate_device_selector(self):
        """Populate the device selector with available devices"""
        self.device_selector.clear()
        
        # Add local system
        self.device_selector.addItem("Local System", "local")
        
        # Add remote devices if device manager is available
        if self.device_manager:
            devices = self.device_manager.get_devices()
            for device_id, device_info in devices.items():
                display_name = f"{device_info.get('name', 'Unknown')} ({device_info.get('ip', 'Unknown IP')})"
                self.device_selector.addItem(display_name, device_id)
        
        # If no devices found, disable controls
        if self.device_selector.count() <= 1:
            self.status_label.setText("No remote devices available")
        else:
            self.status_label.setText(f"{self.device_selector.count() - 1} remote devices available")
    
    def _device_changed(self, index):
        """Handle device selection change"""
        device_id = self.device_selector.itemData(index)
        
        if device_id == "local":
            # Show local files
            self._show_local_files()
        else:
            # Show remote files for the selected device
            self._show_remote_files(device_id)
    
    def _show_local_files(self, path=None):
        """Display local files in the file list"""
        if path is None:
            path = os.path.expanduser("~")  # Default to user home
        
        try:
            # Update path label
            self.path_label.setText(f"Path: {path}")
            self.current_path = path
            self.current_device = "local"
            
            # Clear the file list
            self.file_list.setRowCount(0)
            
            # Populate with files and directories
            files = os.listdir(path)
            
            row = 0
            for file in files:
                full_path = os.path.join(path, file)
                
                # Skip hidden files
                if file.startswith('.') and not os.path.isdir(full_path):
                    continue
                
                # Get file info
                try:
                    stat_info = os.stat(full_path)
                    size = stat_info.st_size
                    modified = datetime.fromtimestamp(stat_info.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                    
                    # Determine type
                    if os.path.isdir(full_path):
                        type_str = "Directory"
                        size_str = "--"
                    else:
                        # Get file extension
                        _, ext = os.path.splitext(file)
                        type_str = ext[1:].upper() if ext else "File"
                        
                        # Format size
                        if size < 1024:
                            size_str = f"{size} B"
                        elif size < 1024 * 1024:
                            size_str = f"{size/1024:.1f} KB"
                        elif size < 1024 * 1024 * 1024:
                            size_str = f"{size/(1024*1024):.1f} MB"
                        else:
                            size_str = f"{size/(1024*1024*1024):.1f} GB"
                    
                    # Add to table
                    self.file_list.insertRow(row)
                    self.file_list.setItem(row, 0, QTableWidgetItem(file))
                    self.file_list.setItem(row, 1, QTableWidgetItem(size_str))
                    self.file_list.setItem(row, 2, QTableWidgetItem(modified))
                    self.file_list.setItem(row, 3, QTableWidgetItem(type_str))
                    
                    # Store full path as data
                    self.file_list.item(row, 0).setData(Qt.UserRole, full_path)
                    
                    row += 1
                except (PermissionError, FileNotFoundError):
                    # Skip files we can't access
                    continue
            
            self.status_label.setText(f"Displaying {row} items from local system")
            
        except Exception as e:
            self.status_label.setText(f"Error loading files: {str(e)}")
            logger.error(f"Error loading local files: {str(e)}")
    
    def _show_remote_files(self, device_id, path=None):
        """Display remote files from the selected device"""
        if path is None:
            path = "/"  # Default to root
            
        # Update state
        self.current_path = path
        self.current_device = device_id
        self.path_label.setText(f"Path: {path}")
        
        # Clear the file list
        self.file_list.setRowCount(0)
        
        # Use device manager to get file list
        if self.device_manager:
            try:
                # Request file listing from device
                self.status_label.setText(f"Requesting file listing from {device_id}...")
                
                # This would be implemented to communicate with the remote device
                # For now, show a placeholder message
                self.status_label.setText(f"Remote file browsing not fully implemented for {device_id}")
                
                # Add some placeholder files for demonstration
                self._add_demo_remote_files()
                
            except Exception as e:
                self.status_label.setText(f"Error: {str(e)}")
                logger.error(f"Error getting remote files: {str(e)}")
        else:
            self.status_label.setText("Device manager not available")
    
    def _add_demo_remote_files(self):
        """Add demo remote files for demonstration"""
        demo_files = [
            {"name": "Documents", "size": "--", "modified": "2025-04-15 10:23:45", "type": "Directory"},
            {"name": "Downloads", "size": "--", "modified": "2025-05-01 15:42:32", "type": "Directory"},
            {"name": "report.pdf", "size": "2.4 MB", "modified": "2025-05-08 09:12:35", "type": "PDF"},
            {"name": "data.xlsx", "size": "352.1 KB", "modified": "2025-05-07 14:22:18", "type": "XLSX"},
            {"name": "presentation.pptx", "size": "4.7 MB", "modified": "2025-04-28 16:01:22", "type": "PPTX"},
            {"name": "config.xml", "size": "8.2 KB", "modified": "2025-05-02 11:45:03", "type": "XML"},
            {"name": "server.log", "size": "1.2 MB", "modified": "2025-05-10 08:15:46", "type": "LOG"}
        ]
        
        for i, file_info in enumerate(demo_files):
            self.file_list.insertRow(i)
            self.file_list.setItem(i, 0, QTableWidgetItem(file_info["name"]))
            self.file_list.setItem(i, 1, QTableWidgetItem(file_info["size"]))
            self.file_list.setItem(i, 2, QTableWidgetItem(file_info["modified"]))
            self.file_list.setItem(i, 3, QTableWidgetItem(file_info["type"]))
            
            # Store path as data
            full_path = f"{self.current_path}/{file_info['name']}" if self.current_path != "/" else f"/{file_info['name']}"
            self.file_list.item(i, 0).setData(Qt.UserRole, full_path)
    
    def _go_up_directory(self):
        """Navigate to the parent directory"""
        if self.current_path in ["/", "C:\\", os.path.expanduser("~")]:
            # Already at root or home, do nothing
            return
        
        # Get parent directory
        parent_dir = os.path.dirname(self.current_path)
        
        if self.current_device == "local":
            self._show_local_files(parent_dir)
        else:
            self._show_remote_files(self.current_device, parent_dir)
    
    def _on_file_double_clicked(self, index):
        """Handle double-click on file item"""
        if index.column() != 0:  # Only respond to first column
            return
            
        row = index.row()
        item = self.file_list.item(row, 0)
        file_path = item.data(Qt.UserRole)
        file_name = item.text()
        
        # Check if it's a directory
        file_type = self.file_list.item(row, 3).text()
        
        if file_type == "Directory":
            # Navigate to directory
            if self.current_device == "local":
                self._show_local_files(file_path)
            else:
                new_path = f"{self.current_path}/{file_name}" if self.current_path != "/" else f"/{file_name}"
                self._show_remote_files(self.current_device, new_path)
        else:
            # Regular file
            if self.current_device == "local":
                # Open local file with default application
                try:
                    import subprocess
                    import platform
                    
                    system = platform.system()
                    if system == "Windows":
                        os.startfile(file_path)
                    elif system == "Darwin":  # macOS
                        subprocess.call(["open", file_path])
                    else:  # Linux/Unix
                        subprocess.call(["xdg-open", file_path])
                        
                except Exception as e:
                    QMessageBox.warning(self, "Error", f"Could not open file: {str(e)}")
            else:
                # For remote files, show download dialog
                reply = QMessageBox.question(
                    self,
                    "Download File",
                    f"Would you like to download the file '{file_name}'?",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No
                )
                
                if reply == QMessageBox.Yes:
                    self._download_file(file_path)
    
    def _show_context_menu(self, position):
        """Show context menu for file list item"""
        menu = QMenu()
        
        # Get selected items
        selected_items = self.file_list.selectedItems()
        if not selected_items:
            return
            
        # Get the row of the first selected item
        row = selected_items[0].row()
        
        # Get file info
        file_name = self.file_list.item(row, 0).text()
        file_path = self.file_list.item(row, 0).data(Qt.UserRole)
        file_type = self.file_list.item(row, 3).text()
        
        # Add menu actions based on file type
        if file_type == "Directory":
            open_action = menu.addAction("Open Directory")
            open_action.triggered.connect(lambda: self._on_file_double_clicked(self.file_list.indexFromItem(selected_items[0])))
        else:
            if self.current_device == "local":
                open_action = menu.addAction("Open File")
                open_action.triggered.connect(lambda: self._on_file_double_clicked(self.file_list.indexFromItem(selected_items[0])))
            else:
                download_action = menu.addAction("Download File")
                download_action.triggered.connect(lambda: self._download_file(file_path))
        
        menu.addSeparator()
        
        # Add file operations
        if self.current_device == "local":
            delete_action = menu.addAction("Delete")
            delete_action.triggered.connect(lambda: self._delete_file(file_path))
            
            rename_action = menu.addAction("Rename")
            rename_action.triggered.connect(lambda: self._rename_file(file_path))
        
        # Add upload/download based on context
        if self.current_device == "local":
            # For local files, add upload option
            upload_action = menu.addAction("Upload to Remote")
            upload_action.triggered.connect(lambda: self._upload_file_to_remote(file_path))
        else:
            # For remote files, add download option if not already there
            if not menu.actions()[0].text() == "Download File":
                download_action = menu.addAction("Download File")
                download_action.triggered.connect(lambda: self._download_file(file_path))
        
        # Execute the menu
        menu.exec_(self.file_list.mapToGlobal(position))
    
    def _upload_file(self):
        """Upload a file to the selected device"""
        # If no remote device is selected, show error
        if self.device_selector.currentData() == "local":
            QMessageBox.warning(self, "Upload Error", "Please select a remote device to upload to")
            return
            
        # Open file dialog
        file_paths, _ = QFileDialog.getOpenFileNames(
            self,
            "Select Files to Upload",
            os.path.expanduser("~"),
            "All Files (*.*)"
        )
        
        if not file_paths:
            return  # User canceled
            
        # Get the target device
        device_id = self.device_selector.currentData()
        
        # Upload each selected file
        for file_path in file_paths:
            self._start_upload(file_path, device_id, self.current_path)
    
    def _upload_file_to_remote(self, file_path):
        """Upload a specific file to a remote device"""
        # If no remote device is selected, show device selector
        if self.device_selector.currentData() == "local":
            # Get list of available devices
            devices = []
            for i in range(1, self.device_selector.count()):  # Skip local
                devices.append((self.device_selector.itemText(i), self.device_selector.itemData(i)))
            
            if not devices:
                QMessageBox.warning(self, "Upload Error", "No remote devices available")
                return
                
            # If only one device, use that
            if len(devices) == 1:
                device_id = devices[0][1]
            else:
                # Show device selector dialog
                from PyQt5.QtWidgets import QDialog, QVBoxLayout, QDialogButtonBox
                
                dialog = QDialog(self)
                dialog.setWindowTitle("Select Target Device")
                layout = QVBoxLayout(dialog)
                
                device_combo = QComboBox()
                for device_name, device_id in devices:
                    device_combo.addItem(device_name, device_id)
                
                layout.addWidget(QLabel("Select a device to upload to:"))
                layout.addWidget(device_combo)
                
                buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
                buttons.accepted.connect(dialog.accept)
                buttons.rejected.connect(dialog.reject)
                layout.addWidget(buttons)
                
                if dialog.exec_() == QDialog.Accepted:
                    device_id = device_combo.currentData()
                else:
                    return  # User canceled
        else:
            device_id = self.device_selector.currentData()
        
        # Start the upload
        self._start_upload(file_path, device_id, "/")  # Default to root directory
    
    def _start_upload(self, file_path, device_id, destination):
        """Start a file upload in a separate thread"""
        if not os.path.isfile(file_path):
            QMessageBox.warning(self, "Upload Error", f"File not found: {file_path}")
            return
            
        # Get file size
        file_size = os.path.getsize(file_path)
        file_name = os.path.basename(file_path)
        
        # Show in transfers table
        row = self.transfers_table.rowCount()
        self.transfers_table.insertRow(row)
        self.transfers_table.setItem(row, 0, QTableWidgetItem(file_name))
        self.transfers_table.setItem(row, 1, QTableWidgetItem(f"To: {self.device_selector.currentText()}"))
        
        # Add progress bar
        progress_bar = QProgressBar()
        progress_bar.setRange(0, 100)
        progress_bar.setValue(0)
        self.transfers_table.setCellWidget(row, 2, progress_bar)
        
        self.transfers_table.setItem(row, 3, QTableWidgetItem("Starting..."))
        
        # Create progress callback
        def update_progress(percent):
            progress_bar.setValue(percent)
            self.transfers_table.item(row, 3).setText(f"Uploading ({percent}%)")
        
        # Create completion callback
        def transfer_completed(success, message):
            if success:
                self.transfers_table.item(row, 3).setText("Completed")
                # Send notification
                if self.message_service:
                    notification = Message(
                        content=f"File uploaded successfully: {file_name}",
                        msg_type=MessageType.INFO,
                        sender="File Transfer"
                    )
                    self.message_service.send_message(notification)
            else:
                self.transfers_table.item(row, 3).setText(f"Failed: {message}")
                # Send notification
                if self.message_service:
                    notification = Message(
                        content=f"File upload failed: {file_name} - {message}",
                        msg_type=MessageType.ERROR,
                        sender="File Transfer"
                    )
                    self.message_service.send_message(notification)
        
        # Start upload in a separate thread
        transfer_thread = FileTransferThread(
            file_path=file_path,
            device_id=device_id,
            destination=destination,
            transfer_type=TransferType.UPLOAD,
            file_service=self.file_service
        )
        
        # Connect signals
        transfer_thread.progress_updated.connect(update_progress)
        transfer_thread.transfer_completed.connect(transfer_completed)
        
        # Start the thread
        transfer_thread.start()
        
        # Store the thread
        self.active_transfers[file_name] = transfer_thread
        
        # Emit signal
        self.file_transfer_started.emit(file_name, device_id, file_size)
        
        # Update status
        self.status_label.setText(f"Uploading {file_name} to {device_id}...")
    
    def _download_selected(self):
        """Download selected file from remote device"""
        # Check if file is selected
        selected_items = self.file_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Download Error", "No file selected")
            return
            
        # If local device is selected, can't download
        if self.device_selector.currentData() == "local":
            QMessageBox.warning(self, "Download Error", "Cannot download from local device")
            return
            
        # Get the row of the first selected item
        row = selected_items[0].row()
        
        # Get file info
        file_path = self.file_list.item(row, 0).data(Qt.UserRole)
        
        # Download the file
        self._download_file(file_path)
    
    def _download_file(self, file_path):
        """Download a file from remote device"""
        # Get file name
        file_name = os.path.basename(file_path)
        
        # Get device ID
        device_id = self.device_selector.currentData()
        
        # Ask for download location
        download_dir = QFileDialog.getExistingDirectory(
            self,
            "Select Download Location",
            os.path.expanduser("~/Downloads")
        )
        
        if not download_dir:
            return  # User canceled
            
        # Full destination path
        destination = os.path.join(download_dir, file_name)
        
        # Check if file already exists
        if os.path.exists(destination):
            reply = QMessageBox.question(
                self,
                "File Exists",
                f"The file '{file_name}' already exists. Overwrite?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            
            if reply == QMessageBox.No:
                return
        
        # Show in transfers table
        row = self.transfers_table.rowCount()
        self.transfers_table.insertRow(row)
        self.transfers_table.setItem(row, 0, QTableWidgetItem(file_name))
        self.transfers_table.setItem(row, 1, QTableWidgetItem(f"From: {self.device_selector.currentText()}"))
        
        # Add progress bar
        progress_bar = QProgressBar()
        progress_bar.setRange(0, 100)
        progress_bar.setValue(0)
        self.transfers_table.setCellWidget(row, 2, progress_bar)
        
        self.transfers_table.setItem(row, 3, QTableWidgetItem("Starting..."))
        
        # Create progress callback
        def update_progress(percent):
            progress_bar.setValue(percent)
            self.transfers_table.item(row, 3).setText(f"Downloading ({percent}%)")
        
        # Create completion callback
        def transfer_completed(success, message):
            if success:
                self.transfers_table.item(row, 3).setText("Completed")
                # Send notification
                if self.message_service:
                    notification = Message(
                        content=f"File downloaded successfully: {file_name}",
                        msg_type=MessageType.INFO,
                        sender="File Transfer"
                    )
                    self.message_service.send_message(notification)
            else:
                self.transfers_table.item(row, 3).setText(f"Failed: {message}")
                # Send notification
                if self.message_service:
                    notification = Message(
                        content=f"File download failed: {file_name} - {message}",
                        msg_type=MessageType.ERROR,
                        sender="File Transfer"
                    )
                    self.message_service.send_message(notification)
        
        # Start download in a separate thread
        transfer_thread = FileTransferThread(
            file_path=file_path,
            device_id=device_id,
            destination=destination,
            transfer_type=TransferType.DOWNLOAD,
            file_service=self.file_service
        )
        
        # Connect signals
        transfer_thread.progress_updated.connect(update_progress)
        transfer_thread.transfer_completed.connect(transfer_completed)
        
        # Start the thread
        transfer_thread.start()
        
        # Store the thread
        self.active_transfers[file_name] = transfer_thread
        
        # Emit signal
        self.file_transfer_started.emit(file_name, device_id, 0)  # Size unknown for remote files
        
        # Update status
        self.status_label.setText(f"Downloading {file_name} from {device_id}...")
    
    def _delete_file(self, file_path):
        """Delete a file"""
        # Get file name
        file_name = os.path.basename(file_path)
        
        # Confirm deletion
        reply = QMessageBox.question(
            self,
            "Confirm Deletion",
            f"Are you sure you want to delete '{file_name}'?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.No:
            return
            
        try:
            if self.current_device == "local":
                # Delete local file
                if os.path.isdir(file_path):
                    import shutil
                    shutil.rmtree(file_path)
                else:
                    os.remove(file_path)
                    
                # Refresh the file list
                self._refresh_files_list()
                
                # Update status
                self.status_label.setText(f"Deleted {file_name}")
            else:
                # Delete remote file
                # This would be implemented with device_manager
                self.status_label.setText("Remote deletion not implemented yet")
                
        except Exception as e:
            QMessageBox.warning(self, "Delete Error", f"Could not delete file: {str(e)}")
    
    def _rename_file(self, file_path):
        """Rename a file"""
        # Get file name
        file_name = os.path.basename(file_path)
        
        # Get new name
        from PyQt5.QtWidgets import QInputDialog
        
        new_name, ok = QInputDialog.getText(
            self,
            "Rename File",
            "Enter new name:",
            text=file_name
        )
        
        if not ok or not new_name or new_name == file_name:
            return
            
        try:
            if self.current_device == "local":
                # Rename local file
                new_path = os.path.join(os.path.dirname(file_path), new_name)
                os.rename(file_path, new_path)
                
                # Refresh the file list
                self._refresh_files_list()
                
                # Update status
                self.status_label.setText(f"Renamed {file_name} to {new_name}")
            else:
                # Rename remote file
                # This would be implemented with device_manager
                self.status_label.setText("Remote rename not implemented yet")
                
        except Exception as e:
            QMessageBox.warning(self, "Rename Error", f"Could not rename file: {str(e)}")
    
    def _refresh_files_list(self):
        """Refresh the file list"""
        if hasattr(self, 'current_device') and hasattr(self, 'current_path'):
            if self.current_device == "local":
                self._show_local_files(self.current_path)
            else:
                self._show_remote_files(self.current_device, self.current_path)
    
    def _on_message_received(self, message):
        """Handle received messages"""
        # Look for file transfer related messages
        if message.sender == "File Transfer":
            # File transfer completed notification
            if "successfully" in message.content:
                # Refresh file list
                self._refresh_files_list()
    
    def search_files(self):
        """Search for files"""
        query = self.search_input.text().strip()
        if not query:
            return
            
        # If local is selected, perform local search
        if self.device_selector.currentData() == "local":
            self._search_local_files(query)
        else:
            # Search on remote device
            self._search_remote_files(query)
    
    def _search_local_files(self, query):
        """Search for files locally"""
        import fnmatch
        
        # Start from current directory
        if hasattr(self, 'current_path') and self.current_path:
            start_dir = self.current_path
        else:
            start_dir = os.path.expanduser("~")
        
        # Clear the file list
        self.file_list.setRowCount(0)
        
        # Update status
        self.status_label.setText(f"Searching for '{query}' in {start_dir}...")
        
        # Enable wildcard search
        pattern = f"*{query}*"
        
        # Limit depth to avoid too long searches
        max_depth = 3
        
        matches = []
        
        # Walk the directory tree
        for root, dirs, files in os.walk(start_dir):
            # Check depth
            depth = root[len(start_dir):].count(os.sep)
            if depth > max_depth:
                dirs[:] = []  # Don't go deeper
                continue
                
            # Search directories
            for d in dirs:
                if fnmatch.fnmatch(d.lower(), pattern.lower()):
                    matches.append(os.path.join(root, d))
                    
            # Search files
            for f in files:
                if fnmatch.fnmatch(f.lower(), pattern.lower()):
                    matches.append(os.path.join(root, f))
                    
            # Limit results
            if len(matches) >= 100:
                break
        
        # Display results
        for i, file_path in enumerate(matches):
            try:
                # Get file info
                stat_info = os.stat(file_path)
                size = stat_info.st_size
                modified = datetime.fromtimestamp(stat_info.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                
                # Determine type
                if os.path.isdir(file_path):
                    type_str = "Directory"
                    size_str = "--"
                else:
                    # Get file extension
                    _, ext = os.path.splitext(os.path.basename(file_path))
                    type_str = ext[1:].upper() if ext else "File"
                    
                    # Format size
                    if size < 1024:
                        size_str = f"{size} B"
                    elif size < 1024 * 1024:
                        size_str = f"{size/1024:.1f} KB"
                    elif size < 1024 * 1024 * 1024:
                        size_str = f"{size/(1024*1024):.1f} MB"
                    else:
                        size_str = f"{size/(1024*1024*1024):.1f} GB"
                
                # Add to table
                self.file_list.insertRow(i)
                self.file_list.setItem(i, 0, QTableWidgetItem(os.path.basename(file_path)))
                self.file_list.setItem(i, 1, QTableWidgetItem(size_str))
                self.file_list.setItem(i, 2, QTableWidgetItem(modified))
                self.file_list.setItem(i, 3, QTableWidgetItem(type_str))
                
                # Store full path as data
                self.file_list.item(i, 0).setData(Qt.UserRole, file_path)
                
            except (PermissionError, FileNotFoundError):
                # Skip files we can't access
                continue
                
        # Update status
        self.status_label.setText(f"Found {self.file_list.rowCount()} items matching '{query}'")
    
    def _search_remote_files(self, query):
        """Search for files on remote device"""
        device_id = self.device_selector.currentData()
        
        # Update status
        self.status_label.setText(f"Searching for '{query}' on {self.device_selector.currentText()}...")
        
        # Clear the file list
        self.file_list.setRowCount(0)
        
        # This would be implemented to communicate with the remote device
        # For now, show some demo results
        
        # Add demo search results
        self._add_demo_search_results(query)
    
    def _add_demo_search_results(self, query):
        """Add demo search results for demonstration"""
        # Create some plausible search results based on the query
        import random
        
        # Base paths for results
        base_paths = ["/home/user", "/var/www", "/etc/config", "/usr/local/bin"]
        
        # File types that might match query
        extensions = ["pdf", "txt", "docx", "xlsx", "pptx", "jpg", "png", "log", "xml", "json", "csv"]
        
        # Generate random results
        results = []
        
        # Use query to make results more relevant
        if "report" in query.lower():
            types = ["pdf", "docx", "xlsx"]
            prefixes = ["annual_report", "monthly_report", "status_report", "financial_report"]
            
            for _ in range(min(5, random.randint(3, 8))):
                prefix = random.choice(prefixes)
                ext = random.choice(types)
                path = f"{random.choice(base_paths)}/Documents/{prefix}_{random.randint(2020, 2025)}.{ext}"
                size = f"{random.uniform(0.5, 10):.1f} MB"
                date = f"2025-{random.randint(1,5):02d}-{random.randint(1,28):02d} {random.randint(8,18):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d}"
                results.append((path, size, date, ext.upper()))
        
        elif "config" in query.lower():
            types = ["xml", "json", "ini", "conf", "yaml"]
            prefixes = ["system_config", "app_config", "network_config", "security_config"]
            
            for _ in range(min(6, random.randint(4, 9))):
                prefix = random.choice(prefixes)
                ext = random.choice(types)
                path = f"{random.choice(base_paths)}/config/{prefix}.{ext}"
                size = f"{random.uniform(0.1, 2):.1f} KB"
                date = f"2025-{random.randint(1,5):02d}-{random.randint(1,28):02d} {random.randint(8,18):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d}"
                results.append((path, size, date, ext.upper()))
        
        elif "log" in query.lower():
            types = ["log", "txt"]
            prefixes = ["system", "error", "access", "debug", "application"]
            
            for _ in range(min(8, random.randint(5, 12))):
                prefix = random.choice(prefixes)
                ext = random.choice(types)
                path = f"{random.choice(base_paths)}/logs/{prefix}.{ext}"
                size = f"{random.uniform(1, 50):.1f} MB"
                date = f"2025-{random.randint(1,5):02d}-{random.randint(1,28):02d} {random.randint(8,18):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d}"
                results.append((path, size, date, ext.upper()))
        
        else:
            # Generic results
            for _ in range(min(10, random.randint(2, 15))):
                ext = random.choice(extensions)
                path = f"{random.choice(base_paths)}/{query.lower()}_{random.randint(1, 100)}.{ext}"
                
                if ext in ["pdf", "docx", "pptx"]:
                    size = f"{random.uniform(0.5, 10):.1f} MB"
                elif ext in ["jpg", "png"]:
                    size = f"{random.uniform(0.2, 5):.1f} MB"
                else:
                    size = f"{random.uniform(0.1, 500):.1f} KB"
                    
                date = f"2025-{random.randint(1,5):02d}-{random.randint(1,28):02d} {random.randint(8,18):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d}"
                results.append((path, size, date, ext.upper()))
        
        # Add directory results
        if random.random() > 0.5:
            for _ in range(random.randint(1, 3)):
                dir_name = f"{query.lower()}_directory"
                path = f"{random.choice(base_paths)}/{dir_name}"
                date = f"2025-{random.randint(1,5):02d}-{random.randint(1,28):02d} {random.randint(8,18):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d}"
                results.append((path, "--", date, "Directory"))
        
        # Display results
        for i, (file_path, size, modified, file_type) in enumerate(results):
            self.file_list.insertRow(i)
            self.file_list.setItem(i, 0, QTableWidgetItem(os.path.basename(file_path)))
            self.file_list.setItem(i, 1, QTableWidgetItem(size))
            self.file_list.setItem(i, 2, QTableWidgetItem(modified))
            self.file_list.setItem(i, 3, QTableWidgetItem(file_type))
            
            # Store full path as data
            self.file_list.item(i, 0).setData(Qt.UserRole, file_path)
        
        # Update status
        self.status_label.setText(f"Found {len(results)} items matching '{query}' on {self.device_selector.currentText()}")
    
    def _share_files(self):
        """Share selected files with other devices"""
        # Check if file is selected
        selected_items = self.file_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Share Error", "No file selected")
            return
            
        # Only allow sharing from local device for now
        if self.device_selector.currentData() != "local":
            QMessageBox.warning(self, "Share Error", "Can only share local files")
            return
            
        # Get the file info
        rows = set()
        for item in selected_items:
            rows.add(item.row())
            
        files_to_share = []
        for row in rows:
            file_path = self.file_list.item(row, 0).data(Qt.UserRole)
            file_name = self.file_list.item(row, 0).text()
            files_to_share.append((file_path, file_name))
        
        # Create sharing dialog
        from PyQt5.QtWidgets import QDialog, QVBoxLayout, QDialogButtonBox
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Share Files")
        dialog.setMinimumWidth(400)
        layout = QVBoxLayout(dialog)
        
        # Add text
        layout.addWidget(QLabel(f"Share {len(files_to_share)} selected file(s) with:"))
        
        # Get available devices
        devices = []
        for i in range(1, self.device_selector.count()):  # Skip local
            device_text = self.device_selector.itemText(i)
            device_id = self.device_selector.itemData(i)
            devices.append((device_text, device_id))
        
        # Add device checkboxes
        device_checkboxes = []
        for device_text, _ in devices:
            checkbox = QCheckBox(device_text)
            layout.addWidget(checkbox)
            device_checkboxes.append(checkbox)
        
        # Add share details
        # NOTE: This would be expanded with permissions, expiry, etc.
        layout.addWidget(QLabel("Access permissions:"))
        
        permission_combo = QComboBox()
        permission_combo.addItems(["Read Only", "Read and Write", "Full Access"])
        layout.addWidget(permission_combo)
        
        # Add buttons
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        
        # Execute dialog
        if dialog.exec_() == QDialog.Accepted:
            # Get selected devices
            selected_devices = []
            for i, checkbox in enumerate(device_checkboxes):
                if checkbox.isChecked():
                    selected_devices.append(devices[i])
            
            if not selected_devices:
                QMessageBox.warning(self, "Share Error", "No devices selected")
                return
                
            # Get selected permission
            permission = permission_combo.currentText()
            
            # For each file and device, create a share
            for file_path, file_name in files_to_share:
                for device_text, device_id in selected_devices:
                    # Add to shared files list
                    row = self.shared_list.rowCount()
                    self.shared_list.insertRow(row)
                    self.shared_list.setItem(row, 0, QTableWidgetItem(file_name))
                    self.shared_list.setItem(row, 1, QTableWidgetItem(device_text))
                    self.shared_list.setItem(row, 2, QTableWidgetItem(permission))
                    
                    # In a real implementation, this would register the share with the file service
            
            # Show success message
            QMessageBox.information(
                self,
                "Files Shared",
                f"Shared {len(files_to_share)} file(s) with {len(selected_devices)} device(s)"
            )
    
    def _unshare_files(self):
        """Stop sharing selected files"""
        # Check if file is selected in shared list
        selected_items = self.shared_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Unshare Error", "No shared file selected")
            return
            
        # Confirm unshare
        reply = QMessageBox.question(
            self,
            "Confirm Unshare",
            "Are you sure you want to stop sharing the selected files?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.No:
            return
            
        # Get the rows
        rows = set()
        for item in selected_items:
            rows.add(item.row())
            
        # Remove in reverse order to keep indices valid
        for row in sorted(rows, reverse=True):
            self.shared_list.removeRow(row)
        
        # Show success message
        QMessageBox.information(
            self,
            "Files Unshared",
            f"Stopped sharing {len(rows)} file(s)"
        )
        
    def cleanup(self):
        """Cleanup resources before widget is destroyed"""
        # Stop all active transfers
        for file_name, thread in self.active_transfers.items():
            if thread.isRunning():
                thread.terminate()
                thread.wait()
        
        # Stop refresh timer
        if self.refresh_timer.isActive():
            self.refresh_timer.stop()