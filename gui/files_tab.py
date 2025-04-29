"""
Files tab for Network Scanner - provides file management across remote devices
"""

import os
import logging
import math
import time
from datetime import datetime
from typing import Dict, List

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QFileDialog,
    QTreeWidget, QTreeWidgetItem, QLineEdit, QPushButton, QLabel, 
    QComboBox, QMessageBox, QMenu, QTableWidget, QTableWidgetItem, 
    QHeaderView, QButtonGroup, QToolButton, QInputDialog, QDialog,
    QDialogButtonBox, QFormLayout
)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QIcon

logger = logging.getLogger(__name__)

# Common file icons - can be extended as needed
FILE_ICONS = {
    "default": "icons/file.png",
    "dir": "icons/folder.png",
    "txt": "icons/text.png",
    "pdf": "icons/pdf.png",
    "doc": "icons/doc.png",
    "docx": "icons/doc.png",
    "jpg": "icons/image.png",
    "png": "icons/image.png",
    "mp3": "icons/audio.png",
    "mp4": "icons/video.png",
    "zip": "icons/archive.png",
    "exe": "icons/executable.png",
    "py": "icons/code.png",
}

class FilesTab(QWidget):
    """Tab for remote file management functionality"""
    
    def __init__(self, device_manager, file_service, message_service):
        super().__init__()
        self.device_manager = device_manager  # This is our DeviceManager
        self.file_service = file_service
        self.message_service = message_service
        self.search_results = []
        self.selected_device = None
        self.current_directory = None
        self.is_windows = False  # Flag to track if current device is Windows
        self._setup_ui()
        
        # Register for device changes to auto-refresh the device list
        if self.device_manager and hasattr(self.device_manager, 'add_device_change_callback'):
            self.device_manager.add_device_change_callback(self._load_devices)
        
    def _setup_ui(self):
        """Set up the files UI"""
        main_layout = QVBoxLayout(self)
        
        # Top search bar
        search_layout = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search files by name, extension, size, content...")
        self.search_input.returnPressed.connect(self.search_files)
        search_layout.addWidget(self.search_input, 3)
        
        # Device selection
        self.device_combo = QComboBox()
        self.device_combo.addItem("All Devices")
        self.device_combo.currentIndexChanged.connect(self._on_device_changed)
        search_layout.addWidget(self.device_combo, 1)
        
        search_button = QPushButton("Search")
        search_button.clicked.connect(self.search_files)
        search_layout.addWidget(search_button)
        
        advanced_button = QPushButton("Advanced")
        advanced_button.clicked.connect(self._show_advanced_search)
        search_layout.addWidget(advanced_button)
        
        main_layout.addLayout(search_layout)
        
        # Main splitter
        splitter = QSplitter(Qt.Horizontal)
        
        # Left side - Directory tree
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        
        dir_label = QLabel("File System")
        dir_label.setStyleSheet("font-weight: bold; font-size: 14px; padding: 5px;")
        left_layout.addWidget(dir_label)
        
        self.dir_tree = QTreeWidget()
        self.dir_tree.setHeaderLabels(["Directories"])
        self.dir_tree.setColumnCount(1)
        self.dir_tree.itemClicked.connect(self._on_directory_selected)
        left_layout.addWidget(self.dir_tree)
        
        refresh_tree_button = QPushButton("Refresh")
        refresh_tree_button.clicked.connect(self.refresh_directory_tree)
        left_layout.addWidget(refresh_tree_button)
        
        splitter.addWidget(left_panel)
        
        # Right side - File list
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        
        self.path_label = QLabel("No directory selected")
        self.path_label.setStyleSheet("font-weight: bold; font-size: 14px; padding: 5px;")
        right_layout.addWidget(self.path_label)
        
        # File tools
        tools_layout = QHBoxLayout()
        
        # View mode buttons
        self.view_mode_group = QButtonGroup(self)
        self.list_btn = QToolButton()
        self.list_btn.setText("List")
        self.list_btn.setCheckable(True)
        self.list_btn.setChecked(True)
        self.view_mode_group.addButton(self.list_btn, 1)
        
        self.grid_btn = QToolButton()
        self.grid_btn.setText("Grid")
        self.grid_btn.setCheckable(True)
        self.view_mode_group.addButton(self.grid_btn, 2)
        
        tools_layout.addWidget(self.list_btn)
        tools_layout.addWidget(self.grid_btn)
        tools_layout.addStretch()
        
        # Sort and filter options
        tools_layout.addWidget(QLabel("Sort by:"))
        self.sort_combo = QComboBox()
        self.sort_combo.addItems(["Name", "Size", "Type", "Modified"])
        tools_layout.addWidget(self.sort_combo)
        
        tools_layout.addWidget(QLabel("Filter:"))
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["All Files", "Documents", "Images", "Videos", "Audio", "Archives", "Code"])
        self.filter_combo.currentIndexChanged.connect(self._apply_filter)
        tools_layout.addWidget(self.filter_combo)
        
        right_layout.addLayout(tools_layout)
        
        # Files table
        self.files_table = QTableWidget()
        self.files_table.setColumnCount(5)
        self.files_table.setHorizontalHeaderLabels(["Name", "Size", "Type", "Modified", "Actions"])
        self.files_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.files_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.files_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.files_table.customContextMenuRequested.connect(self._show_context_menu)
        self.files_table.doubleClicked.connect(self._on_file_double_clicked)
        self.files_table.setAlternatingRowColors(True)
        right_layout.addWidget(self.files_table)
        
        # File operation buttons
        buttons_layout = QHBoxLayout()
        
        buttons = [
            ("New Folder", self._create_new_folder),
            ("Upload", self._upload_file),
            ("Download Selected", self._download_selected),
            ("Delete Selected", self._delete_selected)
        ]
        
        for text, callback in buttons:
            btn = QPushButton(text)
            btn.clicked.connect(callback)
            buttons_layout.addWidget(btn)
            
        right_layout.addLayout(buttons_layout)
        splitter.addWidget(right_panel)
        splitter.setSizes([200, 600])  # Initial sizes for the panels
        main_layout.addWidget(splitter)
        
        # Status bar
        self.status_label = QLabel("Ready")
        main_layout.addWidget(self.status_label)
        
        # Load devices
        self._load_devices()
        
    def _sanitize_windows_path(self, path):
        """Make sure Windows paths are formatted correctly"""
        if not path:
            return path
        
        # Handle drive letters properly
        if len(path) >= 2 and path[1] == ':':
            drive_letter = path[0].upper()
            # Ensure proper drive letter format
            path = f"{drive_letter}:" + path[2:]
        
        # Replace any forward slashes with backslashes
        path = path.replace("/", "\\")
        
        # Remove any double backslashes (except for UNC paths)
        if not path.startswith("\\\\"):
            while "\\\\" in path:
                path = path.replace("\\\\", "\\")
        
        return path

    def _format_path_for_display(self, path):
        """Format path for display in the UI"""
        if self.is_windows:
            # Keep Windows format for display (using backslashes)
            return path
        else:
            # Use Unix format for display (forward slashes)
            return path.replace("\\", "/")

    def _load_devices(self):
        """Load available network devices with remote management capability"""
        # Clear existing items
        while self.device_combo.count() > 1:  # Keep "All Devices"
            self.device_combo.removeItem(1)
            
        try:
            if self.device_manager:
                # Get devices from the DeviceManager that are online with network_agent
                devices = self.device_manager.get_discovered_devices()
                
                if devices:
                    # Add devices to combobox
                    for device in devices:
                        device_name = device.get("hostname", device.get("ip_address", "Unknown Device"))
                        device_id = device.get("id") or device.get("ip_address")
                        self.device_combo.addItem(device_name, device_id)
                    self.status_label.setText(f"Found {len(devices)} devices with remote management")
                else:
                    self.status_label.setText("No devices with remote management. Run network_agent.py on target machines.")
        except Exception as e:
            logger.error(f"Error loading devices: {e}")
            self.status_label.setText(f"Error loading devices: {str(e)}")
            
    def _on_device_changed(self, index):
        """Handle device selection change"""
        if index == 0:
            self.selected_device = None
            self.is_windows = False
            self.dir_tree.clear()
            self.path_label.setText("No directory selected")
            self.files_table.setRowCount(0)
        else:
            self.selected_device = self.device_combo.currentData()
            
            # Check if device is Windows
            if hasattr(self.device_manager, 'get_system_info'):
                try:
                    system_info = self.device_manager.get_system_info(self.selected_device)
                    self.is_windows = system_info and "windows" in system_info.get("platform", "").lower()
                except Exception:
                    self.is_windows = False
            
            self.refresh_directory_tree()
            
    def refresh_directory_tree(self):
        """Refresh the directory tree"""
        self.dir_tree.clear()
        if not self.selected_device:
            return
            
        try:
            directories = self._get_directories("/")
            
            root_item = QTreeWidgetItem(self.dir_tree)
            root_item.setText(0, self.device_combo.currentText())
            root_item.setIcon(0, self._get_icon("dir"))
            root_item.setData(0, Qt.UserRole, "/")
            
            for directory in directories:
                dir_item = QTreeWidgetItem(root_item)
                dir_item.setText(0, directory.get("name"))
                dir_item.setIcon(0, self._get_icon("dir"))
                dir_item.setData(0, Qt.UserRole, directory.get("path"))
                
                # Add placeholder for expandable dirs
                if directory.get("has_subdirs", True):
                    placeholder = QTreeWidgetItem(dir_item)
                    placeholder.setText(0, "Loading...")
                    
            root_item.setExpanded(True)
        except Exception as e:
            logger.error(f"Error refreshing directory tree: {e}")
            self.status_label.setText(f"Error loading directories: {str(e)}")
            
    def _get_icon(self, icon_type):
        """Get icon for file type"""
        icon_path = FILE_ICONS.get(icon_type, FILE_ICONS.get("default"))
        return QIcon(icon_path) if icon_path and os.path.exists(icon_path) else QIcon()
        
    def _on_directory_selected(self, item, column):
        """Handle directory selection"""
        path = item.data(0, Qt.UserRole)
        if not path:
            return
            
        # Load subdirectories on first expansion
        if item.childCount() == 1 and item.child(0).text(0) == "Loading...":
            item.removeChild(item.child(0))  # Remove placeholder
            try:
                subdirs = self._get_directories(path)
                for subdir in subdirs:
                    dir_item = QTreeWidgetItem(item)
                    dir_item.setText(0, subdir.get("name"))
                    dir_item.setIcon(0, self._get_icon("dir"))
                    dir_item.setData(0, Qt.UserRole, subdir.get("path"))
                    
                    if subdir.get("has_subdirs", True):
                        placeholder = QTreeWidgetItem(dir_item)
                        placeholder.setText(0, "Loading...")
            except Exception as e:
                logger.error(f"Error loading subdirectories: {e}")
                self.status_label.setText(f"Error loading subdirectories: {str(e)}")
        
        # Update current directory
        self.current_directory = path
        
        # Update path label
        device_name = self.device_combo.currentText()
        self.path_label.setText(f"{device_name}: {self._format_path_for_display(path)}")
        
        # Load files for this directory
        self._load_files(path)
            
    def _get_directories(self, path):
        """Get directories from selected device"""
        if not self.selected_device:
            return []
            
        # Try to use device_manager to get real directories
        if hasattr(self.device_manager, 'get_system_info') and hasattr(self.device_manager, 'execute_command'):
            try:
                # Get system info to check if Windows
                system_info = self.device_manager.get_system_info(self.selected_device)
                self.is_windows = system_info and "windows" in system_info.get("platform", "").lower()
                
                if self.is_windows:
                    # Handle Windows directories
                    if path == "/":
                        # List drives for root directory
                        cmd = "wmic logicaldisk get caption"
                        result = self.device_manager.execute_command(self.selected_device, cmd)
                        
                        if result:
                            directories = []
                            for line in result.strip().split('\n'):
                                drive = line.strip()
                                if drive and drive != "Caption":  # Skip header
                                    directories.append({
                                        "name": drive,
                                        "path": f"{drive}",  # Don't add backslash to drive letter
                                        "has_subdirs": True
                                    })
                            return directories
                    else:
                        # Fix path handling for subdirectories
                        # Create proper Windows path - maintain drive letter format
                        if ":" in path:
                            # Path already has drive letter (C:, D:, etc.)
                            windows_path = self._sanitize_windows_path(path)
                        else:
                            # Something went wrong, try to recover
                            windows_path = path.replace("/", "\\")
                        
                        # Use proper command to list directories only
                        cmd = f"dir /ad /b \"{windows_path}\""
                        result = self.device_manager.execute_command(self.selected_device, cmd)
                        
                        if result:
                            directories = []
                            for line in result.strip().split('\n'):
                                name = line.strip()
                                if name and len(name) > 0:
                                    # Skip system directories
                                    if name not in ["System Volume Information", "$RECYCLE.BIN", "$Recycle.Bin"]:
                                        # Properly construct the full path
                                        if windows_path.endswith("\\"):
                                            full_path = f"{windows_path}{name}"
                                        else:
                                            full_path = f"{windows_path}\\{name}"
                                            
                                        directories.append({
                                            "name": name,
                                            "path": full_path,  # Keep Windows path format
                                            "has_subdirs": True
                                        })
                            return directories
                else:
                    # Linux/Mac handling
                    cmd = f"ls -la {path}"
                    result = self.device_manager.execute_command(self.selected_device, cmd)
                    
                    if result:
                        directories = []
                        lines = result.strip().split('\n')
                        
                        for line in lines[1:]:  # Skip the first line (total)
                            parts = line.split()
                            if len(parts) >= 9:
                                if parts[0].startswith('d'):  # Directory check
                                    name = parts[8]
                                    if name not in [".", ".."]:
                                        directories.append({
                                            "name": name,
                                            "path": os.path.join(path, name).replace("\\", "/"),
                                            "has_subdirs": True
                                        })
                        return directories
            except Exception as e:
                logger.error(f"Error getting directories: {e}")
                # Fall back to simulated data
        
        # Return simulated directories for testing
        if path == "/":
            return [
                {"name": "home", "path": "/home", "has_subdirs": True},
                {"name": "var", "path": "/var", "has_subdirs": True},
                {"name": "etc", "path": "/etc", "has_subdirs": True},
            ]
        elif path == "/home":
            return [
                {"name": "user", "path": "/home/user", "has_subdirs": True},
                {"name": "admin", "path": "/home/admin", "has_subdirs": True}
            ]
        elif path == "/home/user":
            return [
                {"name": "Documents", "path": "/home/user/Documents", "has_subdirs": True},
                {"name": "Pictures", "path": "/home/user/Pictures", "has_subdirs": True},
                {"name": "Downloads", "path": "/home/user/Downloads", "has_subdirs": False}
            ]
        return []
            
    def _load_files(self, path):
        """Load files from selected directory"""
        self.files_table.setRowCount(0)
        if not self.selected_device or not path:
            return
            
        try:
            # Use appropriate path format based on OS
            cmd_path = path
            if self.is_windows and ":" in path:
                cmd_path = self._sanitize_windows_path(path)
            
            files = self._get_files(cmd_path)
            
            for i, file_info in enumerate(files):
                self.files_table.insertRow(i)
                
                # File name with icon
                name_item = QTableWidgetItem(file_info.get("name"))
                extension = file_info.get("extension", "").lower()
                icon_type = "dir" if file_info.get("is_dir") else extension
                name_item.setIcon(self._get_icon(icon_type))
                name_item.setData(Qt.UserRole, file_info)
                self.files_table.setItem(i, 0, name_item)
                
                # Size
                is_dir = file_info.get("is_dir", False)
                size_str = "<DIR>" if is_dir else self._format_size(file_info.get("size", 0))
                size_item = QTableWidgetItem(size_str)
                size_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
                self.files_table.setItem(i, 1, size_item)
                
                # Type
                file_type = "Directory" if is_dir else f"{extension.upper()} File"
                if "mime_type" in file_info and file_info["mime_type"]:
                    file_type = file_info["mime_type"]
                self.files_table.setItem(i, 2, QTableWidgetItem(file_type))
                
                # Modified date
                mod_time = datetime.fromtimestamp(file_info.get("modified", 0)).strftime("%Y-%m-%d %H:%M:%S")
                self.files_table.setItem(i, 3, QTableWidgetItem(mod_time))
                
                # Actions button
                action_btn = QPushButton("Actions")
                action_btn.clicked.connect(lambda _, row=i: self._show_file_actions(row))
                self.files_table.setCellWidget(i, 4, action_btn)
            
            self.status_label.setText(f"Loaded {len(files)} items from {self._format_path_for_display(path)}")
            
            # Apply current filter
            self._apply_filter(self.filter_combo.currentIndex())
        except Exception as e:
            logger.error(f"Error loading files: {e}")
            self.status_label.setText(f"Error loading files: {str(e)}")
            
    def _get_files(self, path):
        """Get files from selected directory"""
        if not self.selected_device:
            return []
            
        # Try to use device_manager if available
        if hasattr(self.device_manager, 'get_system_info') and hasattr(self.device_manager, 'execute_command'):
            try:
                # Check if path is valid
                if not path:
                    logger.warning("Empty path provided to _get_files")
                    return []
                
                if self.is_windows:
                    # Use Windows commands
                    windows_path = self._sanitize_windows_path(path)
                    
                    # Get both files and directories
                    cmd = f"dir \"{windows_path}\" /a /b"
                    result = self.device_manager.execute_command(self.selected_device, cmd)
                    
                    if result:
                        files = []
                        current_time = time.time()
                        
                        for line in result.strip().split('\n'):
                            name = line.strip()
                            if name and name not in [".", ".."]:
                                # Create full path - proper Windows format
                                if windows_path.endswith("\\"):
                                    full_path = f"{windows_path}{name}"
                                else:
                                    full_path = f"{windows_path}\\{name}"
                                
                                # Check if it's a directory using another command
                                dir_check_cmd = f"if exist \"{full_path}\\*\" (echo isdir) else (echo isfile)"
                                check_result = self.device_manager.execute_command(self.selected_device, dir_check_cmd)
                                is_dir = check_result and "isdir" in check_result.lower()
                                
                                # Skip system directories/files that might cause issues
                                if name in ["System Volume Information", "$RECYCLE.BIN", "$Recycle.Bin"]:
                                    continue
                                    
                                # Get file extension
                                extension = ""
                                if not is_dir and "." in name:
                                    extension = name.split(".")[-1].lower()
                                
                                # Get file size (only for files)
                                size = 0
                                if not is_dir:
                                    size_cmd = f"for %I in (\"{full_path}\") do @echo %~zI"
                                    size_result = self.device_manager.execute_command(self.selected_device, size_cmd)
                                    try:
                                        if size_result and size_result.strip().isdigit():
                                            size = int(size_result.strip())
                                    except ValueError:
                                        pass
                                
                                files.append({
                                    "name": name,
                                    "path": full_path,  # Keep Windows format
                                    "size": size,
                                    "modified": current_time - 86400,  # Placeholder
                                    "extension": extension,
                                    "is_dir": is_dir
                                })
                        return files
                else:
                    # Linux/Mac handling
                    cmd = f"ls -la {path}"
                    result = self.device_manager.execute_command(self.selected_device, cmd)
                    
                    if result:
                        files = []
                        lines = result.strip().split('\n')
                        
                        for line in lines[1:]:  # Skip the first line (total)
                            parts = line.split()
                            if len(parts) >= 9:
                                name = parts[8]
                                if name not in [".", ".."]:
                                    is_dir = parts[0].startswith('d')
                                    size = int(parts[4]) if not is_dir else 0
                                    extension = name.split(".")[-1].lower() if not is_dir and "." in name else ""
                                    
                                    files.append({
                                        "name": name,
                                        "path": os.path.join(path, name).replace("\\", "/"),
                                        "size": size,
                                        "modified": time.time() - 86400,  # Placeholder
                                        "extension": extension,
                                        "is_dir": is_dir
                                    })
                        return files
            except Exception as e:
                logger.error(f"Error executing remote command: {e}")
                # Fall back to simulated data
        
        # Return simulated files for testing
        current_time = time.time()
        if path == "/home/user/Documents":
            return [
                {
                    "name": "Project Proposal.docx",
                    "path": "/home/user/Documents/Project Proposal.docx",
                    "size": 1024 * 1024 * 2.5,
                    "modified": current_time - 86400,
                    "extension": "docx",
                    "is_dir": False
                },
                {
                    "name": "Budget.xlsx",
                    "path": "/home/user/Documents/Budget.xlsx",
                    "size": 1024 * 512,
                    "modified": current_time - 86400 * 2,
                    "extension": "xlsx",
                    "is_dir": False
                },
                {
                    "name": "Meeting Notes",
                    "path": "/home/user/Documents/Meeting Notes",
                    "size": 0,
                    "modified": current_time - 86400 * 5,
                    "is_dir": True
                }
            ]
        return []
            
    def _format_size(self, size_bytes):
        """Format file size"""
        if size_bytes == 0:
            return "0 B"
        
        size_names = ("B", "KB", "MB", "GB", "TB")
        i = int(math.floor(math.log(size_bytes, 1024))) if size_bytes > 0 else 0
        p = math.pow(1024, i)
        s = round(size_bytes / p, 2)
        
        return f"{s} {size_names[i]}"

    def search_files(self):
        """Search for files based on query"""
        query = self.search_input.text().strip()
        if not query:
            QMessageBox.warning(self, "Search Error", "Please enter a search query.")
            return
            
        self.status_label.setText(f"Searching for '{query}'...")
        device_id = self.device_combo.currentData() if self.device_combo.currentIndex() > 0 else None
            
        try:
            results = self._perform_search(query, device_id)
            self._display_search_results(results)
        except Exception as e:
            logger.error(f"Error searching files: {e}")
            self.status_label.setText(f"Error searching: {str(e)}")
            
    def _perform_search(self, query, device_id=None):
        """Perform file search"""
        # Use device_manager if available for a specific device
        if device_id and hasattr(self.device_manager, 'get_system_info') and hasattr(self.device_manager, 'execute_command'):
            try:
                # Get system info to check platform
                system_info = self.device_manager.get_system_info(device_id)
                is_windows = system_info and "windows" in system_info.get("platform", "").lower()
                
                if is_windows:
                    # Windows search command - use more specific searching
                    # Double quotes in Windows can cause issues, so use single quotes in findstr
                    safe_query = query.replace("\"", "'")
                    cmd = f"dir /s /b | findstr /i \"{safe_query}\""
                    result = self.device_manager.execute_command(device_id, cmd)
                else:
                    # Linux search command
                    cmd = f"find / -name \"*{query}*\" -type f -o -name \"*{query}*\" -type d 2>/dev/null"
                    result = self.device_manager.execute_command(device_id, cmd)
                
                if result:
                    search_results = []
                    current_time = time.time()
                    device_name = self.device_combo.currentText() if device_id else "Unknown"
                    
                    for line in result.strip().split('\n'):
                        if line.strip():
                            path = line.strip()
                            if is_windows:
                                name = os.path.basename(path)
                                # Check if path is a directory
                                dir_check_cmd = f"if exist \"{path}\\*\" (echo isdir) else (echo isfile)"
                                check_result = self.device_manager.execute_command(device_id, dir_check_cmd)
                                is_dir = check_result and "isdir" in check_result.lower()
                            else:  # Linux
                                name = os.path.basename(path)
                                is_dir = os.path.isdir(path) if os.path.exists(path) else "/" in path and path.endswith("/")
                            
                            extension = name.split(".")[-1].lower() if not is_dir and "." in name else ""
                            
                            # Keep Windows path format for Windows systems
                            display_path = path
                            if not is_windows:
                                display_path = path.replace("\\", "/")
                            
                            search_results.append({
                                "name": name,
                                "path": path,  # Keep original path format
                                "device": device_name,
                                "device_id": device_id,
                                "size": 0,  # Placeholder
                                "modified": current_time - 86400,  # Placeholder
                                "extension": extension,
                                "is_dir": is_dir
                            })
                    return search_results
            except Exception as e:
                logger.error(f"Error performing remote search: {e}")
        
        # Simulated search results for testing or if remote search failed
        current_time = time.time()
        results = [
            {
                "name": "Project Proposal.docx",
                "path": "/home/user/Documents/Project Proposal.docx",
                "device": "Desktop-PC (Remote Managed)",
                "device_id": "123456",
                "size": 1024 * 1024 * 2.5,
                "modified": current_time - 86400,
                "extension": "docx",
                "is_dir": False
            },
            {
                "name": "Project Notes.txt",
                "path": "/home/admin/Notes/Project Notes.txt",
                "device": "Server-01 (Remote Managed)",
                "device_id": "789012",
                "size": 1024 * 15,
                "modified": current_time - 86400 * 3,
                "extension": "txt",
                "is_dir": False
            }
        ]
        
        if device_id:
            results = [r for r in results if r.get("device_id") == device_id]
            
        return results
        
    def _display_search_results(self, results):
        """Display search results"""
        self.files_table.setRowCount(0)
        self.search_results = results
        self.path_label.setText(f"Search Results: {len(results)} items found")
        
        for i, file_info in enumerate(results):
            self.files_table.insertRow(i)
            
            # File name with device info
            name_text = f"{file_info.get('name')} (on {file_info.get('device', 'Unknown Device')})"
            name_item = QTableWidgetItem(name_text)
            icon_type = "dir" if file_info.get("is_dir") else file_info.get("extension", "").lower()
            name_item.setIcon(self._get_icon(icon_type))
            name_item.setData(Qt.UserRole, file_info)
            self.files_table.setItem(i, 0, name_item)
            
            # Size
            is_dir = file_info.get("is_dir", False)
            size_str = "<DIR>" if is_dir else self._format_size(file_info.get("size", 0))
            size_item = QTableWidgetItem(size_str)
            size_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            self.files_table.setItem(i, 1, size_item)
            
            # Type
            ext = file_info.get("extension", "").lower()
            file_type = "Directory" if is_dir else f"{ext.upper()} File"
            self.files_table.setItem(i, 2, QTableWidgetItem(file_type))
            
            # Modified
            mod_time = datetime.fromtimestamp(file_info.get("modified", 0)).strftime("%Y-%m-%d %H:%M:%S")
            self.files_table.setItem(i, 3, QTableWidgetItem(mod_time))
            
            # Actions
            action_btn = QPushButton("Actions")
            action_btn.clicked.connect(lambda _, row=i: self._show_file_actions(row))
            self.files_table.setCellWidget(i, 4, action_btn)
            
        self.status_label.setText(f"Found {len(results)} items matching your query")

    def _show_advanced_search(self):
        """Show advanced search dialog"""
        dialog = AdvancedSearchDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            params = dialog.get_search_parameters()
            self.status_label.setText("Searching with advanced parameters...")
            device_id = self.device_combo.currentData() if self.device_combo.currentIndex() > 0 else None
                
            try:
                results = self._perform_advanced_search(params, device_id)
                self._display_search_results(results)
            except Exception as e:
                logger.error(f"Error searching files: {e}")
                self.status_label.setText(f"Error searching: {str(e)}")
                
    def _perform_advanced_search(self, params, device_id=None):
        """Perform advanced file search"""
        # For simplicity, use the basic search for now with the filename parameter
        return self._perform_search(params.get("filename", ""), device_id)
    
    def _apply_filter(self, index):
        """Apply file type filter"""
        filter_type = self.filter_combo.currentText()
        
        # If there are no files shown, skip filtering
        if self.files_table.rowCount() == 0:
            return
            
        for row in range(self.files_table.rowCount()):
            file_info = self.files_table.item(row, 0).data(Qt.UserRole)
            if not file_info:
                continue
                
            is_dir = file_info.get("is_dir", False)
            extension = file_info.get("extension", "").lower()
            
            # Always show all files or directories
            if filter_type == "All Files" or is_dir:
                self.files_table.setRowHidden(row, False)
                continue
                
            # Apply filter based on type
            show_row = False
            if filter_type == "Documents" and extension in ["doc", "docx", "pdf", "txt", "rtf", "odt", "xlsx", "pptx"]:
                show_row = True
            elif filter_type == "Images" and extension in ["jpg", "jpeg", "png", "gif", "bmp", "tiff"]:
                show_row = True
            elif filter_type == "Videos" and extension in ["mp4", "avi", "mov", "wmv", "mkv"]:
                show_row = True
            elif filter_type == "Audio" and extension in ["mp3", "wav", "flac", "aac", "ogg"]:
                show_row = True
            elif filter_type == "Archives" and extension in ["zip", "rar", "7z", "tar", "gz"]:
                show_row = True
            elif filter_type == "Code" and extension in ["py", "java", "c", "cpp", "js", "html", "css", "php"]:
                show_row = True
                
            self.files_table.setRowHidden(row, not show_row)
        
    def _show_file_actions(self, row):
        """Show actions menu for a file"""
        file_info = self.files_table.item(row, 0).data(Qt.UserRole)
        
        menu = QMenu(self)
        
        # Create action items based on file type
        if file_info.get("is_dir"):
            menu.addAction("Open").triggered.connect(lambda: self._open_directory(file_info))
        else:
            menu.addAction("Download").triggered.connect(lambda: self._download_file(file_info))
            menu.addAction("Open").triggered.connect(lambda: self._open_file(file_info))
            
        menu.addSeparator()
        menu.addAction("Copy").triggered.connect(lambda: self._copy_file(file_info))
        menu.addAction("Move/Rename").triggered.connect(lambda: self._move_file(file_info))
        menu.addAction("Delete").triggered.connect(lambda: self._delete_file(file_info))
        
        button = self.files_table.cellWidget(row, 4)
        menu.exec_(button.mapToGlobal(button.rect().center()))
        
    def _show_context_menu(self, pos):
        """Show context menu for selected files"""
        selected_rows = self.files_table.selectionModel().selectedRows()
        if not selected_rows:
            return
            
        menu = QMenu(self)
        
        # Special actions for single selection
        if len(selected_rows) == 1:
            row = selected_rows[0].row()
            file_info = self.files_table.item(row, 0).data(Qt.UserRole)
            
            if file_info.get("is_dir"):
                menu.addAction("Open Directory").triggered.connect(lambda: self._open_directory(file_info))
            else:
                menu.addAction("Open File").triggered.connect(lambda: self._open_file(file_info))
                
        # Multi-selection actions
        menu.addSeparator()
        menu.addAction(f"Download Selected ({len(selected_rows)})").triggered.connect(self._download_selected)
        menu.addAction(f"Copy Selected ({len(selected_rows)})").triggered.connect(self._copy_selected)
        menu.addAction(f"Delete Selected ({len(selected_rows)})").triggered.connect(self._delete_selected)
        
        menu.exec_(self.files_table.mapToGlobal(pos))
        
    def _on_file_double_clicked(self, index):
        """Handle double-click on file"""
        row = index.row()
        file_info = self.files_table.item(row, 0).data(Qt.UserRole)
        
        if file_info.get("is_dir"):
            self._open_directory(file_info)
        else:
            self._open_file(file_info)
            
    def _open_directory(self, dir_info):
        """Open a directory"""
        path = dir_info.get("path")
        device_id = dir_info.get("device_id")
        
        # Switch device if needed
        if device_id and device_id != self.selected_device:
            for i in range(1, self.device_combo.count()):
                if self.device_combo.itemData(i) == device_id:
                    self.device_combo.setCurrentIndex(i)
                    break
        
        # Properly format path based on OS
        if self.is_windows and ":" in path:
            path = self._sanitize_windows_path(path)
        
        # Try to find and select path in tree
        root = self.dir_tree.invisibleRootItem()
        for i in range(root.childCount()):
            if self._find_and_select_path(root.child(i), path):
                break
        else:
            # Not found in tree, load directly
            self.current_directory = path
            self.path_label.setText(f"{dir_info.get('device', 'Unknown Device')}: {self._format_path_for_display(path)}")
            self._load_files(path)
            
    def _find_and_select_path(self, item, target_path):
        """Recursively find and select a path in directory tree"""
        path = item.data(0, Qt.UserRole)
        
        # Handle case differences in Windows paths
        if self.is_windows and path and target_path:
            path = path.lower()
            target_path = target_path.lower()
        
        if path == target_path:
            self.dir_tree.setCurrentItem(item)
            self._on_directory_selected(item, 0)
            return True
            
        # Check children
        for i in range(item.childCount()):
            child = item.child(i)
            child_path = child.data(0, Qt.UserRole)
            
            if not child_path:
                continue
            
            # Normalize paths for comparison
            if self.is_windows and child_path and target_path:
                child_path = child_path.lower()
                target_path_lower = target_path.lower()
                
                # Special comparison for Windows paths
                if target_path_lower.startswith(child_path) or (
                    child_path.endswith("\\") and target_path_lower.startswith(child_path[:-1])):
                    item.setExpanded(True)
                    
                    # Load subdirs if needed
                    if child.childCount() == 1 and child.child(0).text(0) == "Loading...":
                        self._on_directory_selected(child, 0)
                        
                    if self._find_and_select_path(child, target_path):
                        return True
            else:
                # Unix-style path comparison
                if target_path.startswith(child_path):
                    item.setExpanded(True)
                    
                    # Load subdirs if needed
                    if child.childCount() == 1 and child.child(0).text(0) == "Loading...":
                        self._on_directory_selected(child, 0)
                        
                    if self._find_and_select_path(child, target_path):
                        return True
                    
        return False

    # File operations
    def _download_file(self, file_info):
        """Download a file"""
        file_name = file_info.get("name")
        file_path = file_info.get("path")
        device_id = file_info.get("device_id", self.selected_device)
        
        # Ask for save location
        file_dialog = QFileDialog()
        file_dialog.setAcceptMode(QFileDialog.AcceptSave)
        file_dialog.selectFile(file_name)
        
        if file_dialog.exec_():
            save_path = file_dialog.selectedFiles()[0]
            self.status_label.setText(f"Downloading {file_name} to {save_path}...")
            
            # Use device manager if available
            if hasattr(self.device_manager, 'send_file'):
                try:
                    # Ensure proper path format for the OS
                    remote_path = file_path
                    if self.is_windows and ":" in file_path:
                        remote_path = self._sanitize_windows_path(file_path)
                    
                    self.device_manager.send_file(device_id, remote_path, save_path)
                    QTimer.singleShot(100, lambda: self._download_complete(file_name, save_path))
                except Exception as e:
                    logger.error(f"Error downloading file: {e}")
                    self.status_label.setText(f"Error: {str(e)}")
                    QMessageBox.warning(self, "Download Error", str(e))
            else:
                # Demo mode
                QTimer.singleShot(1000, lambda: self._download_complete(file_name, save_path))
            
    def _download_complete(self, file_name, save_path):
        """Handle download completion"""
        self.status_label.setText(f"Downloaded {file_name} to {save_path}")
        QMessageBox.information(self, "Download Complete", f"File {file_name} has been downloaded to {save_path}")

    def _download_selected(self):
        """Download selected files"""
        selected_rows = self.files_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.warning(self, "No Selection", "Please select files to download.")
            return
            
        # Ask for save directory
        file_dialog = QFileDialog()
        file_dialog.setFileMode(QFileDialog.DirectoryOnly)
        file_dialog.setWindowTitle("Select Download Directory")
        
        if file_dialog.exec_():
            save_dir = file_dialog.selectedFiles()[0]
            file_count = 0
            
            # Process each selected file
            for row_idx in selected_rows:
                row = row_idx.row()
                file_info = self.files_table.item(row, 0).data(Qt.UserRole)
                
                # Skip directories for now
                if not file_info.get("is_dir"):
                    file_name = file_info.get("name")
                    file_path = file_info.get("path")
                    device_id = file_info.get("device_id", self.selected_device)
                    save_path = os.path.join(save_dir, file_name)
                    
                    self.status_label.setText(f"Downloading {file_name} to {save_dir}...")
                    
                    # Use device manager if available
                    if hasattr(self.device_manager, 'send_file'):
                        try:
                            # Ensure proper path format for the OS
                            remote_path = file_path
                            if self.is_windows and ":" in file_path:
                                remote_path = self._sanitize_windows_path(file_path)
                            
                            self.device_manager.send_file(device_id, remote_path, save_path)
                            file_count += 1
                        except Exception as e:
                            logger.error(f"Error downloading {file_name}: {e}")
                    else:
                        # Demo mode
                        file_count += 1
            
            # Show completion after all files are processed
            if file_count > 0:
                QTimer.singleShot(500, lambda: self._bulk_download_complete(file_count, save_dir))
            else:
                self.status_label.setText("No files were downloaded")

    def _bulk_download_complete(self, count, save_dir):
        """Handle bulk download completion"""
        self.status_label.setText(f"Downloaded {count} files to {save_dir}")
        QMessageBox.information(self, "Download Complete", f"{count} files have been downloaded to {save_dir}")
        
    def _open_file(self, file_info):
        """Preview a file"""
        file_name = file_info.get("name")
        file_path = file_info.get("path")
        
        # In a real implementation, first download the file to a temp location, then open it
        self.status_label.setText(f"Opening {file_name}...")
        
        # For demo purposes
        QMessageBox.information(self, "Open File", f"Opening file: {file_name} from {file_path}")
        
    def _copy_file(self, file_info):
        """Copy a file"""
        QMessageBox.information(self, "Copy File", "File copy functionality will be implemented here.")
        
    def _copy_selected(self):
        """Copy selected files"""
        selected_rows = self.files_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.warning(self, "No Selection", "Please select files to copy.")
            return
            
        QMessageBox.information(self, "Copy Files", f"Copying {len(selected_rows)} files")
        
    def _move_file(self, file_info):
        """Move or rename a file"""
        QMessageBox.information(self, "Move/Rename File", "File move/rename functionality will be implemented here.")
        
    def _delete_file(self, file_info):
        """Delete a file"""
        file_name = file_info.get("name")
        file_path = file_info.get("path")
        device_id = file_info.get("device_id", self.selected_device)
        
        reply = QMessageBox.question(self, "Delete File", 
                                 f"Are you sure you want to delete '{file_name}'?",
                                 QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
                                 
        if reply == QMessageBox.Yes:
            # In a real implementation, use DeviceManager to delete the file
            self.status_label.setText(f"Deleting {file_name}...")
            
            if hasattr(self.device_manager, 'execute_command'):
                try:
                    # Prepare for OS-specific command
                    if self.is_windows:
                        # Clean up Windows path
                        windows_path = self._sanitize_windows_path(file_path)
                        cmd = f"del /q \"{windows_path}\""
                    else:
                        cmd = f"rm -f \"{file_path}\""
                    
                    result = self.device_manager.execute_command(device_id, cmd)
                    
                    # Check if successful (command usually won't return anything if successful)
                    if result == "" or result is None:
                        QTimer.singleShot(100, lambda: self._delete_complete(file_name))
                    else:
                        self.status_label.setText(f"Error deleting {file_name}: {result}")
                        QMessageBox.warning(self, "Delete Failed", result)
                except Exception as e:
                    logger.error(f"Error deleting file: {e}")
                    self.status_label.setText(f"Error: {str(e)}")
                    QMessageBox.warning(self, "Delete Error", str(e))
            else:
                # Demo mode - simulate successful deletion
                QTimer.singleShot(1000, lambda: self._delete_complete(file_name))
            
    def _delete_complete(self, file_name):
        """Handle file deletion completion"""
        self.status_label.setText(f"Deleted {file_name}")
        
        # Refresh file list
        if self.current_directory:
            self._load_files(self.current_directory)
        
    def _delete_selected(self):
        """Delete selected files"""
        selected_rows = self.files_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.warning(self, "No Selection", "Please select files to delete.")
            return
            
        reply = QMessageBox.question(self, "Delete Files", 
                                 f"Are you sure you want to delete {len(selected_rows)} files?",
                                 QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
                                 
        if reply == QMessageBox.Yes:
            # In a real implementation, use DeviceManager to delete the files
            self.status_label.setText(f"Deleting {len(selected_rows)} files...")
            
            # For each selected file
            for row_idx in selected_rows:
                row = row_idx.row()
                file_info = self.files_table.item(row, 0).data(Qt.UserRole)
                file_path = file_info.get("path")
                device_id = file_info.get("device_id", self.selected_device)
                
                if hasattr(self.device_manager, 'execute_command'):
                    try:
                        if self.is_windows:
                            # Clean up Windows path
                            windows_path = self._sanitize_windows_path(file_path)
                            cmd = f"del /q \"{windows_path}\""
                        else:
                            cmd = f"rm -f \"{file_path}\""
                        
                        self.device_manager.execute_command(device_id, cmd)
                    except Exception as e:
                        logger.error(f"Error deleting {file_path}: {e}")
            
            # Simulate deletion for demo purposes
            QTimer.singleShot(1000, lambda: self._bulk_delete_complete(len(selected_rows)))
            
    def _bulk_delete_complete(self, count):
        """Handle bulk file deletion completion"""
        self.status_label.setText(f"Deleted {count} files")
        
        # Refresh file list
        if self.current_directory:
            self._load_files(self.current_directory)
            
    def _create_new_folder(self):
        """Create a new folder"""
        if not self.current_directory:
            QMessageBox.warning(self, "No Directory", "Please select a directory first.")
            return
            
        folder_name, ok = QInputDialog.getText(self, "New Folder", "Enter folder name:")
        
        if ok and folder_name:
            # In a real implementation, use DeviceManager to create the folder
            self.status_label.setText(f"Creating folder {folder_name}...")
            
            if hasattr(self.device_manager, 'execute_command'):
                try:
                    # Handle OS-specific path and command
                    if self.is_windows:
                        windows_path = self._sanitize_windows_path(self.current_directory)
                        if windows_path.endswith("\\"):
                            new_folder_path = f"{windows_path}{folder_name}"
                        else:
                            new_folder_path = f"{windows_path}\\{folder_name}"
                        cmd = f"mkdir \"{new_folder_path}\""
                    else:
                        # Create new folder path
                        new_folder_path = os.path.join(self.current_directory, folder_name).replace("\\", "/")
                        cmd = f"mkdir -p \"{new_folder_path}\""
                    
                    result = self.device_manager.execute_command(self.selected_device, cmd)
                    
                    # Check if successful
                    if result == "" or result is None:
                        QTimer.singleShot(100, lambda: self._folder_created(folder_name))
                    else:
                        self.status_label.setText(f"Error creating folder: {result}")
                        QMessageBox.warning(self, "Folder Creation Failed", result)
                except Exception as e:
                    logger.error(f"Error creating folder: {e}")
                    self.status_label.setText(f"Error: {str(e)}")
                    QMessageBox.warning(self, "Folder Creation Error", str(e))
            else:
                # Demo mode - simulate successful folder creation
                QTimer.singleShot(1000, lambda: self._folder_created(folder_name))
            
    def _folder_created(self, folder_name):
        """Handle folder creation completion"""
        self.status_label.setText(f"Created folder {folder_name}")
        
        # Refresh directory tree and file list
        self.refresh_directory_tree()
        if self.current_directory:
            self._load_files(self.current_directory)
            
    def _upload_file(self):
        """Upload a file to current directory"""
        if not self.current_directory:
            QMessageBox.warning(self, "No Directory", "Please select a directory first.")
            return
            
        # Ask for file(s) to upload
        file_dialog = QFileDialog()
        file_dialog.setFileMode(QFileDialog.ExistingFiles)
        
        if file_dialog.exec_():
            file_paths = file_dialog.selectedFiles()
            
            # Upload each file
            for file_path in file_paths:
                file_name = os.path.basename(file_path)
                
                # In a real implementation, use DeviceManager to upload the file
                self.status_label.setText(f"Uploading {file_name}...")
                
                if hasattr(self.device_manager, 'send_file'):
                    try:
                        # Prepare remote path based on OS
                        if self.is_windows:
                            windows_path = self._sanitize_windows_path(self.current_directory)
                            if windows_path.endswith("\\"):
                                remote_path = f"{windows_path}{file_name}"
                            else:
                                remote_path = f"{windows_path}\\{file_name}"
                        else:
                            remote_path = os.path.join(self.current_directory, file_name).replace("\\", "/")
                        
                        # Send file to remote device
                        success = self.device_manager.send_file(
                            self.selected_device,
                            file_path,  # Local file path
                            remote_path  # Remote path
                        )
                        
                        if success:
                            QTimer.singleShot(100, lambda name=file_name: self._upload_complete(name))
                        else:
                            self.status_label.setText(f"Error uploading {file_name}")
                            QMessageBox.warning(self, "Upload Failed", f"Failed to upload {file_name} to the remote device.")
                    except Exception as e:
                        logger.error(f"Error uploading file: {e}")
                        self.status_label.setText(f"Error: {str(e)}")
                        QMessageBox.warning(self, "Upload Error", str(e))
                else:
                    # Demo mode - simulate successful upload
                    QTimer.singleShot(2000, lambda name=file_name: self._upload_complete(name))
                
    def _upload_complete(self, file_name):
        """Handle file upload completion"""
        self.status_label.setText(f"Uploaded {file_name}")
        
        # Refresh file list
        if self.current_directory:
            self._load_files(self.current_directory)


class AdvancedSearchDialog(QDialog):
    """Dialog for advanced search options"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Advanced Search")
        self.setMinimumWidth(400)
        
        layout = QVBoxLayout(self)
        form = QFormLayout()
        
        # Search fields
        self.filename_edit = QLineEdit()
        form.addRow("File Name:", self.filename_edit)
        
        self.content_edit = QLineEdit()
        form.addRow("File Content:", self.content_edit)
        
        self.type_combo = QComboBox()
        self.type_combo.addItems(["All Files", "Documents", "Images", "Videos", "Audio", "Archives", "Code"])
        form.addRow("File Type:", self.type_combo)
        
        # Size options (in a horizontal layout)
        size_layout = QHBoxLayout()
        self.min_size_edit = QLineEdit()
        self.min_size_edit.setPlaceholderText("Min")
        self.max_size_edit = QLineEdit()
        self.max_size_edit.setPlaceholderText("Max")
        self.size_unit_combo = QComboBox()
        self.size_unit_combo.addItems(["B", "KB", "MB", "GB"])
        self.size_unit_combo.setCurrentText("MB")
        
        size_layout.addWidget(self.min_size_edit)
        size_layout.addWidget(QLabel("to"))
        size_layout.addWidget(self.max_size_edit)
        size_layout.addWidget(self.size_unit_combo)
        form.addRow("Size:", size_layout)
        
        # Date options (in a horizontal layout)
        date_layout = QHBoxLayout()
        self.start_date_edit = QLineEdit()
        self.start_date_edit.setPlaceholderText("YYYY-MM-DD")
        self.end_date_edit = QLineEdit()
        self.end_date_edit.setPlaceholderText("YYYY-MM-DD")
        
        date_layout.addWidget(self.start_date_edit)
        date_layout.addWidget(QLabel("to"))
        date_layout.addWidget(self.end_date_edit)
        form.addRow("Modified:", date_layout)
        
        layout.addLayout(form)
        
        # Dialog buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
        
    def get_search_parameters(self):
        """Get search parameters from dialog fields"""
        return {
            "filename": self.filename_edit.text(),
            "content": self.content_edit.text(),
            "file_type": self.type_combo.currentText(),
            "min_size": self.min_size_edit.text,
            "max_size": self.max_size_edit.text(),
            "size_unit": self.size_unit_combo.currentText(),
            "start_date": self.start_date_edit.text(),
            "end_date": self.end_date_edit.text(),}

            