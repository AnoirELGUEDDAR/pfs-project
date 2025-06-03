"""
MonitoringTab - Interface for Prometheus and Grafana integration
Current Date and Time (UTC): 2025-05-13 00:27:14
Author: AnoirELGUEDDAR
"""

import json
import socket
import subprocess
import os
import ipaddress
import webbrowser
from datetime import datetime

try:
    # Try importing PyQt5 first
    from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, 
                               QTreeWidget, QTreeWidgetItem, QGroupBox, QFormLayout, 
                               QTabWidget, QFileDialog, QMessageBox, QSplitter)
    from PyQt5.QtCore import Qt
except ImportError:
    try:
        # Fall back to PySide2
        from PySide2.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, 
                                    QTreeWidget, QTreeWidgetItem, QGroupBox, QFormLayout, 
                                    QTabWidget, QFileDialog, QMessageBox, QSplitter)
        from PySide2.QtCore import Qt
    except ImportError:
        # If both fail, try PyQt6
        from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, 
                                 QTreeWidget, QTreeWidgetItem, QGroupBox, QFormLayout, 
                                 QTabWidget, QFileDialog, QMessageBox, QSplitter)
        from PyQt6.QtCore import Qt

# Constants
WINDOWS_EXPORTER_PORT = 9182
LINUX_EXPORTER_PORT = 9100
GRAFANA_URL = "http://localhost:3000"
WINDOWS_DASHBOARD_ID = "cedu9anr3yuwwc"
LINUX_DASHBOARD_ID = "Xcedu9anr3yuwwcX"


class MonitoringTab(QWidget):
    def __init__(self, parent=None, device_manager=None):
        super().__init__(parent)
        self.device_manager = device_manager  # This should be the ScannerTab instance
        self.windows_targets = []
        self.linux_targets = []
        self.mobile_devices = []  # New list for mobile devices
        self.prometheus_config_path = ""
        self.scanner_devices = []  # Direct access to scanner devices
        
        # Check for required modules
        self.check_required_modules()
        
        # Create the main layout
        self.main_layout = QVBoxLayout(self)
        self._setup_ui()
    
    def check_required_modules(self):
        """Check for required modules and show warnings if missing"""
        self.missing_modules = []
        
        # Check for requests (needed for Prometheus HTTP API)
        try:
            import requests
        except ImportError:
            self.missing_modules.append("requests")
        
        # Check for psutil (used for process management)
        try:
            import psutil
        except ImportError:
            self.missing_modules.append("psutil")
        
        # Log the missing modules but don't show popup immediately
        if self.missing_modules:
            print(f"Warning: Missing modules: {', '.join(self.missing_modules)}")
        
    def _setup_ui(self):
        """Set up the user interface components"""
        # Configuration Group
        config_group = QGroupBox("Configuration")
        config_layout = QFormLayout()
        
        # Prometheus config path and browse button
        prom_layout = QHBoxLayout()
        self.prom_path_label = QLabel("")
        prom_layout.addWidget(self.prom_path_label)
        self.browse_btn = QPushButton("Browse")
        self.browse_btn.clicked.connect(self.browse_config)
        prom_layout.addWidget(self.browse_btn)
        config_layout.addRow("Prometheus Config:", prom_layout)
        
        # Button layout
        button_layout = QHBoxLayout()
        
        # Apply config button
        self.apply_btn = QPushButton("Apply to Prometheus")
        self.apply_btn.clicked.connect(self.apply_to_prometheus)
        button_layout.addWidget(self.apply_btn)
        
        # Reload button
        self.reload_btn = QPushButton("Reload Prometheus")
        self.reload_btn.clicked.connect(self.reload_prometheus)
        button_layout.addWidget(self.reload_btn)
        
        # Import from device manager button
        self.import_btn = QPushButton("Import from Device Manager")
        self.import_btn.clicked.connect(self.import_from_device_manager)
        button_layout.addWidget(self.import_btn)
        
        # Dashboard buttons
        self.win_dash_btn = QPushButton("Open Windows Dashboard")
        self.win_dash_btn.clicked.connect(self.open_windows_dashboard)
        button_layout.addWidget(self.win_dash_btn)
        
        self.linux_dash_btn = QPushButton("Open Linux Dashboard")
        self.linux_dash_btn.clicked.connect(self.open_linux_dashboard)
        button_layout.addWidget(self.linux_dash_btn)
        
        # Debug Button (useful for diagnostics)
        self.debug_btn = QPushButton("Debug")
        self.debug_btn.clicked.connect(self.debug_prometheus_labels)
        button_layout.addWidget(self.debug_btn)
        
        config_layout.addRow("", button_layout)
        
        # Status label
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: blue;")
        config_layout.addRow("Status:", self.status_label)
        
        config_group.setLayout(config_layout)
        self.main_layout.addWidget(config_group)
        
        # Create Targets Tabs
        self.targets_tabs = QTabWidget()
        
        # Windows tab
        self.win_tree = QTreeWidget()
        self.win_tree.setHeaderLabels(["Host", "Port", "Status"])
        self.win_tree.setColumnWidth(0, 150)
        self.win_tree.setColumnWidth(1, 80)
        self.win_tree.setColumnWidth(2, 100)
        self.targets_tabs.addTab(self.win_tree, "Windows Targets")
        
        # Linux tab
        self.linux_tree = QTreeWidget()
        self.linux_tree.setHeaderLabels(["Host", "Port", "Status"])
        self.linux_tree.setColumnWidth(0, 150)
        self.linux_tree.setColumnWidth(1, 80)
        self.linux_tree.setColumnWidth(2, 100)
        self.targets_tabs.addTab(self.linux_tree, "Linux Targets")
        
        # Add targets tabs to layout
        self.main_layout.addWidget(self.targets_tabs, 1)  # Give it stretch factor
        
        # Status Group
        status_group = QGroupBox("Status")
        status_layout = QFormLayout()
        
        # Last scan
        self.last_scan_label = QLabel("Never")
        status_layout.addRow("Last Import:", self.last_scan_label)
        
        # Windows count
        self.win_count_label = QLabel("0")
        status_layout.addRow("Windows Targets:", self.win_count_label)
        
        # Linux count
        self.linux_count_label = QLabel("0")
        status_layout.addRow("Linux Targets:", self.linux_count_label)
        
        # Mobile devices count (new)
        self.mobile_count_label = QLabel("0")
        status_layout.addRow("Mobile Devices (skipped):", self.mobile_count_label)
        
        # Missing modules warning (if any)
        if hasattr(self, 'missing_modules') and self.missing_modules:
            missing_label = QLabel(f"Missing modules: {', '.join(self.missing_modules)}")
            missing_label.setStyleSheet("color: red;")
            status_layout.addRow("Warning:", missing_label)
        
        status_group.setLayout(status_layout)
        self.main_layout.addWidget(status_group)
    
    def show_missing_modules_warning(self):
        """Show warning about missing modules if any"""
        if hasattr(self, 'missing_modules') and self.missing_modules:
            QMessageBox.warning(
                self,
                "Missing Dependencies",
                f"The following Python modules are missing and may limit functionality:\n\n"
                f"{', '.join(self.missing_modules)}\n\n"
                f"To install them, run: pip install {' '.join(self.missing_modules)}"
            )
    
    def debug_prometheus_labels(self):
        """Debug Prometheus instance labels - creates a test file with simple structure"""
        try:
            # Create test file with explicit instance
            test_dir = "monitoring"
            if not os.path.exists(test_dir):
                os.makedirs(test_dir)
                
            test_file = os.path.join(test_dir, "test_windows.json")
            test_content = [
                {
                    "targets": ["192.168.1.20:9182"],
                    "labels": {
                        "os": "windows",
                        "instance": "DESKTOP-NKODBR4",
                        "ip": "192.168.1.20"
                    }
                }
            ]
            
            with open(test_file, "w") as f:
                json.dump(test_content, f, indent=2)
                
            # Show test instructions
            QMessageBox.information(
                self,
                "Debug File Created",
                f"Test file created at {test_file}\n\n"
                "To diagnose this issue:\n"
                "1. Add the following job to Prometheus manually:\n\n"
                "  - job_name: 'test_windows'\n"
                "    file_sd_configs:\n"
                "      - files:\n"
                f"          - '{test_file}'\n"
                "    honor_labels: true\n\n"
                "2. Reload Prometheus and check targets\n"
                "3. Query: up{job='test_windows'} in Prometheus"
            )
            
            # Show any missing modules too
            self.show_missing_modules_warning()
            
            # Also, print current device info for debugging
            print("\nDEBUG - Current devices in scanner_devices:")
            for i, device in enumerate(self.scanner_devices):
                os_type = device.get('os_type', 'Unknown')
                ip = device.get('ip', 'Unknown')
                hostname = device.get('hostname', 'Unknown')
                print(f"  [{i}] IP: {ip}, Hostname: {hostname}, OS: {os_type}")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to create debug file: {str(e)}")
    
    def open_windows_dashboard(self):
        """Open Windows dashboard in browser"""
        try:
            windows_url = f"{GRAFANA_URL}/d/{WINDOWS_DASHBOARD_ID}/windows-nodes?orgId=1&refresh=30s&kiosk"
            webbrowser.open(windows_url)
            self.status_label.setText("Windows dashboard opened in browser")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to open dashboard: {str(e)}")
    
    def open_linux_dashboard(self):
        """Open Linux dashboard in browser"""
        try:
            linux_url = f"{GRAFANA_URL}/d/{LINUX_DASHBOARD_ID}/linux-nodes?orgId=1&refresh=30s&kiosk"
            webbrowser.open(linux_url)
            self.status_label.setText("Linux dashboard opened in browser")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to open dashboard: {str(e)}")
    
    def browse_config(self):
        """Browse for prometheus.yml file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Prometheus Config File",
            "",
            "YAML files (*.yml);;All Files (*)"
        )
        if file_path:
            self.prom_path_label.setText(file_path)
            self.prometheus_config_path = file_path
    
    def is_port_open(self, ip, port, timeout=0.5):
        """Check if port is open on IP"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            result = sock.connect_ex((str(ip), port))
            sock.close()
            return result == 0
        except:
            sock.close()
            return False
    
    def import_from_device_manager(self):
        """Import devices from the scanner with enhanced OS detection"""
        try:
            # Step 1: Try multiple ways to get devices from scanner
            devices = None
            
            # First attempt: Use our direct reference to scanner devices
            if hasattr(self, 'scanner_devices') and isinstance(self.scanner_devices, list):
                devices = self.scanner_devices
                print(f"Using direct scanner_devices reference: {len(devices)} devices")
            
            # Second attempt: Use the device_manager's devices attribute
            elif self.device_manager and hasattr(self.device_manager, 'devices'):
                if isinstance(self.device_manager.devices, list):
                    devices = self.device_manager.devices
                    print(f"Using device_manager.devices: {len(devices)} devices")
            
            # Third attempt: Use the device_manager's get_devices method
            elif self.device_manager and hasattr(self.device_manager, 'get_devices'):
                if callable(getattr(self.device_manager, 'get_devices')):
                    devices = self.device_manager.get_devices()
                    print(f"Using device_manager.get_devices(): {len(devices) if devices else 0} devices")
            
            # If we still don't have devices, show error
            if not devices or len(devices) == 0:
                print("No devices found to import")
                QMessageBox.warning(self, "Import Error", "No devices found to import. Please run a network scan first.")
                return
            
            print(f"Found {len(devices)} devices to process")
            
            # Step 2: Clear current targets
            self.windows_targets = []
            self.linux_targets = []
            self.mobile_devices = []  # New list for mobile devices
            
            self.win_tree.clear()
            self.linux_tree.clear()
            
            # Step 3: Process each device
            windows_count = 0
            linux_count = 0
            mobile_count = 0
            
            for device in devices:
                try:
                    # Get IP
                    ip = device.get('ip')
                    if not ip:
                        continue
                    
                    # Get OS type - now with better handling for mobile devices
                    os_type = device.get('os_type', 'Unknown')
                    print(f"Processing device: {ip}, OS: {os_type}")
                    
                    # Skip mobile devices for now - we're not monitoring them yet
                    if os_type in ['Android', 'iOS', 'Mobile Device']:
                        print(f"Device {ip} is a mobile device ({os_type}), skipping for monitoring")
                        mobile_count += 1
                        self.mobile_devices.append(device)
                        continue
                    
                    # Check for Windows exporter
                    has_windows_exporter = device.get('has_windows_exporter', False)
                    if not has_windows_exporter:
                        # Double-check port if needed
                        has_windows_exporter = self.is_port_open(ip, WINDOWS_EXPORTER_PORT)
                    
                    # Check for Linux exporter
                    has_linux_exporter = device.get('has_linux_exporter', False) 
                    if not has_linux_exporter:
                        # Double-check port if needed
                        has_linux_exporter = self.is_port_open(ip, LINUX_EXPORTER_PORT)
                    
                    hostname = device.get('hostname', '')
                    
                    # Add Windows target if exporter found or if OS is Windows and port is open
                    if has_windows_exporter or (os_type == 'Windows' and self.is_port_open(ip, WINDOWS_EXPORTER_PORT)):
                        self.windows_targets.append({
                            "ip": ip, 
                            "port": WINDOWS_EXPORTER_PORT,
                            "hostname": hostname
                        })
                        
                        item = QTreeWidgetItem()
                        item.setText(0, ip)
                        item.setText(1, str(WINDOWS_EXPORTER_PORT))
                        item.setText(2, "Online")
                        self.win_tree.addTopLevelItem(item)
                        windows_count += 1
                    
                    # Add Linux target if exporter found or if OS is Linux/Unix and port is open
                    if has_linux_exporter or (os_type == 'Linux/Unix' and self.is_port_open(ip, LINUX_EXPORTER_PORT)):
                        self.linux_targets.append({
                            "ip": ip,
                            "port": LINUX_EXPORTER_PORT,
                            "hostname": hostname
                        })
                        
                        item = QTreeWidgetItem()
                        item.setText(0, ip)
                        item.setText(1, str(LINUX_EXPORTER_PORT))
                        item.setText(2, "Online")
                        self.linux_tree.addTopLevelItem(item)
                        linux_count += 1
                
                except Exception as e:
                    print(f"Error processing device {ip if 'ip' in locals() else 'unknown'}: {e}")
            
            # Step 4: Update UI and save results
            self.win_count_label.setText(str(windows_count))
            self.linux_count_label.setText(str(linux_count))
            self.mobile_count_label.setText(str(mobile_count))
            self.last_scan_label.setText(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            
            self.save_results()
            
            # Step 5: Show final status with mobile device info
            total = windows_count + linux_count
            status_msg = f"Import successful: {windows_count} Windows and {linux_count} Linux targets found"
            
            if mobile_count > 0:
                status_msg += f" ({mobile_count} mobile devices skipped)"
            
            if total > 0 or mobile_count > 0:
                self.status_label.setText(status_msg)
            else:
                self.status_label.setText("Import complete but no exporters were detected")
            
        except Exception as e:
            import traceback
            error_msg = f"Failed to import devices: {e}"
            print(error_msg)
            traceback.print_exc()
            QMessageBox.critical(self, "Import Error", error_msg)
    
    def save_results(self):
        """Save scan results to JSON files with enhanced instance labels and mobile device support"""
        try:
            # Create monitoring directory if it doesn't exist
            monitor_dir = "monitoring"
            if not os.path.exists(monitor_dir):
                os.makedirs(monitor_dir)
                
            # Windows targets with better instance labeling
            windows_json = []
            for target in self.windows_targets:
                # Use hostname if available, otherwise use IP for instance name
                hostname = target.get('hostname', '')
                
                # Create the target entry with enhanced labeling
                windows_json.append({
                    "targets": [f"{target['ip']}:{target['port']}"],
                    "labels": {
                        "os": "windows",
                        "instance": hostname if hostname else target['ip'],
                        "ip": target['ip']  # Add IP as a separate label
                    }
                })
            
            with open(os.path.join(monitor_dir, "windows_targets.json"), "w") as f:
                json.dump(windows_json, f, indent=2)
            
            # Linux targets with better instance labeling
            linux_json = []
            for target in self.linux_targets:
                # Use hostname if available, otherwise use IP for instance name
                hostname = target.get('hostname', '')
                
                # Create the target entry with enhanced labeling
                linux_json.append({
                    "targets": [f"{target['ip']}:{target['port']}"],
                    "labels": {
                        "os": "linux",
                        "instance": hostname if hostname else target['ip'],
                        "ip": target['ip']  # Add IP as a separate label
                    }
                })
            
            with open(os.path.join(monitor_dir, "linux_targets.json"), "w") as f:
                json.dump(linux_json, f, indent=2)
            
            # If you decide to add mobile device monitoring in the future:
            # Create mobile_targets.json file for Android/iOS devices
            # (This is prepared for future use)
            mobile_targets = []
            for device in self.mobile_devices:
                os_type = device.get('os_type', '')
                ip = device.get('ip', '')
                hostname = device.get('hostname', '')
                if ip:
                    # For demonstration - in reality you'd need a proper exporter for mobile
                    mobile_targets.append({
                        "targets": [f"{ip}:9100"],  # Example port, would need actual exporter
                        "labels": {
                            "os": os_type.lower(),
                            "instance": hostname if hostname else ip,
                            "ip": ip,
                            "mobile": "true"
                        }
                    })

            # Only create the file if we have mobile targets
            if mobile_targets:
                with open(os.path.join(monitor_dir, "mobile_targets.json"), "w") as f:
                    json.dump(mobile_targets, f, indent=2)
            
            print(f"Saved {len(windows_json)} Windows targets and {len(linux_json)} Linux targets to {monitor_dir}")
            if mobile_targets:
                print(f"Also saved {len(mobile_targets)} mobile targets (for future use)")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save results: {str(e)}")
            import traceback
            traceback.print_exc()
    
    def apply_to_prometheus(self):
        """Apply discovered targets to prometheus.yml with proper instance handling"""
        if not self.prometheus_config_path:
            self.prometheus_config_path = self.prom_path_label.text()
            if not self.prometheus_config_path:
                QMessageBox.critical(self, "Error", "No Prometheus config file selected")
                return
        
        try:
            # Read existing config
            with open(self.prometheus_config_path, 'r') as f:
                config_content = f.read()
            
            # Create backup
            backup_path = f"{self.prometheus_config_path}.bak"
            with open(backup_path, 'w') as f:
                f.write(config_content)
            
            # Get current directory for full paths
            current_dir = os.path.abspath(os.path.dirname(self.prometheus_config_path))
            monitor_dir = os.path.abspath("monitoring")
            
            # Get relative paths
            try:
                win_path = os.path.relpath(os.path.join(monitor_dir, "windows_targets.json"), current_dir)
                linux_path = os.path.relpath(os.path.join(monitor_dir, "linux_targets.json"), current_dir)
            except ValueError:
                # If paths are on different drives, use absolute paths
                win_path = os.path.abspath(os.path.join(monitor_dir, "windows_targets.json"))
                linux_path = os.path.abspath(os.path.join(monitor_dir, "linux_targets.json"))
            
            # Fix path format for Prometheus (convert Windows backslashes to forward slashes)
            win_path = win_path.replace('\\', '/')
            linux_path = linux_path.replace('\\', '/')
            
            # Simplified config for Windows nodes - just honor the labels in the file
            windows_config = f"""
  - job_name: 'windows_nodes'
    file_sd_configs:
      - files:
          - '{win_path}'
    metrics_path: /metrics
    honor_labels: true
"""

            # Simplified config for Linux nodes - just honor the labels in the file
            linux_config = f"""
  - job_name: 'linux_nodes'
    file_sd_configs:
      - files:
          - '{linux_path}'
    metrics_path: /metrics
    honor_labels: true
"""
            
            # Check if configurations already exist
            modified_content = config_content
            config_changed = False
            
            if "job_name: 'windows_nodes'" not in config_content:
                # Find scrape_configs section
                if "scrape_configs:" in config_content:
                    modified_content = config_content.replace("scrape_configs:", f"scrape_configs:{windows_config}")
                else:
                    modified_content = config_content + "\nscrape_configs:" + windows_config
                config_changed = True
            else:
                # Replace existing windows_nodes job with our updated version
                import re
                pattern = r'(  - job_name: \'windows_nodes\'.*?)(?=  - job_name:|$)'
                match = re.search(pattern, modified_content, re.DOTALL)
                if match:
                    modified_content = modified_content.replace(match.group(1), windows_config)
                    config_changed = True
            
            if "job_name: 'linux_nodes'" not in modified_content:
                # Find last job
                idx = modified_content.rfind("job_name:")
                if idx >= 0:
                    # Find the end of this job block
                    end_idx = modified_content.find("  - job_name:", idx + 1)
                    if end_idx < 0:
                        # This was the last job, append to the end
                        modified_content += linux_config
                    else:
                        # Insert before the next job
                        modified_content = modified_content[:end_idx] + linux_config + modified_content[end_idx:]
                else:
                    modified_content += linux_config
                config_changed = True
            else:
                # Replace existing linux_nodes job with our updated version
                import re
                pattern = r'(  - job_name: \'linux_nodes\'.*?)(?=  - job_name:|$)'
                match = re.search(pattern, modified_content, re.DOTALL)
                if match:
                    modified_content = modified_content.replace(match.group(1), linux_config)
                    config_changed = True
            
            # Write modified config
            if config_changed:
                with open(self.prometheus_config_path, 'w') as f:
                    f.write(modified_content)
                QMessageBox.information(self, "Success", f"Prometheus configuration updated with instance labels. Backup saved to {backup_path}")
            else:
                QMessageBox.information(self, "No Changes", "Prometheus configuration already contains the required job configurations.")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to update Prometheus config: {str(e)}")
            import traceback
            traceback.print_exc()
    
    def reload_prometheus(self):
        """Reload Prometheus configuration"""
        # Check for missing modules first
        if hasattr(self, 'missing_modules') and 'requests' in self.missing_modules:
            self.show_missing_modules_warning()
        
        try:
            # Try using HTTP API first
            try:
                # Try importing requests inside the method
                import requests
                response = requests.post("http://localhost:9090/-/reload")
                if response.status_code == 200:
                    QMessageBox.information(self, "Success", "Prometheus configuration reloaded")
                    return
            except ImportError:
                # If requests module is not available, skip HTTP method and go straight to other methods
                print("Requests module not available, trying alternative methods")
            except Exception as e:
                # Other HTTP request errors
                print(f"HTTP reload failed: {e}")
            
            # On Windows, try to restart the service
            if os.name == 'nt':
                try:
                    subprocess.run(["net", "stop", "prometheus"], check=True)
                    subprocess.run(["net", "start", "prometheus"], check=True)
                    QMessageBox.information(self, "Success", "Prometheus service restarted")
                    return
                except subprocess.CalledProcessError:
                    pass  # Service might not be installed, try the next method
            
            # Try running as a process - look for prometheus.exe or prometheus binary
            try:
                import psutil
                for proc in psutil.process_iter(['pid', 'name']):
                    if proc.info['name'] in ['prometheus', 'prometheus.exe']:
                        proc_pid = proc.info['pid']
                        if os.name == 'nt':  # Windows
                            subprocess.run(["taskkill", "/F", "/PID", str(proc_pid)])
                        else:  # Linux/Unix
                            subprocess.run(["kill", "-HUP", str(proc_pid)])
                        QMessageBox.information(self, "Success", f"SIGHUP sent to Prometheus (PID: {proc_pid})")
                        return
                        
                # If we got here, Prometheus process wasn't found
                print("Prometheus process not found in process list")
                    
            except ImportError:
                # If psutil is not available, go to next method
                print("psutil module not available, trying command line methods")
            except Exception as e:
                print(f"Process handling error: {e}")
            
            # On Linux, try to send SIGHUP via command line
            if os.name != 'nt':
                try:
                    prometheus_pid = subprocess.check_output(["pgrep", "prometheus"]).decode().strip()
                    if prometheus_pid:
                        subprocess.run(["kill", "-HUP", prometheus_pid])
                        QMessageBox.information(self, "Success", "Reload signal sent to Prometheus")
                        return
                except:
                    pass
            
            # Alternative Windows method using wmic
            if os.name == 'nt':
                try:
                    # Find Prometheus process
                    output = subprocess.check_output(["wmic", "process", "where", "name='prometheus.exe'", "get", "processid"]).decode()
                    lines = output.strip().split('\n')
                    if len(lines) > 1:
                        pid = lines[1].strip()
                        if pid:
                            subprocess.run(["taskkill", "/PID", pid, "/F"])
                            
                            # Try to restart Prometheus - this part needs to be customized for your setup
                            # subprocess.Popen(["C:\\path\\to\\prometheus\\prometheus.exe", "--config.file=prometheus.yml"])
                            QMessageBox.information(self, "Success", "Prometheus killed, please restart it manually")
                            return
                except:
                    pass
            
            # If all automated methods fail, suggest manual restart
            QMessageBox.warning(
                self,
                "Manual Restart Required",
                "Could not automatically reload Prometheus. Please restart it manually:\n\n"
                "1. For Windows: Restart the Prometheus service, or\n"
                "2. For Linux: Run 'kill -HUP $(pgrep prometheus)', or\n"
                "3. Simply stop and restart Prometheus\n\n"
                "To enable automatic reloading via HTTP API, run:\n"
                "pip install requests"
            )
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to reload Prometheus: {str(e)}")