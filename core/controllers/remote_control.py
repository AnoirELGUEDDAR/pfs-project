"""
Remote control functionality for network devices
"""
import logging
import socket
import subprocess
import platform
import time
from typing import Dict, Optional, Tuple

import paramiko
if platform.system() == 'Windows':
    import winrm
    import win32com.client
    import win32api

from config.constants import REMOTE_COMMANDS
from utils.network_utils import send_wake_on_lan

logger = logging.getLogger(__name__)

class RemoteController:
    """
    Controller for remote management of network devices
    """
    
    def __init__(self):
        self.last_result = {}
    
    def send_wake_on_lan(self, mac_address: str) -> bool:
        """
        Send Wake-on-LAN packet to wake up a device
        
        Args:
            mac_address: MAC address of target device
            
        Returns:
            True if packet sent successfully, False otherwise
        """
        return send_wake_on_lan(mac_address)
    
    def shutdown_device(self, 
                       target: str, 
                       username: str = None, 
                       password: str = None, 
                       method: str = "auto") -> Dict:
        """
        Shutdown a remote device
        
        Args:
            target: IP address or hostname of target device
            username: Username for authentication
            password: Password for authentication
            method: Method to use (ssh, winrm, wmi, auto)
            
        Returns:
            Dictionary with operation result
        """
        result = {
            "success": False,
            "message": "",
            "target": target,
            "command": "shutdown"
        }
        
        # Detect method if auto
        if method == "auto":
            method = self._detect_remote_method(target)
            
        logger.info(f"Attempting to shutdown {target} using {method}")
        
        try:
            if method == "ssh":
                # Linux/Unix shutdown via SSH
                return self._ssh_command(target, username, password, "shutdown -h now")
                
            elif method == "winrm":
                # Windows shutdown via WinRM
                if platform.system() != 'Windows':
                    result["message"] = "WinRM method only available on Windows clients"
                    return result
                
                session = winrm.Session(target, auth=(username, password))
                resp = session.run_cmd('shutdown', ['/s', '/t', '0'])
                
                result["success"] = resp.status_code == 0
                result["message"] = resp.std_out.decode('utf-8')
                
            elif method == "wmi":
                # Windows shutdown via WMI
                if platform.system() != 'Windows':
                    result["message"] = "WMI method only available on Windows clients"
                    return result
                
                wmi = win32com.client.GetObject(f"winmgmts://{target}")
                for os in wmi.InstancesOf("Win32_OperatingSystem"):
                    os.Win32Shutdown(1)  # 1 = Shutdown
                    
                result["success"] = True
                result["message"] = "Shutdown command sent via WMI"
                
            else:
                result["message"] = f"Unsupported method: {method}"
        
        except Exception as e:
            result["message"] = f"Error: {str(e)}"
            logger.error(f"Error shutting down {target}: {e}")
            
        self.last_result = result
        return result
    
    def restart_device(self, 
                      target: str, 
                      username: str = None, 
                      password: str = None,
                      method: str = "auto") -> Dict:
        """
        Restart a remote device
        
        Args:
            target: IP address or hostname of target device
            username: Username for authentication
            password: Password for authentication  
            method: Method to use (ssh, winrm, wmi, auto)
            
        Returns:
            Dictionary with operation result
        """
        result = {
            "success": False,
            "message": "",
            "target": target,
            "command": "restart"
        }
        
        # Detect method if auto
        if method == "auto":
            method = self._detect_remote_method(target)
            
        logger.info(f"Attempting to restart {target} using {method}")
        
        try:
            if method == "ssh":
                # Linux/Unix restart via SSH
                return self._ssh_command(target, username, password, "reboot")
                
            elif method == "winrm":
                # Windows restart via WinRM
                if platform.system() != 'Windows':
                    result["message"] = "WinRM method only available on Windows clients"
                    return result
                    
                session = winrm.Session(target, auth=(username, password))
                resp = session.run_cmd('shutdown', ['/r', '/t', '0'])
                
                result["success"] = resp.status_code == 0
                result["message"] = resp.std_out.decode('utf-8')
                
            elif method == "wmi":
                # Windows restart via WMI
                if platform.system() != 'Windows':
                    result["message"] = "WMI method only available on Windows clients"
                    return result
                    
                wmi = win32com.client.GetObject(f"winmgmts://{target}")
                for os in wmi.InstancesOf("Win32_OperatingSystem"):
                    os.Win32Shutdown(2)  # 2 = Restart
                    
                result["success"] = True
                result["message"] = "Restart command sent via WMI"
                
            else:
                result["message"] = f"Unsupported method: {method}"
        
        except Exception as e:
            result["message"] = f"Error: {str(e)}"
            logger.error(f"Error restarting {target}: {e}")
            
        self.last_result = result
        return result
    
    def lock_device(self, 
                   target: str, 
                   username: str = None, 
                   password: str = None,
                   method: str = "auto") -> Dict:
        """
        Lock a remote device
        
        Args:
            target: IP address or hostname of target device
            username: Username for authentication
            password: Password for authentication  
            method: Method to use (ssh, winrm, wmi, auto)
            
        Returns:
            Dictionary with operation result
        """
        result = {
            "success": False,
            "message": "",
            "target": target,
            "command": "lock"
        }
        
        # Detect method if auto
        if method == "auto":
            method = self._detect_remote_method(target)
            
        logger.info(f"Attempting to lock {target} using {method}")
        
        try:
            if method == "ssh":
                # Not standard way to lock Linux via SSH
                result["message"] = "Lock via SSH not supported"
                
            elif method == "winrm":
                # Windows lock via WinRM
                if platform.system() != 'Windows':
                    result["message"] = "WinRM method only available on Windows clients"
                    return result
                    
                session = winrm.Session(target, auth=(username, password))
                # rundll32.exe user32.dll,LockWorkStation
                resp = session.run_cmd('rundll32.exe', ['user32.dll,LockWorkStation'])
                
                result["success"] = resp.status_code == 0
                result["message"] = resp.std_out.decode('utf-8')
                
            elif method == "wmi":
                # Windows lock via WMI
                if platform.system() != 'Windows':
                    result["message"] = "WMI method only available on Windows clients"
                    return result
                    
                # Create process via WMI to run rundll32.exe user32.dll,LockWorkStation
                wmi = win32com.client.GetObject(f"winmgmts://{target}")
                startup = wmi.Get("Win32_ProcessStartup").SpawnInstance_()
                startup.ShowWindow = 0
                process_id, status = wmi.Get("Win32_Process").Create(
                    "rundll32.exe user32.dll,LockWorkStation", None, startup, None)
                
                result["success"] = status == 0
                result["message"] = f"Lock command sent (status={status})"
                
            else:
                result["message"] = f"Unsupported method: {method}"
        
        except Exception as e:
            result["message"] = f"Error: {str(e)}"
            logger.error(f"Error locking {target}: {e}")
            
        self.last_result = result
        return result
    
    def send_message(self, 
                    target: str, 
                    message: str,
                    title: str = "Message",
                    username: str = None, 
                    password: str = None,
                    method: str = "auto") -> Dict:
        """
        Send a message to a remote device
        
        Args:
            target: IP address or hostname of target device
            message: Message content
            title: Message title/caption
            username: Username for authentication
            password: Password for authentication  
            method: Method to use (ssh, winrm, wmi, auto)
            
        Returns:
            Dictionary with operation result
        """
        result = {
            "success": False,
            "message": "",
            "target": target,
            "command": "message"
        }
        
        # Detect method if auto
        if method == "auto":
            method = self._detect_remote_method(target)
            
        logger.info(f"Attempting to send message to {target} using {method}")
        
        try:
            if method == "ssh":
                # Linux message via SSH (using wall command)
                return self._ssh_command(target, username, password, f"echo '{title}: {message}' | wall")
                
            elif method == "winrm":
                # Windows message via WinRM
                if platform.system() != 'Windows':
                    result["message"] = "WinRM method only available on Windows clients"
                    return result
                    
                session = winrm.Session(target, auth=(username, password))
                # Use msg.exe or PowerShell to display message
                ps_script = f'(New-Object -ComObject Wscript.Shell).Popup("{message}", 0, "{title}", 0)'
                resp = session.run_ps(ps_script)
                
                result["success"] = resp.status_code == 0
                result["message"] = resp.std_out.decode('utf-8')
                
            elif method == "wmi":
                # Windows message via WMI
                if platform.system() != 'Windows':
                    result["message"] = "WMI method only available on Windows clients"
                    return result
                    
                # Use WMI to create a process that shows a message box
                wmi = win32com.client.GetObject(f"winmgmts://{target}")
                startup = wmi.Get("Win32_ProcessStartup").SpawnInstance_()
                startup.ShowWindow = 1
                
                # Create PowerShell process to show message
                ps_cmd = f'powershell -Command "(New-Object -ComObject Wscript.Shell).Popup(\'{message}\', 0, \'{title}\', 0)"'
                process_id, status = wmi.Get("Win32_Process").Create(ps_cmd, None, startup, None)
                
                result["success"] = status == 0
                result["message"] = f"Message sent (status={status})"
                
            else:
                result["message"] = f"Unsupported method: {method}"
        
        except Exception as e:
            result["message"] = f"Error: {str(e)}"
            logger.error(f"Error sending message to {target}: {e}")
            
        self.last_result = result
        return result
    
    def execute_command(self, 
                       target: str, 
                       command: str,
                       username: str = None, 
                       password: str = None,
                       method: str = "auto") -> Dict:
        """
        Execute a command on a remote device
        
        Args:
            target: IP address or hostname of target device
            command: Command to execute
            username: Username for authentication
            password: Password for authentication  
            method: Method to use (ssh, winrm, auto)
            
        Returns:
            Dictionary with operation result
        """
        result = {
            "success": False,
            "message": "",
            "target": target,
            "command": "execute",
            "executed": command,
            "output": ""
        }
        
        # Security check - don't allow potentially destructive commands
        if self._is_dangerous_command(command):
            result["message"] = "Command rejected for security reasons"
            return result
        
        # Detect method if auto
        if method == "auto":
            method = self._detect_remote_method(target)
            
        logger.info(f"Attempting to execute command on {target} using {method}: {command}")
        
        try:
            if method == "ssh":
                # Linux command execution via SSH
                ssh_result = self._ssh_command(target, username, password, command)
                return ssh_result
                
            elif method == "winrm":
                # Windows command execution via WinRM
                if platform.system() != 'Windows':
                    result["message"] = "WinRM method only available on Windows clients"
                    return result
                    
                session = winrm.Session(target, auth=(username, password))
                resp = session.run_cmd(command)
                
                result["success"] = resp.status_code == 0
                result["output"] = resp.std_out.decode('utf-8')
                if resp.std_err:
                    result["message"] = resp.std_err.decode('utf-8')
                else:
                    result["message"] = "Command executed successfully"
                
            else:
                result["message"] = f"Unsupported method: {method}"
        
        except Exception as e:
            result["message"] = f"Error: {str(e)}"
            logger.error(f"Error executing command on {target}: {e}")
            
        self.last_result = result
        return result
    
    def _ssh_command(self, 
                    target: str, 
                    username: str, 
                    password: str, 
                    command: str) -> Dict:
        """
        Execute a command via SSH
        
        Args:
            target: IP address or hostname
            username: SSH username
            password: SSH password
            command: Command to execute
            
        Returns:
            Dictionary with operation result
        """
        result = {
            "success": False,
            "message": "",
            "target": target,
            "command": "ssh",
            "executed": command,
            "output": ""
        }
        
        client = None
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(target, username=username, password=password, timeout=5)
            
            stdin, stdout, stderr = client.exec_command(command)
            output = stdout.read().decode('utf-8')
            error = stderr.read().decode('utf-8')
            
            result["output"] = output
            if error:
                result["message"] = error
            else:
                result["message"] = "Command executed successfully"
                result["success"] = True
                
        except Exception as e:
            result["message"] = f"SSH Error: {str(e)}"
            logger.error(f"SSH error for {target}: {e}")
            
        finally:
            if client:
                client.close()
                
        return result
    
    def _detect_remote_method(self, target: str) -> str:
        """
        Try to detect the best remote control method for a target
        
        Args:
            target: IP address or hostname
            
        Returns:
            Best method as string (ssh, winrm, wmi)
        """
        # Check if SSH is available (port 22)
        ssh_available = self._check_port(target, 22)
        if ssh_available:
            return "ssh"
            
        # Check if WinRM is available (port 5985 or 5986)
        winrm_available = self._check_port(target, 5985) or self._check_port(target, 5986)
        if winrm_available:
            return "winrm"
            
        # Default to WMI for Windows hosts
        if platform.system() == 'Windows':
            return "wmi"
            
        # Default to SSH for non-Windows hosts
        return "ssh"
    
    def _check_port(self, host: str, port: int) -> bool:
        """
        Check if a port is open
        
        Args:
            host: IP address or hostname
            port: Port number
            
        Returns:
            True if port is open, False otherwise
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def _is_dangerous_command(self, command: str) -> bool:
        """
        Check if a command might be dangerous
        
        Args:
            command: Command to check
            
        Returns:
            True if command appears dangerous
        """
        command = command.lower()
        dangerous_patterns = [
            "rm -rf", "format", "mkfs", "fdisk", "dd if=",
            "shutdown", "reboot", "halt", "> /dev", ":(){", "fork bomb",
            "deltree", "rd /s", "del /f", "del /q"
        ]
        
        for pattern in dangerous_patterns:
            if pattern in command:
                return True
                
        return False