"""
Module for discovering shared resources on the network.
Includes functionality for finding shared folders, printers, and other resources.
"""

import re
import subprocess
import platform
import socket
from typing import Dict, List, Any, Optional, Tuple

from smb.SMBConnection import SMBConnection

from utils.logger import get_logger

logger = get_logger(__name__)


class ResourceDiscovery:
    """Class for discovering shared resources on the network."""
    
    @staticmethod
    def discover_smb_shares(target_ip: str, username: str = '', password: str = '',
                           domain: str = '', timeout: int = 5) -> Dict[str, Any]:
        """
        Discover SMB shares on a target device.
        
        Args:
            target_ip: IP address of the target
            username: Username for authentication (empty for anonymous)
            password: Password for authentication (empty for anonymous)
            domain: Domain for authentication (empty for workgroup)
            timeout: Connection timeout in seconds
            
        Returns:
            Dictionary containing discovered shares and their properties
        """
        result = {
            'ip': target_ip,
            'accessible': False,
            'shares': []
        }
        
        try:
            # Get local machine name
            local_name = socket.gethostname()
            
            # Try to get remote machine name
            try:
                remote_name = socket.gethostbyaddr(target_ip)[0].split('.')[0]
            except (socket.herror, socket.timeout):
                remote_name = target_ip
            
            # Connect to SMB server
            conn = SMBConnection(username, password, local_name, remote_name, domain, use_ntlm_v2=True)
            connected = conn.connect(target_ip, 445, timeout=timeout)
            
            if connected:
                result['accessible'] = True
                
                # Get shares
                shares = conn.listShares()
                
                for share in shares:
                    share_info = {
                        'name': share.name,
                        'comment': share.comments,
                        'type': ResourceDiscovery._get_share_type(share.type),
                        'readable': False,
                        'writable': False,
                        'contents': []
                    }
                    
                    # Check if we can list contents
                    try:
                        files = conn.listPath(share.name, '/')
                        share_info['readable'] = True
                        
                        # List top-level contents (limited to first 20)
                        for file_info in files[:20]:
                            if file_info.filename in ['.', '..']:
                                continue
                                
                            share_info['contents'].append({
                                'name': file_info.filename,
                                'is_directory': file_info.isDirectory,
                                'size': file_info.file_size,
                                'create_time': file_info.create_time
                            })
                            
                        # Check write access by trying to create and delete a test file
                        test_filename = '.__write_test'
                        try:
                            with conn.openFile(share.name, f'/{test_filename}', 
                                           mode='wb', timeout=timeout) as file_obj:
                                file_obj.write(b'test')
                            conn.deleteFiles(share.name, f'/{test_filename}')
                            share_info['writable'] = True
                        except Exception:
                            share_info['writable'] = False
                            
                    except Exception as e:
                        # Can't access content
                        logger.debug(f"Cannot access contents of {share.name}: {e}")
                    
                    result['shares'].append(share_info)
                
                conn.close()
        
        except Exception as e:
            logger.error(f"Error discovering SMB shares on {target_ip}: {e}")
            result['error'] = str(e)
        
        return result
    
    @staticmethod
    def _get_share_type(type_value: int) -> str:
        """Convert share type value to readable string."""
        types = {
            0: 'DISK',
            1: 'PRINT',
            2: 'DEVICE',
            3: 'IPC',
            2147483648: 'SPECIAL'  # Hidden/administrative
        }
        return types.get(type_value, 'UNKNOWN')
    
    @staticmethod
    def discover_network_resources(use_system_tools: bool = True) -> List[Dict[str, Any]]:
        """
        Discover network resources using system tools.
        
        Args:
            use_system_tools: Whether to use system tools (net view, etc.)
            
        Returns:
            List of discovered network resources
        """
        results = []
        
        if use_system_tools:
            # Use platform-specific tools
            if platform.system() == 'Windows':
                results = ResourceDiscovery._discover_with_net_view()
            else:  # Linux/Mac
                results = ResourceDiscovery._discover_with_smbclient()
        
        return results
    
    @staticmethod
    def _discover_with_net_view() -> List[Dict[str, Any]]:
        """Discover network resources using Windows 'net view' command."""
        results = []
        
        try:
            # Get workgroups/domains
            domains = []
            net_view_result = subprocess.run