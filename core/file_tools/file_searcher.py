"""
File searching functionality across network
"""
import os
import re
import logging
import threading
import time
import socket
from datetime import datetime
from typing import List, Dict, Tuple, Optional, Callable, Generator

import smb
from smb.SMBConnection import SMBConnection
from smb.smb_structs import OperationFailure

logger = logging.getLogger(__name__)

class FileSearcher:
    """
    File searching capabilities for local and network directories
    """
    
    def __init__(self):
        self.searching = False
        self.results = []
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
    
    def search_local(self, 
                    search_term: str, 
                    search_path: str, 
                    file_extensions: Optional[List[str]] = None,
                    case_sensitive: bool = False,
                    max_results: int = 500,
                    callback: Optional[Callable] = None) -> List[Dict]:
        """
        Search for files on the local system
        
        Args:
            search_term: Text to search for (filename or content)
            search_path: Directory to start search from
            file_extensions: List of file extensions to include (None for all)
            case_sensitive: Whether search should be case sensitive
            max_results: Maximum number of results to return
            callback: Optional callback function for results
            
        Returns:
            List of dictionaries with file information
        """
        self.searching = True
        self.results = []
        self.stop_event.clear()
        start_time = time.time()
        
        logger.info(f"Starting local file search for '{search_term}' in {search_path}")
        
        try:
            # Prepare search parameters
            if not case_sensitive:
                search_pattern = re.compile(re.escape(search_term), re.IGNORECASE)
            else:
                search_pattern = re.compile(re.escape(search_term))
            
            # Start search thread
            search_thread = threading.Thread(
                target=self._search_local_worker,
                args=(search_pattern, search_path, file_extensions, max_results, callback)
            )
            search_thread.daemon = True
            search_thread.start()
            
            # Wait for search to complete or be stopped
            search_thread.join()
            
        except Exception as e:
            logger.error(f"Error during local file search: {e}")
        finally:
            self.searching = False
            
        search_time = time.time() - start_time
        logger.info(f"File search completed in {search_time:.2f} seconds. Found {len(self.results)} results")
        
        return self.results
    
    def _search_local_worker(self, 
                           search_pattern: re.Pattern, 
                           search_path: str, 
                           file_extensions: Optional[List[str]], 
                           max_results: int,
                           callback: Optional[Callable]) -> None:
        """
        Worker thread for local file search
        
        Args:
            search_pattern: Compiled regex pattern to search for
            search_path: Directory to start search from
            file_extensions: List of file extensions to include
            max_results: Maximum number of results
            callback: Optional callback function for results
        """
        try:
            for root, dirs, files in os.walk(search_path):
                if self.stop_event.is_set() or len(self.results) >= max_results:
                    break
                
                for file in files:
                    if self.stop_event.is_set() or len(self.results) >= max_results:
                        break
                    
                    # Check file extension if specified
                    if file_extensions:
                        ext = os.path.splitext(file)[1].lower().lstrip('.')
                        if ext not in file_extensions:
                            continue
                    
                    # Check if filename matches
                    if search_pattern.search(file):
                        full_path = os.path.join(root, file)
                        self._add_result(full_path, "filename_match", callback)
                        continue
                    
                    # Skip checking content for binary files or large files
                    full_path = os.path.join(root, file)
                    if not self._is_text_file(full_path) or os.path.getsize(full_path) > 10_000_000:
                        continue
                    
                    # Search file content
                    try:
                        with open(full_path, 'r', errors='ignore') as f:
                            content = f.read()
                            if search_pattern.search(content):
                                self._add_result(full_path, "content_match", callback)
                    except Exception as e:
                        logger.debug(f"Error reading file {full_path}: {e}")
            
        except Exception as e:
            logger.error(f"Error in search worker: {e}")
    
    def search_network(self, 
                      search_term: str,
                      target: str,
                      share: str,
                      username: Optional[str] = None,
                      password: Optional[str] = None,
                      file_extensions: Optional[List[str]] = None,
                      case_sensitive: bool = False,
                      max_results: int = 200,
                      callback: Optional[Callable] = None) -> List[Dict]:
        """
        Search for files on a network share
        
        Args:
            search_term: Text to search for (filename only for network search)
            target: IP address or hostname of the server
            share: Share name to search
            username: Username for authentication (None for guest)
            password: Password for authentication
            file_extensions: List of file extensions to include (None for all)
            case_sensitive: Whether search should be case sensitive
            max_results: Maximum number of results to return
            callback: Optional callback function for results
            
        Returns:
            List of dictionaries with file information
        """
        self.searching = True
        self.results = []
        self.stop_event.clear()
        start_time = time.time()
        
        logger.info(f"Starting network file search for '{search_term}' on {target}/{share}")
        
        try:
            # Prepare search parameters
            if not case_sensitive:
                search_pattern = re.compile(re.escape(search_term), re.IGNORECASE)
            else:
                search_pattern = re.compile(re.escape(search_term))
            
            # Start search thread
            search_thread = threading.Thread(
                target=self._search_network_worker,
                args=(search_pattern, target, share, username, password, 
                      file_extensions, max_results, callback)
            )
            search_thread.daemon = True
            search_thread.start()
            
            # Wait for search to complete
            search_thread.join()
            
        except Exception as e:
            logger.error(f"Error during network file search: {e}")
        finally:
            self.searching = False
            
        search_time = time.time() - start_time
        logger.info(f"Network file search completed in {search_time:.2f} seconds. Found {len(self.results)} results")
        
        return self.results
    
    def _search_network_worker(self, 
                             search_pattern: re.Pattern,
                             target: str,
                             share: str,
                             username: Optional[str],
                             password: Optional[str],
                             file_extensions: Optional[List[str]],
                             max_results: int,
                             callback: Optional[Callable]) -> None:
        """
        Worker thread for network file search
        
        Args:
            search_pattern: Compiled regex pattern to search for
            target: IP address or hostname of the server
            share: Share name to search
            username: Username for authentication
            password: Password for authentication
            file_extensions: List of file extensions to include
            max_results: Maximum number of results
            callback: Optional callback function for results
        """
        conn = None
        try:
            # Connect to the SMB share
            conn = SMBConnection(
                username or '',
                password or '',
                socket.gethostname(),
                target,
                use_ntlm_v2=True
            )
            
            if not conn.connect(target, 139):  # SMB port
                logger.error(f"Failed to connect to {target}")
                return
            
            # Search files recursively
            path = ""
            self._search_smb_path(conn, share, path, search_pattern, file_extensions, max_results, callback)
            
        except Exception as e:
            logger.error(f"Error in network search worker: {e}")
        finally:
            if conn:
                conn.close()
    
    def _search_smb_path(self, 
                        conn: SMBConnection,
                        share: str,
                        path: str,
                        search_pattern: re.Pattern,
                        file_extensions: Optional[List[str]],
                        max_results: int,
                        callback: Optional[Callable],
                        depth: int = 0) -> None:
        """
        Recursively search a SMB path for files
        
        Args:
            conn: SMB connection
            share: Share name
            path: Current path to search
            search_pattern: Compiled regex pattern
            file_extensions: List of file extensions to include
            max_results: Maximum number of results
            callback: Optional callback function
            depth: Current recursion depth
        """
        if self.stop_event.is_set() or len(self.results) >= max_results or depth > 10:
            return
        
        try:
            file_list = conn.listPath(share, path)
            
            for item in file_list:
                if self.stop_event.is_set() or len(self.results) >= max_results:
                    break
                
                # Skip . and ..
                if item.filename in ['.', '..']:
                    continue
                
                # Full path in share
                item_path = os.path.join(path, item.filename).replace('\\', '/')
                
                if item.isDirectory:
                    # Recurse into directory
                    self._search_smb_path(
                        conn, share, item_path, search_pattern, 
                        file_extensions, max_results, callback, depth + 1
                    )
                else:
                    # Check file extension
                    if file_extensions:
                        ext = os.path.splitext(item.filename)[1].lower().lstrip('.')
                        if ext not in file_extensions:
                            continue
                    
                    # Check filename match
                    if search_pattern.search(item.filename):
                        network_path = f"\\\\{conn.remote_name}\\{share}\\{item_path}"
                        self._add_result(network_path, "filename_match", callback, 
                                        size=item.file_size,
                                        last_modified=item.last_write_time)
            
        except OperationFailure as e:
            # Permission denied or other SMB error
            logger.debug(f"SMB operation failed for {path}: {e}")
        except Exception as e:
            logger.error(f"Error searching SMB path {path}: {e}")
    
    def _add_result(self, 
                  path: str, 
                  match_type: str, 
                  callback: Optional[Callable],
                  size: Optional[int] = None,
                  last_modified: Optional[float] = None) -> None:
        """
        Add a result to the results list
        
        Args:
            path: File path
            match_type: Type of match (filename_match or content_match)
            callback: Optional callback function
            size: File size in bytes
            last_modified: Last modified timestamp
        """
        try:
            # Get file stats if not provided
            if size is None or last_modified is None:
                stats = os.stat(path)
                size = stats.st_size
                last_modified = stats.st_mtime
            
            # Create result dictionary
            result = {
                "path": path,
                "filename": os.path.basename(path),
                "directory": os.path.dirname(path),
                "size": size,
                "size_formatted": self._format_size(size),
                "last_modified": last_modified,
                "last_modified_formatted": datetime.fromtimestamp(last_modified).strftime("%Y-%m-%d %H:%M:%S"),
                "match_type": match_type
            }
            
            # Add to results
            with self.lock:
                self.results.append(result)
            
            # Notify through callback
            if callback:
                callback(result)
                
        except Exception as e:
            logger.debug(f"Error adding result {path}: {e}")
    
    def stop_search(self) -> None:
        """Stop any ongoing search"""
        self.stop_event.set()
    
    def _is_text_file(self, file_path: str) -> bool:
        """
        Check if a file is likely a text file
        
        Args:
            file_path: Path to the file
            
        Returns:
            True if likely a text file, False otherwise
        """
        # Check extension first
        text_extensions = ['txt', 'log', 'xml', 'json', 'csv', 'md', 'py', 'js', 
                          'html', 'css', 'c', 'cpp', 'h', 'java', 'php', 'rb', 
                          'sh', 'bat', 'ps1', 'ini', 'cfg', 'conf']
        
        ext = os.path.splitext(file_path)[1].lower().lstrip('.')
        if ext in text_extensions:
            return True
        
        # Try to read the file and check for binary content
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
                return b'\0' not in chunk  # Binary files often contain null bytes
        except:
            return False
    
    def _format_size(self, size: int) -> str:
        """
        Format file size into human-readable string
        
        Args:
            size: Size in bytes
            
        Returns:
            Formatted size string
        """
        if size < 1024:
            return f"{size} B"
        elif size < 1024 * 1024:
            return f"{size/1024:.1f} KB"
        elif size < 1024 * 1024 * 1024:
            return f"{size/(1024*1024):.1f} MB"
        else:
            return f"{size/(1024*1024*1024):.2f} GB"