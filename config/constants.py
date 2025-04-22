"""
Application constants and definitions
"""

# Application information
APP_NAME = "Network Scanner & Management Tool"
APP_VERSION = "1.0.0"
APP_AUTHOR = "AnoirELGUEDDAR"

# Network scanning constants
DEFAULT_TIMEOUT = 3  # seconds
MAX_THREADS = 100
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    115: "SFTP",
    135: "MSRPC",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    443: "HTTPS",
    445: "SMB",
    587: "SMTP-TLS",
    631: "IPP",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1434: "MSSQL-Browser",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt"
}