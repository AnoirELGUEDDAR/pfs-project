# enhanced_network_scan.py
import socket
import subprocess
import threading
import time
import ipaddress
from datetime import datetime

# Number of concurrent scan threads
MAX_THREADS = 20

# Discovered devices
devices = {}
lock = threading.Lock()

def scan_ip(ip):
    """Scan a single IP address"""
    try:
        # Try to ping the device
        response = subprocess.run(
            ['ping', '-n', '1', '-w', '500', str(ip)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=1
        )
        
        if response.returncode == 0:
            # Ping successful
            try:
                # Try to resolve hostname
                hostname = socket.getfqdn(str(ip))
                if hostname == str(ip):  # If hostname resolution failed
                    hostname = "Unknown"
            except:
                hostname = "Unknown"
            
            # Add to discovered devices
            with lock:
                devices[str(ip)] = {
                    'ip': str(ip),
                    'hostname': hostname,
                    'status': 'Online'
                }
                print(f"✅ {str(ip)} is online - {hostname}")
    except:
        pass  # Ignore errors

def main():
    print("Enhanced Network Scanner")
    print("=" * 30)
    
    # Get local IP and subnet
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    print(f"Your IP address: {local_ip}")
    
    # Determine subnet to scan
    ip_parts = local_ip.split('.')
    subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
    
    print(f"Scanning network: {subnet}")
    print("This will scan all 254 addresses in your subnet. Please wait...")
    start_time = time.time()
    
    # Create thread pool
    threads = []
    
    # Generate all IP addresses in subnet
    network = ipaddress.IPv4Network(subnet)
    
    # Scan all IPs in subnet (except network and broadcast addresses)
    for ip in network.hosts():
        # Wait if we have too many active threads
        while threading.active_count() > MAX_THREADS:
            time.sleep(0.1)
            
        # Start new thread
        t = threading.Thread(target=scan_ip, args=(ip,))
        t.daemon = True
        threads.append(t)
        t.start()
    
    # Wait for all threads to complete
    for t in threads:
        t.join()
    
    # Print summary
    scan_time = time.time() - start_time
    print("\nScan Complete!")
    print(f"Time taken: {scan_time:.2f} seconds")
    print(f"Devices found: {len(devices)}")
    
    # Print table of results
    if devices:
        print("\nDiscovered devices:")
        print("-" * 60)
        print(f"{'IP Address':<15} | {'Hostname':<30} | {'Status':<10}")
        print("-" * 60)
        
        for ip in sorted(devices.keys(), key=lambda x: [int(i) for i in x.split('.')]):
            device = devices[ip]
            print(f"{device['ip']:<15} | {device['hostname']:<30} | {device['status']:<10}")
    
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
    except Exception as e:
        print(f"\nError: {e}")
    finally:
        input("\nPress Enter to exit...")