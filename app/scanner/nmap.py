import nmap
import socket
from urllib.parse import urlparse

def run_nmap(target_url):
    try:
        # Extract hostname
        parsed = urlparse(target_url)
        hostname = parsed.netloc if parsed.netloc else parsed.path
        
        # Get IP
        ip = socket.gethostbyname(hostname)
        
        #fast scan 
        
        nm = nmap.PortScanner()
        scan_result = nm.scan(ip, arguments='-F') 
        
        # Return the scan results as a string
        return str(scan_result)
        
    except Exception as e:
        return f"Error: {str(e)}"



