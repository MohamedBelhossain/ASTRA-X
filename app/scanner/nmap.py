import nmap
import socket
from urllib.parse import urlparse

COMMON_PORTS = "21,22,25,53,80,110,143,443,3306,5432,6379,8080,8443"


def run_nmap(target_url):
    try:
        parsed = urlparse(target_url)
        hostname = parsed.hostname or parsed.path
        ip = socket.gethostbyname(hostname)

        nm = nmap.PortScanner()
        nm.scan(ip, COMMON_PORTS)

        open_ports = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in nm[host][proto].keys():
                    pdata = nm[host][proto][port]
                    if pdata.get('state') == 'open':
                        open_ports.append({
                            'port': str(port),
                            'protocol': proto,
                            'service': pdata.get('name', ''),
                            'status': 'open'
                        })

        return open_ports

    except Exception:
        return []
