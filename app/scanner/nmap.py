import nmap
import socket
from urllib.parse import urlparse


def run_nmap(target_url):
    try:
        parsed = urlparse(target_url)
        hostname = parsed.netloc or parsed.path
        ip = socket.gethostbyname(hostname)

        nm = nmap.PortScanner()
        nm.scan(ip, arguments='-F')

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
