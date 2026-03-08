def analyse_nmap(output):
    """
    Simple parser for nmap output
    """
    if not output or output.startswith("Error:"):
        return []
    
    open_ports = []
    

    if "'state': 'open'" in str(output):
        lines = str(output).split('\\n')
        for line in lines:
            if 'open' in line and 'tcp' in line:
              
                import re
                port_match = re.search(r'(\d+)/tcp', line)
                if port_match:
                    open_ports.append({
                        "port": port_match.group(1),
                        "status": "open"
                    })
    
    return open_ports