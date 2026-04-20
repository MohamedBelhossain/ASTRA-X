def analyse_nmap(output):

    if isinstance(output, list):
        return output

    # Extract from python-nmap dict
    if isinstance(output, dict):
        out = []
        for host in output.get('scan', {}).values():
            for proto in ('tcp', 'udp'):
                for port, pdata in host.get(proto, {}).items():
                    if pdata.get('state') == 'open':
                        out.append({
                            'port': str(port),
                            'protocol': proto,
                            'service': pdata.get('name', ''),
                            'status': 'open'
                        })
        return out

    if isinstance(output, str):
        out = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 3 or 'open' not in parts:
                continue
            port_proto = parts[0]
            port = port_proto.split('/')[0]
            proto = port_proto.split('/')[1] if '/' in port_proto else 'tcp'
            service = parts[2]
            out.append({'port': port, 'protocol': proto, 'service': service, 'status': 'open'})
        return out

    return []