import logging
import re
import socket
import subprocess
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

COMMON_PORTS = "21,22,25,53,80,110,143,443,3306,5432,6379,8080,8443"
NMAP_TIMEOUT_SECONDS = 30

logger = logging.getLogger(__name__)

_ALLOWED_PORT_CHARS = re.compile(r"^[0-9,-]+$")
_PORT_VALUE = re.compile(r"^[1-9][0-9]{0,4}$")


def _failure_extra(event, **fields):
    return {"event": event, **fields}


def _log_failure(level, event, **fields):
    logger.log(level, event, extra=_failure_extra(event, **fields))


def _parse_port_number(value):
    if not _PORT_VALUE.fullmatch(value):
        raise ValueError("Port values must be numeric and between 1 and 65535.")

    port = int(value)
    if port > 65535:
        raise ValueError("Port values must be between 1 and 65535.")

    return port


def validate_ports(ports):
    if isinstance(ports, int):
        ports = str(ports)
    elif not isinstance(ports, str):
        raise ValueError("Ports must be a string or integer.")

    if not ports or not _ALLOWED_PORT_CHARS.fullmatch(ports):
        raise ValueError("Ports may only contain digits, commas, and hyphens.")

    if "," in ports:
        if "-" in ports:
            raise ValueError("Port lists may only contain single port values.")

        values = ports.split(",")
        if len(values) < 2 or any(not value for value in values):
            raise ValueError("Port lists must contain comma-separated port values.")

        for value in values:
            _parse_port_number(value)

        return ports

    if "-" in ports:
        values = ports.split("-")
        if len(values) != 2 or not values[0] or not values[1]:
            raise ValueError("Port ranges must use the start-end format.")

        start = _parse_port_number(values[0])
        end = _parse_port_number(values[1])
        if start > end:
            raise ValueError("Port range start must be less than or equal to end.")

        return ports

    _parse_port_number(ports)
    return ports


def _target_hostname(target_url):
    parsed = urlparse(target_url)
    hostname = parsed.hostname or parsed.path
    if not hostname:
        raise ValueError("Target URL does not contain a hostname.")

    return hostname


def _parse_nmap_xml(output):
    root = ET.fromstring(output)
    open_ports = []

    for host in root.findall("host"):
        ports = host.find("ports")
        if ports is None:
            continue

        for port in ports.findall("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue

            service = port.find("service")
            open_ports.append({
                "port": port.get("portid", ""),
                "protocol": port.get("protocol", "tcp"),
                "service": service.get("name", "") if service is not None else "",
                "status": "open",
            })

    return open_ports


def run_nmap(target_url, ports=COMMON_PORTS, resolved_ip=None):
    hostname = None
    ip = None

    try:
        validated_ports = validate_ports(ports)
        hostname = _target_hostname(target_url)
        ip = resolved_ip or socket.gethostbyname(hostname)

        command = [
            "nmap",
            "-T4",
            "--host-timeout",
            "20s",
            "-p",
            validated_ports,
            "-oX",
            "-",
            ip,
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=NMAP_TIMEOUT_SECONDS,
            check=False,
            shell=False,
        )

        if result.returncode != 0:
            _log_failure(
                logging.WARNING,
                "nmap_scan_failed",
                hostname=hostname,
                ip=ip,
                return_code=result.returncode,
                stderr=result.stderr.strip(),
            )
            return []

        return _parse_nmap_xml(result.stdout)

    except ValueError as exc:
        _log_failure(
            logging.WARNING,
            "nmap_input_rejected",
            hostname=hostname,
            ip=ip,
            error=str(exc),
        )
    except (socket.gaierror, socket.timeout) as exc:
        _log_failure(
            logging.WARNING,
            "nmap_target_resolution_failed",
            hostname=hostname,
            error_type=exc.__class__.__name__,
            error=str(exc),
        )
    except subprocess.TimeoutExpired as exc:
        _log_failure(
            logging.WARNING,
            "nmap_scan_timeout",
            hostname=hostname,
            ip=ip,
            timeout_seconds=NMAP_TIMEOUT_SECONDS,
            error=str(exc),
        )
    except FileNotFoundError as exc:
        _log_failure(
            logging.ERROR,
            "nmap_binary_not_found",
            hostname=hostname,
            ip=ip,
            error=str(exc),
        )
    except ET.ParseError as exc:
        _log_failure(
            logging.WARNING,
            "nmap_output_parse_failed",
            hostname=hostname,
            ip=ip,
            error=str(exc),
        )
    except OSError as exc:
        _log_failure(
            logging.ERROR,
            "nmap_execution_error",
            hostname=hostname,
            ip=ip,
            error_type=exc.__class__.__name__,
            error=str(exc),
        )
    except Exception as exc:
        logger.exception(
            "nmap_unexpected_error",
            extra=_failure_extra(
                "nmap_unexpected_error",
                hostname=hostname,
                ip=ip,
                error_type=exc.__class__.__name__,
                error=str(exc),
            ),
        )

    return []
