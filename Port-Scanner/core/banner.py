import socket 
import ssl 
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from core.port_scan import PortResult

logger = logging.getLogger(__name__)

# Probes for services that don't speak first
# Use {host} placeholder - gets formatted per target
PROBES: dict[int, bytes] = {
    80: b"GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: scanner/0.1\r\n\r\n",
    8080: b"GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: scanner/0.1\r\n\r\n",
    8000: b"GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: scanner/0.1\r\n\r\n",
}

# Ports that need TLS wrapping before we can speak HTTP 
TLS_PORTS = {443, 8443}

def _build_probe(probe: int, host: str) -> Optional[bytes]: 
    template = PROBES.get(probe)
    if template is None:
        return None 
    return template.replace(b"{host}", host.encode())

def grab_banner(host: str, port: int, timeout: float = 3.0) -> Optional[str]: 
    sock = None 
    try: 
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(timeout) 
        raw_sock.connect((host, port))

        if port in TLS_PORTS: 
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw_sock, server_hostname=host)
        else:
            sock = raw_sock 
        
        probe = _build_probe(port, host)
        if port in TLS_PORTS: 
            probe = PROBES.get(80, b"").replace(b"{host}", host.encode())

        if probe: 
            sock.sendall(probe)

        data = sock.recv(4096)
        if not data: 
            return None
        
        banner = data.decode(errors="ignore").strip()
        return banner if banner else None
    except (socket.timeout, ConnectionResetError, ssl.SSLError, OSError) as e: 
        logger.debug("Banner grab failed for %s:%d - %s", host, port, e)
        return None
    finally:     
        if sock: 
            try:
                sock.close()
            except Exception: 
                pass

def grab_banners(
        open_ports: list[PortResult], 
        workers: int = 50, 
        timeout: float = 3.0,  
) -> dict[int, str]: 
    banners: dict[int, str] = {}

    if not open_ports:
        return banners
    
    logger.info("Grabbing banners on %d ports...", len(open_ports))

    with ThreadPoolExecutor(max_workers=workers) as pool:
        future_to_port = {
            pool.submit(grab_banner, p.host, p.port, timeout): p.port
            for p in open_ports
        }

        for future in as_completed(future_to_port): 
            port = future_to_port[future]
            try: 
                banner = future.result()
                if banner: 
                    banners[port] = banner
                    logger.debug("Port %d: %s", port, banner[:80])
            except Exception as e: 
                logger.warning("Banner grab raised for port %d: %s", port, e)

        logger.info("Got banner from %d/%d ports", len(banners), len(open_ports))
        return banners