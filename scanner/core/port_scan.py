import socket 
import logging 
import time 
from dataclasses import dataclass
from typing import Literal, Callable, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils.network import RateLimiter 

logger = logging.getLogger(__name__)

PortState = Literal["open", "closed", "filtered"]

@dataclass 
class PortResult: 
    host: str 
    port: int
    state: PortState
    latency_ms: float

    @property 
    def is_open(self) -> bool: 
        return self.state == "open"

def scan_port(
        host: str,
        port: int, 
        timeout: float = 1.0, 
        rate_limiter: Optional[RateLimiter] = None
) -> PortResult: 
    if rate_limiter: 
        rate_limiter.wait() 
        
    start = time.monotonic() 
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try: 
        err = sock.connect_ex((host, port))
        if err == 0: 
            state = "open"
        elif err in (111, 61): 
            state = "closed"
        else: 
            state = "filtered"
    except socket.timeout: 
        state = "filtered"
    except OSError as e: 
        logger.debug("Port %d error: %s", port, e)
        state = "filtered"
    finally:
        sock.close()

    latency_ms = (time.monotonic() - start) * 1000 
    return PortResult(host, port, state, latency_ms)

def scan_ports(
        host: str, 
        ports: list[int], 
        workers: int = 100, 
        timeout: float = 1.0, 
        rate_limiter: Optional[RateLimiter] = None, 
        on_progress: Optional[Callable[[int, int], None]] = None, 
        only_open: bool = True
) -> list[PortResult]: 
    results = [] 
    total = len(ports) 
    completed = 0 

    logger.info("Scanning %d ports on %s (workers=%d, timeout=%.1fs)", 
                total, host, workers, timeout)
    
    try: 
        with ThreadPoolExecutor(max_workers=workers) as pool: 
            futures = {
                pool.submit(scan_port, host, p, timeout, rate_limiter): p 
                for p in ports 
            }

            for future in as_completed(futures): 
                try: 
                    result = future.result()
                    if not only_open or result.is_open:
                        results.append(result)
                except Exception as e: 
                    port = futures[future]
                    logger.warning("Failed to scan port %d: %s", port, e)
                
                completed += 1
                if on_progress:
                    on_progress(completed, total)
    except KeyboardInterrupt: 
        logger.warning("Scan interrupted by user - returning partial results")

    results.sort(key=lambda r: r.port)

    open_count = sum(1 for r in results if r.is_open)
    logger.info("Scan completed: %d open / %d scanned", open_count, total)

    return results