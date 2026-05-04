import ipaddress
import socket 
import time
import threading

def is_valid_ip(addr): 
    try:
        ipaddress.ip_address(addr) 
        return True
    except ValueError: 
        return False 

def resolve_host(hostname): 
    return socket.gethostbyname(hostname) 

def parse_port_range(s): 
    ports = set() 
    for part in s.split(","): 
        part = part.strip()
        if "-" in part: 
            start, end = part.split("-") 
            ports.update(range(int(start), int(end) + 1))
        else: 
            ports.add(int(part))
    return sorted(ports)

class RateLimiter: 
    def __init__(self, calls_per_sec: float):
        self.min_interval = 1.0 / calls_per_sec
        self.last_call = 0.0 
        self.lock = threading.Lock() 

    def wait(self): 
        with self.lock(): 
            now = time.monotonic()
            elapsed = now - self.last_call 
            sleep_for = self.min_interval - elapsed
            if sleep_for > 0: 
                time.sleep(sleep_for)
            self.last_call = time.monotonic()  