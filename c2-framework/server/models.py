from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Literal

TaskStatus = Literal["pending", "sent", "completed"]

@dataclass 
class Agent: 
    id: str
    hostname: str
    username: str
    os: str
    ip: str
    first_seen: datetime
    last_seen: datetime

@dataclass 
class Task: 
    id: str
    agent_id: str
    command: str
    created_at: datetime
    status: TaskStatus

@dataclass
class Result: 
    task_id: str
    agent_id: str
    output: str
    received_at: datetime

    