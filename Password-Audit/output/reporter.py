import json 
from dataclasses import dataclass, asdict
from rich.console import Console
from rich.table import Table

@dataclass
class AuditResult:
    hash: str
    algo: str
    cracked: bool 
    plaintext: str | None
    breach_count: int | None

    @property 
    def status(self) -> str: 
        if not self.cracked:
            return "uncracked"
        if self.breach_count and self.breach_count > 0:
            return "cracked + breached"
        return "cracked"
    
def to_cli(results: list[AuditResult], console: Console = None):
    console = console or Console()
    
    table = Table(title="Password Audit Results")
    table.add_column("Hash", overflow="ellipsis", max_width=20)
    table.add_column("Algo")
    table.add_column("Plaintext")
    table.add_column("Status")
    table.add_column("Breaches", justify="right")

    for r in results:
        color = "red" if r.cracked else "green"
        table.add_row(
            r.hash[:16] + "...",
            r.algo,
            r.plaintext or "[dim]—[/dim]",
            f"[{color}]{r.status}[/{color}]",
            str(r.breach_count) if r.breach_count is not None else "[dim]—[/dim]",
        )
    
    console.print(table)

    total = len(results)
    cracked = sum(1 for r in results if r.cracked)
    breached = sum(1 for r in results if r.breach_count and r.breach_count > 0)
    console.print(f"\nCracked: {cracked}/{total}    In breach corpus: {breached}")

def to_json(results: list[AuditResult], path: str):
    with open(path, "w") as f:
        json.dump([asdict(r) for r in results], f, indent=2)