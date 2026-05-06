import json 
import logging
from dataclasses import dataclass, asdict, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console 
from rich.table import Table
from rich import box

from core.banner import PortResult
from core.fingerprint import Service

logger = logging.getLogger(__name__)

@dataclass
class Finding: 
    host: str
    port: int
    service: str
    severity: str 
    title: str
    description: str 
    evidence: Optional[str] = None
    references: list[str] = field(default_factory=list)

@dataclass 
class ScanReport: 
    target: str
    host: str                
    started_at: str
    finished_at: str
    duration_sec: float
    ports_scanned: int
    open_ports: list[PortResult]
    services: list[Service]
    findings: list[Finding] = field(default_factory=list)

_SEVERITY_COLORS = {
    "info":     "blue",
    "low":      "cyan",
    "medium":   "yellow",
    "high":     "red",
    "critical": "bold red",
}

def to_cli(report: ScanReport, console: Optional[Console] = None) -> None:
    console = console or Console()

    console.print()
    console.rule(f"[bold]Scan report: {report.target}[/bold]")
    console.print(
        f"[dim]Resolved:[/dim] {report.host}    "
        f"[dim]Duration:[/dim] {report.duration_sec:.2f}s    "
        f"[dim]Ports scanned:[/dim] {report.ports_scanned}"
    )
    console.print()

    if not report.open_ports:
        console.print("[yellow]No open ports found.[/yellow]")
        return
    
    table = Table(
        title=f"Open ports ({len(report.open_ports)})",
        box=box.ROUNDED,
        title_style="bold",
        header_style="bold cyan",
    )
    table.add_column("Port", justify="right", style="green")
    table.add_column("Service")
    table.add_column("Product")
    table.add_column("Version")
    table.add_column("Latency", justify="right", style="dim")

    services_by_port = {s.port: s for s in report.services}

    for p in report.open_ports: 
        svc = services_by_port.get(p.port)
        table.add_row(
            f"{p.port}/tcp",
            svc.name if svc else "unknown",
            svc.product if svc and svc.product else "[dim]—[/dim]",
            svc.version if svc and svc.version else "[dim]—[/dim]",
            f"{p.latency_ms:.0f}ms",
        )
    
    console.print(table)

    if report.findings:
        _print_findings_table(report.findings, console)
    
    console.print()

def _print_findings_table(findings: list[Finding], console: Console) -> None:
    table = Table(
        title=f"Findings ({len(findings)})",
        box=box.ROUNDED,
        title_style="bold",
        header_style="bold cyan",
    )
    table.add_column("Severity", style="bold")
    table.add_column("Port", justify="right")
    table.add_column("Title")
    table.add_column("Description", overflow="fold")
    
    # Sort by severity, then port
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for f in sorted(findings, key=lambda f: (sev_order.get(f.severity, 99), f.port)):
        color = _SEVERITY_COLORS.get(f.severity, "white")
        table.add_row(
            f"[{color}]{f.severity.upper()}[/{color}]",
            str(f.port),
            f.title,
            f.description,
        )
    
    console.print(table)
