import argparse
import ipaddress
import logging
import socket
import sys
import time
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler

from core.port_scan import scan_ports
from core.banner import grab_banners
from core.fingerprint import fingerprint
from output.reporter import ScanReport, to_cli
from utils.network import parse_port_range, RateLimiter


console = Console()


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True,
                              show_path=False, markup=True)],
    )

def _is_private_ip(ip: str) -> bool: 
    try: 
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False
    
def _resolve_target(target: str) -> str:
    try:
        ip = socket.gethostbyname(target)
        if ip != target:
            console.print(f"[dim]Resolved {target} → {ip}[/dim]")
        return ip
    except socket.gaierror as e:
        console.print(f"[red]Failed to resolve {target}: {e}[/red]")
        sys.exit(2)

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="scanner",
        description="A learning-purpose port scanner with service fingerprinting.",
        epilog="Only scan systems you own or have written permission to test.",
    )
    
    parser.add_argument(
        "-t", "--target", required=True,
        help="Target IP or hostname (e.g., 192.168.56.101 or scanme.nmap.org)",
    )
    parser.add_argument(
        "-p", "--ports", default="1-1000",
        help='Ports to scan: "80", "1-1000", "22,80,443", "1-100,8080" (default: 1-1000)',
    )
    parser.add_argument(
        "--workers", type=int, default=100,
        help="Concurrent scan threads (default: 100)",
    )
    parser.add_argument(
        "--timeout", type=float, default=1.0,
        help="Per-port connect timeout in seconds (default: 1.0)",
    )
    parser.add_argument(
        "--banner-timeout", type=float, default=3.0,
        help="Per-port banner grab timeout in seconds (default: 3.0)",
    )
    parser.add_argument(
        "--rate-limit", type=float, default=None,
        help="Maximum scan attempts per second (default: unlimited)",
    )
    parser.add_argument(
        "--skip-banners", action="store_true",
        help="Skip banner grabbing / fingerprinting",
    )
    parser.add_argument(
        "-o", "--output", choices=["cli", "json", "all"], default="cli",
        help="Output format (default: cli)",
    )
    parser.add_argument(
        "--output-file", type=Path, default=None,
        help="Path for JSON output (default: scan_<target>_<timestamp>.json)",
    )
    parser.add_argument(
        "--i-have-permission", action="store_true",
        help="Required to scan non-private IPs. You are responsible for legality.",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Show debug-level logs",
    )
    
    return parser.parse_args()

def main() -> int: 
    args = parse_args()
    _setup_logging(args.verbose)
    log = logging.getLogger("main")

    host_ip = _resolve_target(args.target)

    if not _is_private_ip(host_ip) and not args.i_have_permission: 
        console.print(
            "\n[bold red]Refusing to scan a public IP without --i-have-permission.[/bold red]\n"
            "Scanning systems without authorization is illegal in most jurisdictions.\n"
            "If you have written permission to scan this target, re-run with the flag.\n"
        )
        return 2
    
    try: 
        ports = parse_port_range(args.ports)
    except ValueError as e: 
        console.print(f"[red]Invalid port specification: {e}[/red]")
        return 2
    
    if not ports:
        console.print("[red]No ports to scan.[/red]")
        return 2
    
    rate_limiter = RateLimiter(args.rate_limit) if args.rate_limit else None
    
    started_at = datetime.now()
    t_start = time.monotonic()

    console.print(
        f"\n[bold]Scanning[/bold] {args.target} "
        f"[dim]({host_ip}, {len(ports)} ports, {args.workers} workers)[/dim]"
    )

    with console.status("[cyan]Scanning ports..."):
        open_ports = scan_ports(
            host=host_ip,
            ports=ports,
            workers=args.workers,
            timeout=args.timeout,
            rate_limiter=rate_limiter,
        )
    
    log.info("Found %d open ports", len(open_ports))

    services = []
    if open_ports and not args.skip_banners:
        with console.status("[cyan]Grabbing banners..."):
            banners = grab_banners(
                open_ports=open_ports,
                workers=min(args.workers, 50),
                timeout=args.banner_timeout,
            )
        services = [fingerprint(p.port, banners.get(p.port)) for p in open_ports]
    elif open_ports:
        services = [fingerprint(p.port, None) for p in open_ports]
    
    finished_at = datetime.now()
    duration = time.monotonic() - t_start
    
    report = ScanReport(
        target=args.target,
        host=host_ip,
        started_at=started_at.isoformat(),
        finished_at=finished_at.isoformat(),
        duration_sec=duration,
        ports_scanned=len(ports),
        open_ports=open_ports,
        services=services,
    )

    if args.output in ("cli", "all"):
        to_cli(report, console)
    
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user.[/yellow]")
        sys.exit(130)
    