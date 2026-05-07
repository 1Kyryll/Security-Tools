import argparse
from pathlib import Path
from rich.console import Console

from core.detector import detect
from core.cracker import crack
from breach.hibp import is_pwned
from output.reporter import AuditResult, to_cli, to_json

console = Console()


def parse_args():
    p = argparse.ArgumentParser(description="Audit password hashes")
    p.add_argument("-i", "--input", required=True,
                   help="File of hashes, one per line")
    p.add_argument("-w", "--wordlist", required=True,
                   help="Path to wordlist (e.g., rockyou.txt)")
    p.add_argument("-a", "--algo", default=None,
                   help="Hash algorithm (auto-detected if not set)")
    p.add_argument("--check-breaches", action="store_true",
                   help="Check cracked passwords against HIBP")
    p.add_argument("--json", type=Path, default=None,
                   help="Write JSON report to this path")
    return p.parse_args()

def main() -> int: 
    args = parse_args()

    hashes = [line.strip() for line in open(args.input) if line.strip()]
    if not hashes: 
        console.print("[red]No hashes in input file.[/red]")
        return 1
    
    algo = args.algo or detect(hashes[0])
    if algo in ("unknown", "md5_or_ntlm"):
        console.print(f"[yellow]Ambiguous hash type ({algo}). Pass --algo md5 or --algo ntlm.[/yellow]")
        return 2
    if algo in ("bcrypt", "argon2", "sha512crypt"):
        console.print(f"[yellow]Detected {algo} — too slow for this tool. Use hashcat.[/yellow]")
        return 2
       
    console.print(f"[cyan]Algorithm: {algo}    Hashes: {len(hashes)}    Wordlist: {args.wordlist}[/cyan]")
    
    def progress(tried, found, total):
        console.print(f"[dim]  tried={tried:,}  cracked={found}/{total}[/dim]", end="\r")
    
    cracked_map = crack(set(hashes), algo, args.wordlist, on_progress=progress)
    console.print()  
    
    breach_counts = {}
    if args.check_breaches:
        with console.status("[cyan]Checking HIBP..."):
            for h, plaintext in cracked_map.items():
                breach_counts[h] = is_pwned(plaintext)
    
    results = [
        AuditResult(
            hash=h,
            algo=algo,
            cracked=h in cracked_map,
            plaintext=cracked_map.get(h),
            breach_count=breach_counts.get(h),
        )
        for h in hashes
    ]
    
    to_cli(results)
    if args.json:
        to_json(results, args.json)
        console.print(f"[green]✓[/green] JSON report: {args.json}")
    
    return 0


if __name__ == "__main__":
    raise SystemExit(main())