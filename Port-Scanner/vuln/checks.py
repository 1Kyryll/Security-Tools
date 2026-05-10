import ftplib
import logging
from typing import Callable

import requests

from core.fingerprint import Service
from output.reporter import Finding
from vuln.cve_db import lookup_cves

logger = logging.getLogger(__name__)

requests.packages.urllib3.disable_warnings()


def check_cves(service: Service, host: str) -> list[Finding]:
    if not service.product or not service.version:
        return []
    
    cves = lookup_cves(service.product, service.version)
    return [
        Finding(
            host=host, port=service.port, service=service.name,
            severity=cve.severity,
            title=cve.id,
            description=cve.summary[:300],
            references=cve.references,
        )
        for cve in cves
    ]


def check_http_headers(service: Service, host: str) -> list[Finding]:
    if service.name not in ("http", "https"):
        return []
    
    scheme = "https" if service.name == "https" else "http"
    url = f"{scheme}://{host}:{service.port}/"
    
    try:
        r = requests.get(url, timeout=5, verify=False, allow_redirects=False)
    except requests.RequestException as e:
        logger.debug("HTTP request failed for %s: %s", url, e)
        return []
    
    expected = {
        "Strict-Transport-Security": "Missing HSTS — allows protocol downgrade attacks",
        "Content-Security-Policy":   "Missing CSP — no XSS mitigation",
        "X-Frame-Options":           "Missing X-Frame-Options — clickjacking risk",
        "X-Content-Type-Options":    "Missing — allows MIME sniffing",
    }
    
    return [
        Finding(host, service.port, service.name, "low",
                f"Missing header: {header}", desc, evidence=url)
        for header, desc in expected.items()
        if header not in r.headers
    ]


def check_anon_ftp(service: Service, host: str) -> list[Finding]:
    if service.name != "ftp":
        return []
    
    try:
        ftp = ftplib.FTP(host, timeout=5)
        ftp.login()  
        ftp.quit()
        return [Finding(
            host, service.port, "ftp", "medium",
            "Anonymous FTP enabled",
            "Server allows login with username 'anonymous' and no password.",
        )]
    except (ftplib.all_errors, OSError):
        return []


def check_default_paths(service: Service, host: str) -> list[Finding]:
    if service.name not in ("http", "https"):
        return []
    
    scheme = "https" if service.name == "https" else "http"
    base = f"{scheme}://{host}:{service.port}"
    
    sensitive = {
        "/.git/config":      ("high",     "Exposed .git config — source code likely leaked"),
        "/.env":             ("critical", "Exposed .env file — likely contains secrets"),
        "/phpinfo.php":      ("medium",   "Exposed phpinfo() — leaks server config"),
        "/server-status":    ("low",      "Apache server-status exposed"),
        "/admin/":           ("info",     "Admin path responds — review access controls"),
    }
    
    findings = []
    for path, (severity, desc) in sensitive.items():
        try:
            r = requests.get(base + path, timeout=3, verify=False, allow_redirects=False)
            if r.status_code == 200 and len(r.content) > 0:
                findings.append(Finding(
                    host, service.port, service.name, severity,
                    f"Exposed: {path}", desc, evidence=f"{base}{path} → 200",
                ))
        except requests.RequestException:
            continue
    
    return findings

ALL_CHECKS: list[Callable[[Service, str], list[Finding]]] = [
    check_cves,
    check_http_headers,
    check_anon_ftp,
    check_default_paths,
]


def run_all_checks(services: list[Service], host: str) -> list[Finding]:
    findings = []
    for service in services:
        for check in ALL_CHECKS:
            try:
                findings.extend(check(service, host))
            except Exception as e:
                logger.warning("Check %s failed on %s: %s",
                               check.__name__, service, e)
    return findings