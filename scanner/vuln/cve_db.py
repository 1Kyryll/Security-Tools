import os 
import time
import logging
import json 
from nvd_client import NvdApi
from dotenv import load_dotenv
from dataclasses import dataclass, field, asdict
from typing import Literal, Optional
from pathlib import Path 

from utils.network import RateLimiter

logger = logging.getLogger(__name__)

load_dotenv()

CACHE_DIR = Path.home() / ".scanner" / "cve_cache"
CACHE_TTL_SECONDS = 7 * 24 * 3600 
DEFAULT_RATE = 50 / 30.0

api_key = os.getenv("NVD_API_KEY")
nvd_api = NvdApi(api_key)

Severity = Literal["none", "low", "medium", "high", "critical"]

@dataclass 
class CVE: 
    id: str
    cvss_score: int
    severity: Severity
    summary: str
    references: list[str] = field(default_factory=list)
    published: Optional[str] = None

CPE_MAP = {
    "openssh":  ("openbsd",        "openssh"),
    "apache":   ("apache",         "http_server"),
    "nginx":    ("nginx",          "nginx"),
    "vsftpd":   ("vsftpd_project", "vsftpd"),
    "proftpd":  ("proftpd",        "proftpd"),
    "postfix":  ("postfix",        "postfix"),
    "exim":     ("exim",           "exim"),
    "mysql":    ("oracle",         "mysql"),
    "samba":    ("samba",          "samba"),
}

def _severity(score: Optional[float]) -> str: 
    if score is None: 
        return "none"
    if score >= 9.0: 
        return "critical"
    if score >= 7.0: 
        return "high"
    if score >= 4.0: 
        return "medium" 
    if score > 0: 
        return "low"
    return "none"

def _cache_path(key: str) -> Path: 
    safe = key.replace("/", "_").replace(":", "_").replace(" ", "_")
    return CACHE_DIR / f"{safe}.json"

def _load_cache(key: str) -> Optional[list[CVE]]: 
    path = _cache_path(key)
    if not path.exists():
        return None
    
    age = time.time() - path.stat().st_mtime
    if age > CACHE_TTL_SECONDS: 
        logger.debug("Cache expired for %s (age %.0fs)", key, age)
        return None
    
    try: 
        with path.open() as f: 
            data = json.load(f)
        return [CVE(**item) for item in data]
    except (json.JSONDecodeError, TypeError) as e: 
        logger.warning("Corrupt cache for %s: %s", key, e)
        return None
    
def _save_cache(key: str, cves: list[CVE]) -> None: 
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    path = _cache_path(key)
    try: 
        with path.open("w") as f: 
            json.dump([asdict(c) for c in cves], f, indent=2)
    except OSError as e: 
        logger.warning("Failed to write cache for %s: %s", key, e)

def _parse(entry): 
    cve = entry.get("cve", entry)

    summary = next((d["value"] for d in cve.get("descriptions", [])
                    if d.get("lang") == "en"), "")
    score = None
    for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if items := cve.get("metrics", {}).get(k):
            score = items[0].get("cvssData", {}).get("baseScore")
            if score is not None:
                score = float(score)
                break

    refs = [r["url"] for r in cve.get("references", []) if r.get("url")][:5]
    return CVE(cve["id"], score, _severity(score), summary, refs)


def lookup_cves(product: str, version: str) -> list[CVE]:
    if not product or not version: 
        return [] 
    
    mapping = CPE_MAP.get(product.lower())
    if not mapping:
        return []
    
    vendor, prod = mapping
    cpe = f"cpe:2.3:a:{vendor}:{prod}:{version}:*:*:*:*:*:*:*"

    keyword = f"{product} {version}".strip() if version else product
    cache_key = keyword.lower().replace(" ", "_") 
    
    cached = _load_cache(cache_key)
    if cached is not None:
        logger.debug("Cache hit for %r (%d CVEs)", keyword, len(cached))
        return cached

    logger.info("Querying NVD for %r", keyword)
    try: 
        response = nvd_api.get_cve_by_cpe(cpe_name=cpe, per_page=50, offset=0)
    except Exception as e: 
        logger.warning("NVD lookup failed for %s: %s", cpe, e)
        return []
    
    entries = response.get("vulnerabilities", []) if isinstance(response, dict) else response or []
    cves = [_parse(e) for e in entries if e]

    _save_cache(cache_key, cves)

    return cves