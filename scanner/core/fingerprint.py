import re 
import logging
from typing import Optional, Pattern
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class Service: 
    port: int
    name: str
    product: Optional[str] = None
    version: Optional[str] = None
    raw_banner: Optional[str] = None

    def __str__(self) -> str: 
        if self.product and self.version: 
            return f"{self.name} ({self.product} {self.version})" 
        if self.product:
            return f"{self.name} ({self.product})"
        return self.name

@dataclass 
class Signature: 
    name: str 
    pattern: Pattern[str] 
    product_group: int = 1
    version_group: int = 2

# Order matters — more specific patterns first.
SIGNATURES: list[Signature] = [
    
    # ── SSH ──────────────────────────────────────────────────────────
    # "SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1"
    # "SSH-2.0-dropbear_2019.78"
    Signature(
        name="ssh",
        pattern=re.compile(r"^SSH-[\d.]+-([A-Za-z][A-Za-z0-9]*)_([\w.]+)"),
    ),
    
    # ── HTTP (via Server header) ─────────────────────────────────────
    # "Server: Apache/2.2.8 (Ubuntu) DAV/2"
    # "Server: nginx/1.18.0"
    # "Server: Microsoft-IIS/10.0"
    Signature(
        name="http",
        pattern=re.compile(
            r"Server:\s*([A-Za-z][\w.-]*?)(?:/([\w.]+))?(?:\s|\r|$)",
            re.IGNORECASE | re.MULTILINE,
        ),
    ),
    
    # ── FTP ──────────────────────────────────────────────────────────
    # "220 (vsFTPd 2.3.4)"
    # "220 ProFTPD 1.3.5 Server ..."
    # "220-FileZilla Server 0.9.41 beta"
    # "220 Welcome to Pure-FTPd"
    Signature(
        name="ftp",
        pattern=re.compile(
            r"220[- ].*?(vsFTPd|ProFTPD|FileZilla|Pure-FTPd|Microsoft FTP|Serv-U|wu-ftpd)"
            r"[\s\(\)v]*([\d.]+)?",
            re.IGNORECASE,
        ),
    ),
    
    # ── SMTP ─────────────────────────────────────────────────────────
    # "220 host.example ESMTP Postfix (Ubuntu)"
    # "220 mail ESMTP Sendmail 8.14.4"
    # "220 Exim 4.92"
    Signature(
        name="smtp",
        pattern=re.compile(
            r"220.*?(Postfix|Sendmail|Exim|qmail|Exchange|Microsoft ESMTP)"
            r"[\s/v]*([\d.]+)?",
            re.IGNORECASE,
        ),
    ),
    
    # ── POP3 ─────────────────────────────────────────────────────────
    # "+OK Dovecot ready."
    # "+OK Microsoft Exchange Server 2003 POP3 server"
    Signature(
        name="pop3",
        pattern=re.compile(
            r"\+OK.*?(Dovecot|Exchange|qpopper|Cyrus|Courier)[\s/v]*([\d.]+)?",
            re.IGNORECASE,
        ),
    ),
    
    # ── IMAP ─────────────────────────────────────────────────────────
    # "* OK [CAPABILITY ...] Dovecot ready."
    Signature(
        name="imap",
        pattern=re.compile(
            r"\*\s*OK.*?(Dovecot|Exchange|Cyrus|Courier)[\s/v]*([\d.]+)?",
            re.IGNORECASE,
        ),
    ),
    
    # ── MySQL ────────────────────────────────────────────────────────
    # Binary handshake, but version string is ASCII embedded:
    # "\n5.0.51a-3ubuntu5\x00..."
    # We default product to "MySQL" since the protocol implies it.
    Signature(
        name="mysql",
        pattern=re.compile(r"(\d+\.\d+\.\d+[\w-]*)"),
        product_group=0,    # no product group; we'll hard-code below
        version_group=1,
    ),
    
    # ── VNC ──────────────────────────────────────────────────────────
    # "RFB 003.008\n"
    Signature(
        name="vnc",
        pattern=re.compile(r"RFB\s+0*(\d+)\.0*(\d+)"),
        product_group=0,    # no product, just version "3.8"
        version_group=1,    # we'll combine groups 1+2 manually
    ),
]

# Port → likely service name when no banner / no signature matches.
DEFAULT_SERVICES: dict[int, str] = {
    21:    "ftp",
    22:    "ssh",
    23:    "telnet",
    25:    "smtp",
    53:    "dns",
    67:    "dhcp",
    69:    "tftp",
    80:    "http",
    110:   "pop3",
    111:   "rpcbind",
    123:   "ntp",
    135:   "msrpc",
    137:   "netbios-ns",
    139:   "netbios-ssn",
    143:   "imap",
    161:   "snmp",
    389:   "ldap",
    443:   "https",
    445:   "smb",
    465:   "smtps",
    513:   "rlogin",
    514:   "shell",
    587:   "smtp-submission",
    631:   "ipp",
    636:   "ldaps",
    993:   "imaps",
    995:   "pop3s",
    1080:  "socks",
    1099:  "rmiregistry",
    1433:  "mssql",
    1521:  "oracle",
    1524:  "ingreslock",
    2049:  "nfs",
    2121:  "ftp-alt",
    3306:  "mysql",
    3389:  "rdp",
    5432:  "postgresql",
    5900:  "vnc",
    5901:  "vnc-1",
    5985:  "winrm",
    6000:  "x11",
    6379:  "redis",
    6667:  "irc",
    8000:  "http-alt",
    8009:  "ajp13",
    8080:  "http-proxy",
    8180:  "http-tomcat",
    8443:  "https-alt",
    9200:  "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
}

def fingerprint(port: int, banner: Optional[str]) -> Service: 
    default_name = DEFAULT_SERVICES.get(port, "unknown")
    
    if not banner: 
        return Service(port, default_name)
    for sig in SIGNATURES: 
        match = sig.pattern.search(banner)
        if not match: 
            continue

        try: 
            # Special cases for signatures where groups need post-processing
            if sig.name == "mysql":
                version = match.group(1)
                return Service(
                    port=port, name="mysql", product="MySQL",
                    version=version, raw_banner=banner,
                )
            if sig.name == "vnc":
                major, minor = match.group(1), match.group(2)
                return Service(
                    port=port, name="vnc", product="VNC",
                    version=f"{major}.{minor}", raw_banner=banner,
                )
        
            product = match.group(sig.product_group) if sig.product_group else None
            version = (match.group(sig.version_group) 
                       if sig.version_group <= match.lastindex else None)
            
            return Service(
                port=port, 
                name=sig.name, 
                product=product.strip() if product else None, 
                version=version.strip() if version else None, 
                raw_banner=banner
            )
        except (IndexError, AttributeError) as e: 
            logger.debug("Signature %s matched but group extraction failed: %s", sig.name, e)
            continue

    return Service(port, default_name, banner)