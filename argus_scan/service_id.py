"""Service and version fingerprinting from raw banner strings via regex signatures."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class ServiceMatch:
    product: str
    version: str | None
    raw_banner: str


# Each entry: (compiled regex, product name, version group index or None)
SIGNATURES: list[tuple[re.Pattern, str, int | None]] = [
    (re.compile(r"SSH-2\.0-OpenSSH_([\w.]+)"), "OpenSSH", 1),
    (re.compile(r"SSH-1\.99-OpenSSH_([\w.]+)"), "OpenSSH (legacy proto)", 1),
    (re.compile(r"220.*vsFTPd ([\d.]+)", re.I), "vsFTPd", 1),
    (re.compile(r"220.*ProFTPD ([\d.]+)", re.I), "ProFTPD", 1),
    (re.compile(r"220.*Pure-FTPd", re.I), "Pure-FTPd", None),
    (re.compile(r"Apache/([\d.]+)"), "Apache HTTPD", 1),
    (re.compile(r"nginx/([\d.]+)"), "nginx", 1),
    (re.compile(r"Microsoft-IIS/([\d.]+)"), "Microsoft IIS", 1),
    (re.compile(r"MySQL.*?([\d]+\.[\d]+\.[\d]+)"), "MySQL", 1),
    (re.compile(r"([\d]+\.[\d]+\.[\d]+)-MariaDB"), "MariaDB", 1),
    (re.compile(r"PostgreSQL"), "PostgreSQL", None),
    (re.compile(r"Redis.*?version=([\d.]+)", re.I), "Redis", 1),
    (re.compile(r"\+OK Redis"), "Redis", None),
    (re.compile(r"220.*Microsoft FTP Service", re.I), "Microsoft FTP Service", None),
    (re.compile(r"220.*Exim ([\d.]+)", re.I), "Exim", 1),
    (re.compile(r"220.*Postfix", re.I), "Postfix", None),
    (re.compile(r"MongoDB"), "MongoDB", None),
    (re.compile(r"RFB 00(\d)\.00(\d)"), "VNC (RFB)", None),
    (re.compile(r"Samba ([\d.]+)"), "Samba", 1),
]


def identify_service(banner: str | None) -> ServiceMatch | None:
    """Identify product + version from a raw banner string."""
    if not banner:
        return None
    for pattern, product, group in SIGNATURES:
        m = pattern.search(banner)
        if m:
            version = m.group(group) if group else None
            return ServiceMatch(product=product, version=version, raw_banner=banner)
    return None


def guess_from_port(port: int) -> str | None:
    """Fallback guess by well-known port number when there's no banner."""
    common = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
        139: "netbios-ssn", 143: "imap", 443: "https", 445: "microsoft-ds",
        465: "smtps", 587: "submission", 993: "imaps", 995: "pop3s",
        1433: "mssql", 1723: "pptp", 3306: "mysql", 3389: "rdp",
        5432: "postgresql", 5900: "vnc", 5984: "couchdb", 6379: "redis",
        8080: "http-proxy", 8443: "https-alt", 9200: "elasticsearch",
        27017: "mongodb",
    }
    return common.get(port)
