"""DNS record enumeration. A/AAAA via stdlib; MX/TXT/NS/CNAME via optional dnspython."""

from __future__ import annotations

import socket
from dataclasses import dataclass, field

try:
    import dns.resolver  # type: ignore
    _HAS_DNSPYTHON = True
except ImportError:
    _HAS_DNSPYTHON = False


@dataclass
class DNSInfo:
    domain: str
    a_records: list[str] = field(default_factory=list)
    aaaa_records: list[str] = field(default_factory=list)
    mx_records: list[str] = field(default_factory=list)
    txt_records: list[str] = field(default_factory=list)
    ns_records: list[str] = field(default_factory=list)
    cname: str | None = None
    note: str | None = None


def enumerate_dns(domain: str) -> DNSInfo:
    info = DNSInfo(domain=domain)

    try:
        info.a_records = sorted(set(
            r[4][0] for r in socket.getaddrinfo(domain, None, socket.AF_INET)
        ))
    except socket.gaierror:
        pass

    try:
        info.aaaa_records = sorted(set(
            r[4][0] for r in socket.getaddrinfo(domain, None, socket.AF_INET6)
        ))
    except socket.gaierror:
        pass

    if not _HAS_DNSPYTHON:
        info.note = "Install 'dnspython' for MX/TXT/NS/CNAME lookups (pip install dnspython)"
        return info

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    for rtype, attr in (("MX", "mx_records"), ("TXT", "txt_records"), ("NS", "ns_records")):
        try:
            answer = resolver.resolve(domain, rtype)
            values = [str(r).strip('"') for r in answer]
            setattr(info, attr, values)
        except Exception:
            pass

    try:
        answer = resolver.resolve(domain, "CNAME")
        if answer:
            info.cname = str(answer[0])
    except Exception:
        pass

    return info
