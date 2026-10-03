"""TLS/SSL certificate inspection: expiry, self-signed certs, weak protocol versions."""

from __future__ import annotations

import datetime
import socket
import ssl
from dataclasses import dataclass, field


@dataclass
class TLSInfo:
    port: int
    subject: str | None = None
    issuer: str | None = None
    not_after: str | None = None
    days_until_expiry: int | None = None
    protocol: str | None = None
    cipher: str | None = None
    is_self_signed: bool = False
    is_expired: bool = False
    warnings: list[str] = field(default_factory=list)
    error: str | None = None


def _name_to_str(name_tuples) -> str:
    try:
        parts = [f"{k}={v}" for rdn in name_tuples for (k, v) in rdn]
        return ", ".join(parts)
    except Exception:
        return str(name_tuples)


def inspect_tls(host: str, port: int, timeout: float = 3.0) -> TLSInfo:
    """Connect over TLS and extract certificate + protocol details."""
    info = TLSInfo(port=port)

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert()
                info.protocol = tls_sock.version()
                cipher = tls_sock.cipher()
                info.cipher = cipher[0] if cipher else None

                if cert:
                    info.subject = _name_to_str(cert.get("subject", ()))
                    info.issuer = _name_to_str(cert.get("issuer", ()))
                    not_after = cert.get("notAfter")
                    info.not_after = not_after
                    if not_after:
                        expiry = datetime.datetime.strptime(
                            not_after, "%b %d %H:%M:%S %Y %Z"
                        )
                        delta = expiry - datetime.datetime.utcnow()
                        info.days_until_expiry = delta.days
                        info.is_expired = delta.days < 0
                        if info.is_expired:
                            info.warnings.append("Certificate has EXPIRED")
                        elif delta.days < 14:
                            info.warnings.append(
                                f"Certificate expires soon ({delta.days} days)"
                            )

                    if info.subject and info.issuer and info.subject == info.issuer:
                        info.is_self_signed = True
                        info.warnings.append("Certificate appears self-signed")

                if info.protocol in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                    info.warnings.append(
                        f"Outdated/weak protocol in use: {info.protocol}"
                    )

    except ssl.SSLError as e:
        info.error = f"TLS handshake failed: {e}"
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        info.error = f"Connection failed: {e}"

    return info
