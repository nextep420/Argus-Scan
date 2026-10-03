"""HTTP(S) tech-stack detection and misconfiguration checks (exposed .git, .env, etc.)."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field


@dataclass
class HTTPInfo:
    port: int
    status_code: int | None = None
    server_header: str | None = None
    powered_by: str | None = None
    title: str | None = None
    headers: dict = field(default_factory=dict)
    tech_hints: list[str] = field(default_factory=list)
    misconfigs: list[str] = field(default_factory=list)
    error: str | None = None


TECH_HEADER_HINTS = {
    "x-powered-by": "powered_by",
    "server": "server",
}

MISCONFIG_PATHS = {
    "/.git/HEAD": "Exposed .git directory (source code may be downloadable)",
    "/.env": "Exposed .env file (may contain secrets)",
    "/wp-admin/": "WordPress admin panel exposed (verify it's hardened)",
    "/phpinfo.php": "phpinfo() page exposed (leaks server configuration)",
    "/.aws/credentials": "Exposed AWS credentials file path",
    "/server-status": "Apache server-status page exposed",
}


async def _raw_http_get(host: str, port: int, path: str, timeout: float, use_tls: bool) -> tuple[int | None, dict, str]:
    """Minimal HTTP/1.1 GET over asyncio streams. Returns (status, headers, body_snippet)."""
    try:
        if use_tls:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx), timeout=timeout
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
    except Exception:
        return None, {}, ""

    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: argus-scan/0.1\r\n"
        f"Connection: close\r\n\r\n"
    )
    try:
        writer.write(request.encode())
        await writer.drain()
        raw = await asyncio.wait_for(reader.read(8192), timeout=timeout)
    except Exception:
        raw = b""
    finally:
        writer.close()

    text = raw.decode(errors="replace")
    if not text:
        return None, {}, ""

    head, _, body = text.partition("\r\n\r\n")
    lines = head.split("\r\n")
    status_code = None
    if lines:
        parts = lines[0].split(" ")
        if len(parts) >= 2 and parts[1].isdigit():
            status_code = int(parts[1])

    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()

    return status_code, headers, body[:2000]


async def probe_http(host: str, port: int, timeout: float = 3.0, use_tls: bool = False) -> HTTPInfo:
    """Fetch '/' and extract basic tech-stack signals."""
    info = HTTPInfo(port=port)
    status, headers, body = await _raw_http_get(host, port, "/", timeout, use_tls)

    if status is None:
        info.error = "No HTTP response"
        return info

    info.status_code = status
    info.headers = headers
    info.server_header = headers.get("server")
    info.powered_by = headers.get("x-powered-by")

    if info.server_header:
        info.tech_hints.append(f"Server header: {info.server_header}")
    if info.powered_by:
        info.tech_hints.append(f"X-Powered-By: {info.powered_by}")

    if "wp-content" in body or "wp-includes" in body:
        info.tech_hints.append("WordPress markers found in page body")
    if "<title>" in body.lower():
        start = body.lower().find("<title>") + 7
        end = body.lower().find("</title>", start)
        if end > start:
            info.title = body[start:end].strip()[:120]

    return info


async def check_misconfigs(host: str, port: int, timeout: float = 3.0, use_tls: bool = False) -> list[str]:
    """Check a short list of well-known paths for accidental exposure."""
    found = []
    for path, description in MISCONFIG_PATHS.items():
        status, _, _ = await _raw_http_get(host, port, path, timeout, use_tls)
        if status is not None and status < 400:
            found.append(description)
    return found
