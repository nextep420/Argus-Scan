"""Core async TCP scanning engine: port parsing, timing profiles, connect scans."""

from __future__ import annotations

import asyncio
import socket
import time
from dataclasses import dataclass, field
from enum import Enum


TOP_100_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
    113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465,
    513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995,
    1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900,
    2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899,
    5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800,
    5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443,
    8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156,
    49157,
]

TOP_1000_RANGE = list(range(1, 1025)) + sorted(set(TOP_100_PORTS))


class TimingProfile(Enum):
    """Speed/stealth presets, similar to nmap's -T0..-T5.
    Values are (concurrency, timeout_seconds, inter_batch_delay_seconds).
    """
    PARANOID = (5, 5.0, 2.0)
    SNEAKY = (20, 3.0, 0.5)
    POLITE = (100, 2.0, 0.1)
    NORMAL = (500, 1.5, 0.0)
    AGGRESSIVE = (1500, 0.8, 0.0)
    INSANE = (4000, 0.4, 0.0)

    @property
    def concurrency(self) -> int:
        return self.value[0]

    @property
    def timeout(self) -> float:
        return self.value[1]

    @property
    def delay(self) -> float:
        return self.value[2]


@dataclass
class PortResult:
    port: int
    state: str  # "open", "closed", "filtered"
    service: str | None = None
    banner: str | None = None
    latency_ms: float | None = None
    extra: dict = field(default_factory=dict)


@dataclass
class ScanResult:
    target: str
    resolved_ip: str
    open_ports: list[PortResult] = field(default_factory=list)
    closed_count: int = 0
    filtered_count: int = 0
    elapsed_seconds: float = 0.0
    host_up: bool = True


def parse_ports(spec: str) -> list[int]:
    """Parse a port spec into a sorted list of unique ports.

    Accepts: "80", "22,80,443", "1-1024", "1-100,443,8000-8100",
    "top100", "top1000", "all" (1-65535).
    """
    spec = spec.strip().lower()
    if spec in ("top100", "common"):
        return sorted(set(TOP_100_PORTS))
    if spec == "top1000":
        return sorted(set(TOP_1000_RANGE))
    if spec == "all":
        return list(range(1, 65536))

    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p < 65536)


async def _probe_port(
    ip: str,
    port: int,
    timeout: float,
    sem: asyncio.Semaphore,
    grab_banner: bool,
) -> PortResult:
    async with sem:
        start = time.perf_counter()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )
        except asyncio.TimeoutError:
            return PortResult(port=port, state="filtered")
        except ConnectionRefusedError:
            return PortResult(port=port, state="closed")
        except OSError:
            return PortResult(port=port, state="filtered")

        latency = (time.perf_counter() - start) * 1000
        result = PortResult(port=port, state="open", latency_ms=round(latency, 2))

        try:
            result.service = socket.getservbyport(port, "tcp")
        except OSError:
            result.service = None

        if grab_banner:
            try:
                data = await asyncio.wait_for(reader.read(256), timeout=min(timeout, 1.5))
                if data:
                    result.banner = data.decode(errors="replace").strip()
            except (asyncio.TimeoutError, OSError):
                pass

        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass

        return result


async def scan_host(
    target: str,
    ports: list[int],
    profile: TimingProfile = TimingProfile.NORMAL,
    grab_banner: bool = True,
    on_progress=None,
) -> ScanResult:
    """Scan a single host across the given ports.

    on_progress, if given, is called as on_progress(done, total) after
    each port completes, so a CLI can drive a progress bar.
    """
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        return ScanResult(target=target, resolved_ip="", host_up=False)

    sem = asyncio.Semaphore(profile.concurrency)
    start_time = time.perf_counter()

    tasks = [
        asyncio.create_task(_probe_port(ip, p, profile.timeout, sem, grab_banner))
        for p in ports
    ]

    results: list[PortResult] = []
    done_count = 0
    for coro in asyncio.as_completed(tasks):
        res = await coro
        results.append(res)
        done_count += 1
        if on_progress:
            on_progress(done_count, len(tasks))

    elapsed = time.perf_counter() - start_time

    open_ports = sorted((r for r in results if r.state == "open"), key=lambda r: r.port)
    closed = sum(1 for r in results if r.state == "closed")
    filtered = sum(1 for r in results if r.state == "filtered")

    return ScanResult(
        target=target,
        resolved_ip=ip,
        open_ports=open_ports,
        closed_count=closed,
        filtered_count=filtered,
        elapsed_seconds=round(elapsed, 2),
    )


async def scan_multiple_hosts(
    targets: list[str],
    ports: list[int],
    profile: TimingProfile = TimingProfile.NORMAL,
    grab_banner: bool = True,
    on_host_progress=None,
) -> list[ScanResult]:
    """Scan several hosts sequentially (each host scan is itself parallel)."""
    results = []
    for i, target in enumerate(targets):
        res = await scan_host(target, ports, profile, grab_banner)
        results.append(res)
        if on_host_progress:
            on_host_progress(i + 1, len(targets), target)
    return results
