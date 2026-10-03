"""Argus CLI: argparse front-end wiring the scanner, probes, and reports together."""

from __future__ import annotations

import argparse
import asyncio
import sys

from argus_scan import __version__
from argus_scan.scanner import (
    TimingProfile, parse_ports, scan_host, scan_multiple_hosts,
)
from argus_scan.service_id import identify_service, guess_from_port
from argus_scan.tls_inspect import inspect_tls
from argus_scan.http_probe import probe_http, check_misconfigs
from argus_scan.dns_enum import enumerate_dns
from argus_scan.vuln_match import find_vulnerabilities
from argus_scan.report import build_report_data, to_json, to_csv, to_html

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn
    from rich.panel import Panel
    from rich import box
    _HAS_RICH = True
except ImportError:
    _HAS_RICH = False

console = Console() if _HAS_RICH else None

TLS_PORTS = {443, 8443, 993, 995, 465, 636, 3269, 5986, 8883}
HTTP_PORTS = {80, 8000, 8008, 8080, 8081, 81, 3000, 5000, 9000, 591}


def _print(msg: str, style: str = ""):
    if _HAS_RICH:
        console.print(msg, style=style)
    else:
        print(msg)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="argus",
        description="Argus - a fast, modern network reconnaissance toolkit.",
    )
    p.add_argument("targets", nargs="+", help="Host(s) or domain(s) to scan")
    p.add_argument("-p", "--ports", default="top100",
                    help="Ports: '22,80', '1-1024', 'top100', 'top1000', 'all' (default: top100)")
    p.add_argument("-T", "--timing", default="normal",
                    choices=["paranoid", "sneaky", "polite", "normal", "aggressive", "insane"],
                    help="Timing profile, like nmap's -T0..-T5 (default: normal)")
    p.add_argument("--no-banner", action="store_true", help="Skip banner grabbing")
    p.add_argument("--tls", action="store_true", help="Inspect TLS certificates on TLS-like ports")
    p.add_argument("--http", action="store_true", help="Probe HTTP(S) tech stack and common misconfigs")
    p.add_argument("--dns", action="store_true", help="Enumerate DNS records for the target(s)")
    p.add_argument("--vuln", action="store_true", help="Match identified versions against known CVEs")
    p.add_argument("--full", action="store_true", help="Shortcut for --tls --http --dns --vuln")
    p.add_argument("-o", "--output", help="Write report to file (format inferred from extension: .json/.csv/.html)")
    p.add_argument("--no-color", action="store_true", help="Disable colored/rich output")
    p.add_argument("-v", "--version", action="version", version=f"argus {__version__}")
    return p


def _timing_profile(name: str) -> TimingProfile:
    return {
        "paranoid": TimingProfile.PARANOID,
        "sneaky": TimingProfile.SNEAKY,
        "polite": TimingProfile.POLITE,
        "normal": TimingProfile.NORMAL,
        "aggressive": TimingProfile.AGGRESSIVE,
        "insane": TimingProfile.INSANE,
    }[name]


async def _enrich_host(target: str, resolved_ip: str, open_ports, args, enrichments: dict):
    """Run TLS/HTTP/vuln checks for each open port on a host."""
    for p in open_ports:
        key = f"{target}:{p.port}"
        entry = enrichments.setdefault(key, {})

        match = identify_service(p.banner)
        product = match.product if match else None
        version = match.version if match else None
        if product:
            entry["identified_product"] = product
            entry["identified_version"] = version
        elif p.service:
            entry["identified_product"] = guess_from_port(p.port) or p.service

        if args.vuln and product and version:
            vulns = find_vulnerabilities(product, version)
            if vulns:
                entry["vulnerabilities"] = [
                    {"cve": v.cve, "severity": v.severity, "summary": v.summary, "reference": v.reference}
                    for v in vulns
                ]

        if args.tls and p.port in TLS_PORTS:
            tls_info = inspect_tls(resolved_ip, p.port)
            entry["tls"] = {
                "subject": tls_info.subject,
                "issuer": tls_info.issuer,
                "protocol": tls_info.protocol,
                "days_until_expiry": tls_info.days_until_expiry,
                "warnings": tls_info.warnings,
            }

        if args.http and (p.port in HTTP_PORTS or p.port in TLS_PORTS):
            use_tls = p.port in TLS_PORTS
            http_info = await probe_http(resolved_ip, p.port, use_tls=use_tls)
            entry["http"] = {
                "status_code": http_info.status_code,
                "server": http_info.server_header,
                "title": http_info.title,
                "tech_hints": http_info.tech_hints,
            }
            misconfigs = await check_misconfigs(resolved_ip, p.port, use_tls=use_tls)
            if misconfigs:
                entry["misconfigs"] = misconfigs


def _render_host_table(result, enrichments: dict):
    if not _HAS_RICH:
        print(f"\n{result.target} ({result.resolved_ip}) - "
              f"{len(result.open_ports)} open, {result.closed_count} closed, "
              f"{result.filtered_count} filtered, {result.elapsed_seconds}s")
        for p in result.open_ports:
            print(f"  {p.port}/tcp  open  {p.service or ''}  {p.banner or ''}")
        return

    title = f"[bold cyan]{result.target}[/] [dim]({result.resolved_ip})[/]"
    table = Table(title=title, box=box.ROUNDED, title_justify="left")
    table.add_column("Port", style="bold")
    table.add_column("Service")
    table.add_column("Version / Banner")
    table.add_column("Notes")

    for p in result.open_ports:
        key = f"{result.target}:{p.port}"
        enrich = enrichments.get(key, {})
        service = enrich.get("identified_product") or p.service or "-"
        version = enrich.get("identified_version") or ""
        banner_display = f"{service} {version}".strip()

        notes = []
        for v in enrich.get("vulnerabilities", []):
            color = {"critical": "red", "high": "orange3", "medium": "yellow", "low": "blue"}.get(v["severity"], "white")
            notes.append(f"[{color}]{v['cve']} ({v['severity']})[/]")
        for w in enrich.get("tls", {}).get("warnings", []):
            notes.append(f"[yellow]TLS: {w}[/]")
        for m in enrich.get("misconfigs", []):
            notes.append(f"[red]{m}[/]")

        table.add_row(str(p.port), service, banner_display or (p.banner or "-"), "\n".join(notes) or "-")

    console.print(table)
    console.print(
        f"[dim]{result.closed_count} closed, {result.filtered_count} filtered, "
        f"finished in {result.elapsed_seconds}s[/dim]\n"
    )


def main():
    args = build_parser().parse_args()
    global _HAS_RICH, console
    if args.no_color:
        _HAS_RICH = False

    ports = parse_ports(args.ports)
    profile = _timing_profile(args.timing)
    grab_banner = not args.no_banner

    if args.full:
        args.tls = args.http = args.dns = args.vuln = True

    if _HAS_RICH:
        console.print(Panel.fit(
            f"[bold cyan]ARGUS[/] [dim]v{__version__}[/]\n"
            f"[dim]Scanning {len(args.targets)} target(s), {len(ports)} port(s), "
            f"timing={args.timing}[/dim]",
            border_style="cyan",
        ))

    all_results = []
    enrichments: dict = {}

    for target in args.targets:
        if _HAS_RICH:
            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(), TextColumn("{task.percentage:>3.0f}%"), TimeElapsedColumn(),
                console=console, transient=True,
            ) as progress:
                task = progress.add_task(f"Scanning {target}", total=len(ports))

                def on_progress(done, total):
                    progress.update(task, completed=done)

                result = asyncio.run(scan_host(target, ports, profile, grab_banner, on_progress))
        else:
            print(f"Scanning {target} ...")
            result = asyncio.run(scan_host(target, ports, profile, grab_banner))

        if not result.host_up:
            _print(f"[red]Could not resolve or reach {target}[/]" if _HAS_RICH else f"Could not resolve {target}")
            continue

        if result.open_ports:
            asyncio.run(_enrich_host(target, result.resolved_ip, result.open_ports, args, enrichments))

        all_results.append(result)
        _render_host_table(result, enrichments)

        if args.dns:
            dns_info = enumerate_dns(target)
            if dns_info.a_records or dns_info.mx_records:
                _print(f"[bold]DNS for {target}:[/]" if _HAS_RICH else f"DNS for {target}:")
                if dns_info.a_records:
                    _print(f"  A: {', '.join(dns_info.a_records)}")
                if dns_info.mx_records:
                    _print(f"  MX: {', '.join(dns_info.mx_records)}")
                if dns_info.ns_records:
                    _print(f"  NS: {', '.join(dns_info.ns_records)}")
                if dns_info.note:
                    _print(f"  [dim]{dns_info.note}[/]" if _HAS_RICH else f"  {dns_info.note}")
                print()

    if args.output:
        report = build_report_data(all_results, enrichments)
        ext = args.output.rsplit(".", 1)[-1].lower() if "." in args.output else "json"
        writer = {"json": to_json, "csv": to_csv, "html": to_html}.get(ext, to_json)
        content = writer(report)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(content)
        _print(f"[green]Report written to {args.output}[/]" if _HAS_RICH else f"Report written to {args.output}")


if __name__ == "__main__":
    sys.exit(main())
