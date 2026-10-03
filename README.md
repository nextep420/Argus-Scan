# Argus

A fast, modern network reconnaissance toolkit written in pure Python.

Created by **NexTep**.

Argus isn't trying to be a line-for-line nmap clone. It focuses on things a from-scratch Python tool can actually do well: a friendlier interface, readable output, informational CVE awareness, and a one-file HTML report you can open in a browser or send to someone.

## Features

- Fast async scanning — thousands of ports concurrently via `asyncio`
- Six timing profiles (`paranoid` through `insane`), similar to nmap's `-T0`-`-T5`
- Port presets: `top100`, `top1000`, `all`, or any custom range/list
- Service and version fingerprinting from banners (OpenSSH, Apache, nginx, MySQL, Redis, and more)
- TLS/SSL inspection — certificate expiry, self-signed detection, weak protocol warnings
- HTTP tech-stack detection — server headers, frameworks, page titles
- Misconfiguration checks — exposed `.git`, `.env`, phpinfo, server-status, etc. (read-only GETs, no auth bypass)
- Informational CVE matching — flags known, published vulnerabilities for identified software versions, with links to NVD
- DNS enumeration — A/AAAA always, MX/TXT/NS/CNAME with optional `dnspython`
- Terminal UI via [`rich`](https://github.com/Textualize/rich) — colored tables, live progress bars
- One-file HTML reports, dark-themed, zero external dependencies
- JSON and CSV export
- Multi-host scanning in a single command
- No mandatory dependencies for core scanning — `rich` and `dnspython` only improve the experience

## Responsible use

Argus is a reconnaissance and reporting tool. It identifies open ports, running services, and publicly documented CVEs associated with detected versions. It does not exploit, brute-force, or disrupt anything.

Only scan systems you own or have explicit permission to test. Unauthorized scanning may be illegal where you live. A legal practice target is [`scanme.nmap.org`](https://nmap.org/book/testing.html), which nmap's authors leave open for exactly this purpose.

## Installation

```bash
git clone https://github.com/nextep420/argus-scan.git
cd argus-scan
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

Requires Python 3.10+.

## Quick start

```bash
# Top 100 ports, sensible defaults
argus scanme.nmap.org

# Specific ports
argus scanme.nmap.org -p 22,80,443

# A range, scanned more aggressively
argus scanme.nmap.org -p 1-1024 -T aggressive

# Full recon: TLS, HTTP tech-stack, DNS, CVE matching
argus scanme.nmap.org --full

# Multiple hosts, exported as an HTML report
argus host1.com host2.com --full -o report.html
```

## CLI reference

| Flag | Description |
|---|---|
| `-p, --ports` | `22,80`, `1-1024`, `top100`, `top1000`, or `all` |
| `-T, --timing` | `paranoid` `sneaky` `polite` `normal` `aggressive` `insane` |
| `--no-banner` | Skip banner grabbing (faster) |
| `--tls` | Inspect TLS certificates on HTTPS-like ports |
| `--http` | Probe HTTP headers, tech stack, and common misconfigs |
| `--dns` | Enumerate DNS records |
| `--vuln` | Match versions against known CVEs (informational) |
| `--full` | Shortcut for `--tls --http --dns --vuln` |
| `-o, --output` | Write a report — extension picks format (`.json`/`.csv`/`.html`) |
| `--no-color` | Plain text output, no `rich` formatting |

## Architecture

```
argus_scan/
├── scanner.py       # Async TCP connect-scan engine + timing profiles
├── service_id.py    # Banner -> product/version fingerprinting
├── tls_inspect.py   # Certificate inspection
├── http_probe.py    # HTTP tech-stack + misconfig checks
├── dns_enum.py       # DNS record enumeration
├── vuln_match.py     # Local CVE database matching
├── report.py         # JSON / CSV / HTML report generation
├── cli.py            # argparse + rich CLI
└── data/cve_db.json  # Sample CVE reference dataset
```

Each capability lives in its own file, so adding a new probe (say, SMB enumeration or a new fingerprint) just means adding a function and wiring it into `cli.py`.

## Roadmap

- [ ] CIDR range and target-list file support
- [ ] UDP scanning for common services
- [ ] Host discovery / ping sweep before port scanning
- [ ] Plugin system for community-contributed probes
- [ ] Richer CVE dataset
- [ ] `--resume` for interrupted scans

## Running tests

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## License

MIT © 2026 NexTep — see [LICENSE](LICENSE).

## Acknowledgments

Inspired by [nmap](https://nmap.org/), built from scratch in Python with a focus on usability and reporting.
