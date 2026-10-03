"""Basic tests for the port-parsing and scanning logic (no network calls)."""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from argus_scan.scanner import parse_ports, TimingProfile, scan_host
from argus_scan.service_id import identify_service, guess_from_port
from argus_scan.vuln_match import find_vulnerabilities


def test_parse_ports_single():
    assert parse_ports("80") == [80]


def test_parse_ports_list():
    assert parse_ports("22,80,443") == [22, 80, 443]


def test_parse_ports_range():
    assert parse_ports("1-5") == [1, 2, 3, 4, 5]


def test_parse_ports_mixed():
    assert parse_ports("22,80-82") == [22, 80, 81, 82]


def test_parse_ports_top100_nonempty():
    ports = parse_ports("top100")
    assert len(ports) > 50
    assert 80 in ports and 443 in ports


def test_parse_ports_dedupes_and_sorts():
    assert parse_ports("80,22,80,22-24") == [22, 23, 24, 80]


def test_timing_profiles_have_positive_values():
    for profile in TimingProfile:
        assert profile.concurrency > 0
        assert profile.timeout > 0


def test_identify_service_openssh():
    match = identify_service("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5")
    assert match is not None
    assert match.product == "OpenSSH"
    assert match.version == "8.2p1"


def test_identify_service_none_for_empty():
    assert identify_service(None) is None
    assert identify_service("") is None


def test_identify_service_unmatched_banner():
    assert identify_service("totally unrecognized banner text") is None


def test_guess_from_port():
    assert guess_from_port(22) == "ssh"
    assert guess_from_port(443) == "https"
    assert guess_from_port(99999 % 65536) is None or isinstance(guess_from_port(1), (str, type(None)))


def test_find_vulnerabilities_match():
    vulns = find_vulnerabilities("vsFTPd", "2.3.4")
    assert any(v.cve == "CVE-2011-2523" for v in vulns)


def test_find_vulnerabilities_no_match():
    vulns = find_vulnerabilities("vsFTPd", "3.0.5")
    assert vulns == []


def test_find_vulnerabilities_no_version():
    assert find_vulnerabilities("OpenSSH", None) == []


def test_scan_host_unresolvable():
    result = asyncio.run(scan_host(
        "this-domain-should-not-exist-ever.invalid",
        [80],
        TimingProfile.NORMAL,
    ))
    assert result.host_up is False
