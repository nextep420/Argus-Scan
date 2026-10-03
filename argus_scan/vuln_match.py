"""Matches identified product/version pairs against a local CVE reference database."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

_DB_PATH = Path(__file__).parent / "data" / "cve_db.json"


@dataclass
class VulnMatch:
    cve: str
    severity: str
    summary: str
    reference: str


def _load_db() -> list[dict]:
    try:
        with open(_DB_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


_DB = _load_db()


def find_vulnerabilities(product: str, version: str | None) -> list[VulnMatch]:
    """Return known-CVE matches for a given product/version pair."""
    if not version:
        return []

    matches = []
    for entry in _DB:
        if entry["product"].lower() != product.lower():
            continue
        try:
            if re.match(entry["version_pattern"], version):
                matches.append(VulnMatch(
                    cve=entry["cve"],
                    severity=entry["severity"],
                    summary=entry["summary"],
                    reference=entry["reference"],
                ))
        except re.error:
            continue
    return matches
