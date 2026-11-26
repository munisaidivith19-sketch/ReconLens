"""Vulnerable JavaScript library detection using the Retire.js repository (Apache-2.0).

Library versions are read from script URLs, file names and file contents, then compared with
the vulnerable version ranges in ``app/data/retirejs/jsrepository.json``. The data is loaded
once and kept in memory (a few MB).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "retirejs" / "jsrepository.json"
VERSION_RX = r"[0-9][0-9.a-z_\-]+"
# Large bundles: library banners sit near the start or end, so only scan those parts (CPU budget).
CONTENT_HEAD = 384 * 1024
CONTENT_TAIL = 128 * 1024
SEVERITY_ORDER = ("low", "medium", "high", "critical")


@dataclass
class Component:
    name: str
    uri: list[re.Pattern[str]] = field(default_factory=list)
    filename: list[re.Pattern[str]] = field(default_factory=list)
    filecontent: list[re.Pattern[str]] = field(default_factory=list)
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)


def _compile(patterns: list[str]) -> list[re.Pattern[str]]:
    out = []
    for p in patterns or []:
        try:
            out.append(re.compile(p.replace("§§version§§", VERSION_RX)))
        except re.error:
            continue  # a few JS-only regex features (e.g. variable look-behind) are skipped
    return out


@lru_cache(maxsize=1)
def load(path: Path = DATA_FILE) -> tuple[Component, ...]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    comps = []
    for name, entry in raw.items():
        if name == "retire-example" or not isinstance(entry, dict):
            continue
        ex = entry.get("extractors") or {}
        vulns = []
        for v in entry.get("vulnerabilities") or []:
            ids = v.get("identifiers") or {}
            vulns.append(
                {
                    "below": v.get("below"),
                    "at_or_above": v.get("atOrAbove"),
                    "severity": (v.get("severity") or "medium").lower(),
                    "cves": list(ids.get("CVE") or [])[:5],
                    "summary": (ids.get("summary") or "")[:300],
                    "ghsa": ids.get("githubID"),
                    "info": list(v.get("info") or [])[:3],
                }
            )
        comps.append(
            Component(
                name=name,
                uri=_compile(ex.get("uri")),
                filename=_compile(ex.get("filename")),
                filecontent=_compile(ex.get("filecontent")),
                vulnerabilities=vulns,
            )
        )
    return tuple(comps)


def _comparable(part: str | None) -> int | str:
    if not part:
        return 0
    return int(part) if part.isdigit() else part


def is_at_or_above(v1: str, v2: str) -> bool:
    """Retire.js version comparison: numeric parts compare as numbers, others as strings."""
    a, b = re.split(r"[.\-]", v1), re.split(r"[.\-]", v2)
    for i in range(max(len(a), len(b))):
        x = _comparable(a[i] if i < len(a) else None)
        y = _comparable(b[i] if i < len(b) else None)
        if type(x) is not type(y):
            return isinstance(x, int)
        if x > y:  # type: ignore[operator]
            return True
        if x < y:  # type: ignore[operator]
            return False
    return True


def vulnerabilities_for(comp: Component, version: str) -> list[dict[str, Any]]:
    out = []
    for v in comp.vulnerabilities:
        below = v["below"]
        if not below or is_at_or_above(version, below):
            continue
        if v["at_or_above"] and not is_at_or_above(version, v["at_or_above"]):
            continue
        out.append(v)
    return out


# The shared version pattern is greedy, so "jquery-1.8.3.min.js" captures "1.8.3.min": drop build suffixes.
BUILD_SUFFIX = re.compile(
    r"[.\-_](?:min|slim|pack|packed|prod|production|dev|debug|umd|esm|cjs|bundle|full|core|all|js)(?:[.\-_].*)?$",
    re.IGNORECASE,
)


def clean_version(version: str) -> str:
    previous = None
    while previous != version:
        previous, version = version, BUILD_SUFFIX.sub("", version)
    return version.rstrip(".-_")


def _first_version(patterns: list[re.Pattern[str]], text: str) -> str | None:
    for p in patterns:
        m = p.search(text)
        if m and m.groups():
            version = clean_version(m.group(1) or "")
            if version and version[0].isdigit():
                return version
    return None


def detect_url(url: str) -> list[tuple[str, str]]:
    """(component, version) pairs readable from a script URL alone."""
    found = []
    filename = url.split("?", 1)[0].rsplit("/", 1)[-1]
    for comp in load():
        version = _first_version(comp.uri, url) or _first_version(comp.filename, filename)
        if version:
            found.append((comp.name, version))
    return found


def detect_content(text: str) -> list[tuple[str, str]]:
    """(component, version) pairs from file content. CPU-heavy: call it in a worker thread."""
    if len(text) > CONTENT_HEAD + CONTENT_TAIL:
        text = text[:CONTENT_HEAD] + "\n" + text[-CONTENT_TAIL:]
    found = []
    for comp in load():
        version = _first_version(comp.filecontent, text)
        if version:
            found.append((comp.name, version))
    return found


def component(name: str) -> Component | None:
    return next((c for c in load() if c.name == name), None)


def max_severity(vulns: list[dict[str, Any]]) -> str:
    sev = [v["severity"] for v in vulns if v["severity"] in SEVERITY_ORDER]
    return max(sev, key=SEVERITY_ORDER.index) if sev else "medium"
