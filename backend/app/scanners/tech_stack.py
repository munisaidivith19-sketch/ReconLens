"""Technology and version detection from the homepage, using webappanalyzer fingerprints.

Fingerprint data (GPL-3.0) comes from https://github.com/enthec/webappanalyzer and is
loaded once at startup. Only passive signals from the single homepage response are used:
headers, cookies, meta tags, HTML and script URLs. JavaScript is never executed.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

from app.models.finding import Severity
from app.scanners.base import ScanContext, Scanner, ScannerResult

log = logging.getLogger(__name__)

DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "fingerprints"
HTML_SCAN_LIMIT = 400_000
MAX_TECHNOLOGIES = 60


@dataclass
class Pattern:
    raw: str
    version: str | None = None
    confidence: int = 100
    _regex: re.Pattern[str] | None = None
    _broken: bool = False

    @property
    def regex(self) -> re.Pattern[str] | None:
        if self._regex is None and not self._broken:
            try:
                self._regex = re.compile(_js_to_py(self.raw), re.IGNORECASE)
            except re.error:
                self._broken = True
        return self._regex


@dataclass
class Technology:
    name: str
    categories: list[str]
    website: str | None
    cpe: str | None
    implies: list[str]
    headers: dict[str, list[Pattern]] = field(default_factory=dict)
    cookies: dict[str, list[Pattern]] = field(default_factory=dict)
    meta: dict[str, list[Pattern]] = field(default_factory=dict)
    html: list[Pattern] = field(default_factory=list)
    script_src: list[Pattern] = field(default_factory=list)
    url: list[Pattern] = field(default_factory=list)


def _js_to_py(regex: str) -> str:
    # JS named groups (?<name>...) -> Python (?P<name>...); leave lookbehinds alone.
    return re.sub(r"\(\?<(?![=!])", "(?P<", regex)


def parse_pattern(value: str) -> Pattern:
    parts = value.split("\\;")
    pat = Pattern(raw=parts[0])
    for extra in parts[1:]:
        key, _, val = extra.partition(":")
        if key == "version":
            pat.version = val
        elif key == "confidence":
            try:
                pat.confidence = int(val)
            except ValueError:
                pass
    return pat


def _patterns(value: Any) -> list[Pattern]:
    if value is None:
        return []
    if isinstance(value, str):
        return [parse_pattern(value)]
    if isinstance(value, list):
        return [parse_pattern(v) for v in value if isinstance(v, str)]
    return []


def _keyed(value: Any) -> dict[str, list[Pattern]]:
    if not isinstance(value, dict):
        return {}
    return {str(k).lower(): _patterns(v) for k, v in value.items()}


class FingerprintDB:
    def __init__(self, technologies: dict[str, Technology]):
        self.technologies = technologies

    @classmethod
    def load(cls, data_dir: Path = DATA_DIR) -> FingerprintDB:
        cats_raw = json.loads((data_dir / "categories.json").read_text(encoding="utf-8"))
        categories = {int(k): v.get("name", k) for k, v in cats_raw.items()}
        techs: dict[str, Technology] = {}
        for path in sorted((data_dir / "technologies").glob("*.json")):
            for name, spec in json.loads(path.read_text(encoding="utf-8")).items():
                techs[name] = Technology(
                    name=name,
                    categories=[categories.get(c, str(c)) for c in spec.get("cats", [])],
                    website=spec.get("website"),
                    cpe=spec.get("cpe"),
                    implies=[i.split("\\;")[0] for i in _as_list(spec.get("implies"))],
                    headers=_keyed(spec.get("headers")),
                    cookies=_keyed(spec.get("cookies")),
                    meta=_keyed(spec.get("meta")),
                    html=_patterns(spec.get("html")),
                    script_src=_patterns(spec.get("scriptSrc")),
                    url=_patterns(spec.get("url")),
                )
        log.info("Loaded %d technology fingerprints", len(techs))
        return cls(techs)


def _as_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    return []


_db: FingerprintDB | None = None


def load_fingerprints() -> FingerprintDB:
    global _db
    if _db is None:
        _db = FingerprintDB.load()
    return _db


def warm_up() -> None:
    """Compile every regex ahead of the first scan (slow on a 0.1-CPU instance)."""
    fdb = load_fingerprints()
    for tech in fdb.technologies.values():
        for pats in (*tech.headers.values(), *tech.cookies.values(), *tech.meta.values()):
            for p in pats:
                _ = p.regex
        for p in (*tech.html, *tech.script_src, *tech.url):
            _ = p.regex


def resolve_version(template: str | None, match: re.Match[str]) -> str | None:
    if not template:
        return None
    groups = match.groups()

    def group(i: int) -> str:
        return (groups[i - 1] or "") if 0 < i <= len(groups) else ""

    # Ternary syntax: \1?yes:no
    tern = re.fullmatch(r"\\(\d)\?(.*?):(.*)", template)
    if tern:
        template = tern.group(2) if group(int(tern.group(1))) else tern.group(3)
    version = re.sub(r"\\(\d)", lambda m: group(int(m.group(1))), template).strip()
    if not version or len(version) > 40 or not re.search(r"\d", version):
        return None
    return version


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.meta: dict[str, list[str]] = {}
        self.scripts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "meta":
            key = (a.get("name") or a.get("property") or a.get("http-equiv") or "").lower()
            if key:
                self.meta.setdefault(key, []).append(a.get("content", "")[:500])
        elif tag == "script" and a.get("src"):
            if len(self.scripts) < 200:
                self.scripts.append(a["src"][:500])


def parse_page(html: str) -> tuple[dict[str, list[str]], list[str]]:
    parser = _PageParser()
    try:
        parser.feed(html[:HTML_SCAN_LIMIT])
        parser.close()
    except Exception:  # noqa: BLE001, S110 - malformed HTML: keep what was parsed
        pass
    return parser.meta, parser.scripts


@dataclass
class Detection:
    confidence: int = 0
    version: str | None = None


def detect(
    fdb: FingerprintDB,
    headers: dict[str, str],
    cookies: dict[str, str],
    html: str,
    url: str,
) -> list[dict[str, Any]]:
    meta, scripts = parse_page(html)
    html = html[:HTML_SCAN_LIMIT]
    found: dict[str, Detection] = {}

    def hit(tech: Technology, pat: Pattern, subject: str) -> None:
        rx = pat.regex
        if rx is None:
            return
        m = rx.search(subject) if pat.raw else None
        if pat.raw and not m:
            return
        det = found.setdefault(tech.name, Detection())
        det.confidence = min(100, det.confidence + pat.confidence)
        if m is not None:
            v = resolve_version(pat.version, m)
            if v and (det.version is None or len(v) > len(det.version)):
                det.version = v

    for tech in fdb.technologies.values():
        for name, pats in tech.headers.items():
            if name in headers:
                for p in pats:
                    hit(tech, p, headers[name])
        for name, pats in tech.cookies.items():
            if name in cookies:
                for p in pats:
                    hit(tech, p, cookies[name])
        for name, pats in tech.meta.items():
            for content in meta.get(name, []):
                for p in pats:
                    hit(tech, p, content)
        for p in tech.script_src:
            for src in scripts:
                hit(tech, p, src)
        for p in tech.url:
            hit(tech, p, url)
        if html:
            for p in tech.html:
                if p.raw:
                    hit(tech, p, html)

    # Implied technologies (e.g. WordPress -> PHP, MySQL)
    queue = list(found)
    while queue:
        name = queue.pop()
        tech = fdb.technologies.get(name)
        if not tech:
            continue
        for implied in tech.implies:
            if implied in fdb.technologies and implied not in found:
                found[implied] = Detection(confidence=found[name].confidence)
                queue.append(implied)

    out = []
    for name, det in found.items():
        tech = fdb.technologies[name]
        out.append(
            {
                "name": name,
                "categories": tech.categories,
                "version": det.version or "unknown",
                "confidence": det.confidence,
                "website": tech.website,
                "cpe": tech.cpe,
            }
        )
    out.sort(key=lambda t: (-t["confidence"], t["version"] == "unknown", t["name"].lower()))
    return out[:MAX_TECHNOLOGIES]


def _cookie_map(set_cookie_headers: list[str]) -> dict[str, str]:
    out = {}
    for h in set_cookie_headers:
        pair = h.split(";", 1)[0]
        name, _, value = pair.partition("=")
        if name.strip():
            out[name.strip().lower()] = value.strip()[:500]
    return out


class TechStackScanner(Scanner):
    name = "tech_stack"
    label = "Technology stack"
    category = "Technology"
    timeout = 90.0

    async def run(self, ctx: ScanContext) -> ScannerResult:
        resp = await ctx.homepage()
        fdb = load_fingerprints()
        headers = {k.lower(): v for k, v in resp.headers.items()}
        cookies = _cookie_map(resp.set_cookie_headers)
        ctype = headers.get("content-type", "")
        html = resp.text if ("html" in ctype or not ctype) else ""
        # Regex matching is CPU-bound: run it off the event loop.
        techs = await asyncio.to_thread(detect, fdb, headers, cookies, html, resp.url)

        result = ScannerResult(data={"technologies": techs, "count": len(techs)})
        versioned = [t for t in techs if t["version"] != "unknown"]
        if versioned:
            result.findings.append(
                self.finding(
                    "versions_exposed",
                    "Software versions are visible to visitors",
                    Severity.LOW,
                    evidence=", ".join(f"{t['name']} {t['version']}" for t in versioned[:12]),
                    recommendation=(
                        "Exposed versions let attackers match known CVEs instantly. Hide version banners "
                        "and keep these components patched."
                    ),
                )
            )
        if techs:
            result.findings.append(
                self.finding(
                    "detected",
                    f"{len(techs)} technologies identified",
                    Severity.INFO,
                    evidence=", ".join(t["name"] for t in techs[:20]),
                    recommendation="Keep an inventory of these components and track their security advisories.",
                )
            )
        return result
