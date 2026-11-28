"""WordPress plugin and theme versions from the asset URLs on the homepage, matched to NVD CVEs.

Reads only the homepage that every scanner shares (``?ver=`` on /wp-content/plugins/<slug>/…
and /wp-content/themes/<slug>/…). No plugin paths, readme files or admin URLs are requested.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from app.models.finding import Severity
from app.scanners.base import ScanContext, Scanner, ScannerResult
from app.scanners.cve_lookup import CveLookupScanner, severity_for
from app.services import threat_intel

log = logging.getLogger(__name__)

MAX_LOOKUPS = 6
ASSET_RE = re.compile(
    r"""/wp-content/(plugins|themes)/([a-z0-9][a-z0-9_\-]{1,80})/[^"'\s<>]*?\?(?:[^"'\s<>]*&(?:amp;)?)?ver=([0-9][0-9a-z.\-]{0,24})""",
    re.IGNORECASE,
)
SLUG_RE = re.compile(r"/wp-content/(plugins|themes)/([a-z0-9][a-z0-9_\-]{1,80})/", re.IGNORECASE)
VERSION_RE = re.compile(r"^\d+(?:\.\d+){1,3}(?:[-.]?[a-z0-9]+)?$", re.IGNORECASE)


def extract_components(html: str, core_version: str | None) -> list[dict[str, Any]]:
    """Plugins and themes referenced by the page, with a version when one looks real."""
    found: dict[tuple[str, str], set[str]] = {}
    for m in SLUG_RE.finditer(html):
        found.setdefault((m.group(1).lower(), m.group(2).lower()), set())
    for m in ASSET_RE.finditer(html):
        kind, slug, ver = m.group(1).lower(), m.group(2).lower(), m.group(3).rstrip(".-")
        # WordPress appends its own version to assets that don't set one, and some sites use timestamps.
        if ver == core_version or not VERSION_RE.match(ver):
            continue
        found.setdefault((kind, slug), set()).add(ver)
    out = []
    for (kind, slug), versions in sorted(found.items()):
        version = max(versions, key=_version_key) if versions else None
        out.append({"type": kind[:-1], "slug": slug, "version": version})
    return out


def _version_key(v: str) -> tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", v)[:4])


def wp_cpe(slug: str, version: str) -> str:
    product = slug.replace("-", "_")
    return f"cpe:2.3:a:*:{product}:{version}:*:*:*:*:wordpress:*:*"


class WordPressScanner(Scanner):
    name = "wordpress"
    label = "WordPress plugins & themes"
    category = "Vulnerabilities"
    timeout = 90.0
    depends_on = ("tech_stack",)

    async def run(self, ctx: ScanContext) -> ScannerResult:
        techs = (ctx.results.get("tech_stack") or {}).get("technologies", [])
        wp = next((t for t in techs if t.get("name") == "WordPress"), None)
        resp = await ctx.homepage()
        html = resp.text
        if wp is None and "/wp-content/" not in html:
            return ScannerResult(data={"detected": False, "components": []})
        core = wp.get("version") if wp and wp.get("version") != "unknown" else None
        components = extract_components(html, core)

        nvd = CveLookupScanner()
        lookups = 0
        raw: list[tuple[dict[str, Any], dict[str, Any]]] = []
        for comp in components:
            comp["cves"] = []
            if not comp["version"]:
                comp["status"] = "version not exposed"
                continue
            if lookups >= MAX_LOOKUPS:
                comp["status"] = "lookup limit reached"
                continue
            lookups += 1
            try:
                cves = await nvd._nvd(ctx, wp_cpe(comp["slug"], comp["version"]))
            except Exception as exc:  # noqa: BLE001 - one failed lookup shouldn't hide the rest
                log.info("NVD lookup failed for %s: %s", comp["slug"], type(exc).__name__)
                cves = None
            if cves is None:
                comp["status"] = "NVD unavailable"
                continue
            comp["status"] = "ok"
            raw.extend((comp, c) for c in cves)

        kev: dict[str, dict[str, Any]] = {}
        if raw:
            try:
                kev = await threat_intel.get_kev_catalog(ctx.db, ctx.client)
            except Exception as exc:  # noqa: BLE001 - enrichment is best effort
                log.info("KEV unavailable: %s", type(exc).__name__)
        for comp, c in raw:
            k = bool(kev.get(c["id"]))
            comp["cves"].append(
                {
                    "id": c["id"],
                    "cvss": c["cvss"],
                    "severity": severity_for(c["base_severity"], c["cvss"], k).value,
                    "kev": k,
                    "description": c["description"][:300],
                    "url": f"https://nvd.nist.gov/vuln/detail/{c['id']}",
                }
            )
        for comp in components:
            comp["cves"].sort(
                key=lambda c: (c["kev"], Severity(c["severity"]).rank, c["cvss"] or 0), reverse=True
            )

        data = {
            "detected": True,
            "core_version": core,
            "components": components,
            "plugin_count": sum(1 for c in components if c["type"] == "plugin"),
            "theme_count": sum(1 for c in components if c["type"] == "theme"),
            "vulnerable_count": sum(1 for c in components if c["cves"]),
        }
        result = ScannerResult(data=data)
        for comp in components:
            if not comp["cves"]:
                continue
            top = comp["cves"][0]
            kev_hit = any(c["kev"] for c in comp["cves"])
            result.findings.append(
                self.finding(
                    f"{comp['type']}.{comp['slug']}",
                    f"WordPress {comp['type']} {comp['slug']} {comp['version']} has {len(comp['cves'])} known CVE(s)"
                    + (" (known exploited)" if kev_hit else ""),
                    Severity(top["severity"]),
                    evidence="; ".join(
                        f"{c['id']} (CVSS {c['cvss'] if c['cvss'] is not None else 'n/a'}"
                        + (", in CISA KEV" if c["kev"] else "")
                        + ")"
                        for c in comp["cves"][:5]
                    ),
                    recommendation=(
                        f"Upgrade the {comp['slug']} {comp['type']} to its latest release, or remove it if unused. "
                        "The version comes from the ?ver= asset parameter, which some sites set by hand; "
                        "confirm it in wp-admin."
                    ),
                    references=[top["url"], f"https://wordpress.org/{comp['type']}s/{comp['slug']}/"],
                )
            )
        return result
