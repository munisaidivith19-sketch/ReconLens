"""Known CVEs for detected technology versions (NVD API 2.0), enriched with CISA KEV and EPSS.

CVEs are only reported when a version was actually detected. Unknown versions are
reported as "version not exposed, CVE matching not possible".
"""

from __future__ import annotations

import logging
import re
from typing import Any

from app.config import get_settings
from app.core.cache import api_cache_get, api_cache_set
from app.core.rate_limit import AsyncRateLimiter
from app.models.finding import Severity
from app.scanners.base import ScanContext, Scanner, ScannerResult
from app.services import threat_intel

log = logging.getLogger(__name__)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_PAGE_SIZE = 100
MAX_TECH_LOOKUPS = 6
MAX_CVES_PER_TECH = 25

# NVD: 50 requests / 30 s with an API key, 5 / 30 s without.
nvd_limiter_keyed = AsyncRateLimiter(max_calls=45, period=30)
nvd_limiter_anon = AsyncRateLimiter(max_calls=5, period=30)

_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "NONE": Severity.INFO,
}
_CLEAN_VERSION = re.compile(r"^[0-9][0-9a-z.\-_+]*$", re.IGNORECASE)


def build_cpe(cpe_template: str, version: str) -> str | None:
    """cpe:2.3:a:vendor:product:*:... -> cpe:2.3:a:vendor:product:<version>"""
    parts = cpe_template.split(":")
    if len(parts) < 5 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    version = version.strip().lower()
    if not _CLEAN_VERSION.match(version):
        return None
    return ":".join([*parts[:5], version])


def _cvss(metrics: dict[str, Any]) -> tuple[float | None, str | None]:
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        items = metrics.get(key) or []
        if not items:
            continue
        primary = next((m for m in items if m.get("type") == "Primary"), items[0])
        data = primary.get("cvssData", {})
        score = data.get("baseScore")
        sev = data.get("baseSeverity") or primary.get("baseSeverity")
        return (float(score) if score is not None else None), (str(sev).upper() if sev else None)
    return None, None


def parse_nvd(doc: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for item in doc.get("vulnerabilities", []) or []:
        cve = item.get("cve") or {}
        if str(cve.get("vulnStatus", "")).lower() == "rejected":
            continue
        cid = cve.get("id")
        if not cid:
            continue
        desc = next(
            (d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            "",
        )
        score, sev = _cvss(cve.get("metrics") or {})
        out.append(
            {
                "id": cid,
                "cvss": score,
                "base_severity": sev,
                "description": desc[:600],
                "published": cve.get("published"),
            }
        )
    out.sort(key=lambda c: c["cvss"] or 0, reverse=True)
    return out


def severity_for(base_severity: str | None, cvss: float | None, kev: bool) -> Severity:
    sev = _SEVERITY_MAP.get(base_severity or "")
    if sev is None:
        if cvss is None:
            sev = Severity.MEDIUM
        elif cvss >= 9:
            sev = Severity.CRITICAL
        elif cvss >= 7:
            sev = Severity.HIGH
        elif cvss >= 4:
            sev = Severity.MEDIUM
        else:
            sev = Severity.LOW
    return sev.raised(1) if kev else sev


class CveLookupScanner(Scanner):
    name = "cve_lookup"
    label = "CVE intelligence (NVD, KEV, EPSS)"
    category = "Vulnerabilities"
    timeout = 90.0
    depends_on = ("tech_stack",)

    async def _nvd(self, ctx: ScanContext, cpe: str) -> list[dict[str, Any]] | None:
        key = f"nvd:{cpe}"
        cached = await api_cache_get(ctx.db, key)
        if cached is not None:
            return cached
        api_key = get_settings().NVD_API_KEY
        limiter = nvd_limiter_keyed if api_key else nvd_limiter_anon
        if not await limiter.acquire(max_wait=20):
            return None
        headers = {"Accept": "application/json"}
        if api_key:
            headers["apiKey"] = api_key
        resp = await ctx.client.get(
            NVD_URL,
            params={"virtualMatchString": cpe, "resultsPerPage": NVD_PAGE_SIZE},
            headers=headers,
            max_bytes=8 * 1024 * 1024,
            timeout=30.0,
        )
        if resp.status_code != 200:
            log.info("NVD HTTP %s", resp.status_code)
            return None
        cves = parse_nvd(resp.json())[:MAX_CVES_PER_TECH]
        await api_cache_set(ctx.db, key, cves)
        return cves

    async def run(self, ctx: ScanContext) -> ScannerResult:
        techs = (ctx.results.get("tech_stack") or {}).get("technologies", [])
        checked: list[dict[str, Any]] = []
        skipped: list[dict[str, str]] = []
        candidates = []
        for t in techs:
            if t.get("version", "unknown") == "unknown":
                skipped.append(
                    {"technology": t["name"], "reason": "version not exposed, CVE matching not possible"}
                )
                continue
            if not t.get("cpe"):
                skipped.append({"technology": t["name"], "reason": "no CPE mapping in the fingerprint data"})
                continue
            cpe = build_cpe(t["cpe"], t["version"])
            if not cpe:
                skipped.append(
                    {"technology": t["name"], "reason": "version format not usable for CPE matching"}
                )
                continue
            candidates.append((t, cpe))

        for t, _ in candidates[MAX_TECH_LOOKUPS:]:
            skipped.append({"technology": t["name"], "reason": "lookup limit reached for this scan"})
        candidates = candidates[:MAX_TECH_LOOKUPS]

        raw: list[dict[str, Any]] = []
        for t, cpe in candidates:
            cves = await self._nvd(ctx, cpe)
            if cves is None:
                checked.append(
                    {"technology": t["name"], "version": t["version"], "status": "NVD unavailable"}
                )
                continue
            checked.append(
                {"technology": t["name"], "version": t["version"], "status": "ok", "count": len(cves)}
            )
            for c in cves:
                raw.append({**c, "technology": t["name"], "version": t["version"]})

        kev: dict[str, dict[str, Any]] = {}
        epss: dict[str, dict[str, float]] = {}
        if raw:
            try:
                kev = await threat_intel.get_kev_catalog(ctx.db, ctx.client)
            except Exception as exc:  # noqa: BLE001 - enrichment is best effort
                log.info("KEV unavailable: %s", type(exc).__name__)
            try:
                epss = await threat_intel.get_epss(ctx.db, ctx.client, [c["id"] for c in raw])
            except Exception as exc:  # noqa: BLE001
                log.info("EPSS unavailable: %s", type(exc).__name__)

        enriched = []
        for c in raw:
            k = kev.get(c["id"])
            e = epss.get(c["id"], {})
            sev = severity_for(c["base_severity"], c["cvss"], bool(k))
            enriched.append(
                {
                    **c,
                    "severity": sev.value,
                    "kev": bool(k),
                    "kev_date_added": k["date_added"] if k else None,
                    "ransomware": bool(k and k.get("ransomware")),
                    "epss": e.get("epss"),
                    "epss_percentile": e.get("percentile"),
                    "url": f"https://nvd.nist.gov/vuln/detail/{c['id']}",
                }
            )
        enriched.sort(
            key=lambda c: (c["kev"], Severity(c["severity"]).rank, c["epss"] or 0, c["cvss"] or 0),
            reverse=True,
        )

        data = {
            "cves": enriched,
            "checked": checked,
            "skipped": skipped,
            "kev_count": sum(1 for c in enriched if c["kev"]),
            "kev_available": bool(kev),
        }
        result = ScannerResult(data=data)
        self._findings(result, enriched, skipped)
        return result

    def _findings(
        self, result: ScannerResult, cves: list[dict[str, Any]], skipped: list[dict[str, str]]
    ) -> None:
        f = result.findings
        individual = [c for c in cves if c["kev"] or Severity(c["severity"]).rank >= Severity.HIGH.rank][:15]
        for c in individual:
            tags = []
            if c["kev"]:
                tags.append("in CISA KEV (actively exploited)")
            if c["epss"] is not None:
                tags.append(f"EPSS {c['epss'] * 100:.1f}%")
            f.append(
                self.finding(
                    f"cve.{c['id']}",
                    f"{c['id']} in {c['technology']} {c['version']}"
                    + (" (known exploited)" if c["kev"] else ""),
                    Severity(c["severity"]),
                    evidence=(
                        f"CVSS {c['cvss'] if c['cvss'] is not None else 'n/a'}"
                        + (f"; {'; '.join(tags)}" if tags else "")
                        + f". {c['description'][:300]}"
                    ),
                    recommendation=(
                        f"Upgrade {c['technology']} to a release that fixes {c['id']}. "
                        "Confirm the detected version first; banners can be wrong or patched by a vendor."
                    ),
                    references=[c["url"]],
                )
            )
        shown = {c["id"] for c in individual}
        by_tech: dict[str, list[dict[str, Any]]] = {}
        for c in cves:
            if c["id"] not in shown:
                by_tech.setdefault(f"{c['technology']} {c['version']}", []).append(c)
        for tech, items in by_tech.items():
            worst = max((Severity(c["severity"]) for c in items), key=lambda s: s.rank)
            f.append(
                self.finding(
                    f"cves.{tech.replace(' ', '_')}",
                    f"{len(items)} more known CVE(s) affect {tech}",
                    worst,
                    evidence=", ".join(c["id"] for c in items[:12]),
                    recommendation="Upgrade to the latest supported release.",
                )
            )
        unknown = [s["technology"] for s in skipped if s["reason"].startswith("version not exposed")]
        if unknown:
            f.append(
                self.finding(
                    "version_unknown",
                    "Version not exposed, CVE matching not possible",
                    Severity.INFO,
                    evidence="No version detected for: " + ", ".join(unknown[:15]),
                    recommendation="This is good practice. Still track these components' advisories internally.",
                )
            )
