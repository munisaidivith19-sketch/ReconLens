"""0–100 risk score weighted by severity, with extra weight for high-impact conditions."""

from __future__ import annotations

import math
from typing import Any

SEVERITY_POINTS = {"critical": 25.0, "high": 12.0, "medium": 5.0, "low": 1.5, "info": 0.0}

# Findings that matter more than their severity alone suggests.
HEAVY_BONUS = {
    "email_security.spoofable": 12.0,
    "tls_check.expired": 15.0,
    "whois_rdap.expired": 15.0,
    "security_headers.missing_hsts": 6.0,
    "security_headers.missing_csp": 5.0,
    "security_headers.no_https": 10.0,
    "virustotal.malicious": 15.0,
    "blocklists.spamhaus_listed": 12.0,
    "blocklists.urlhaus_online": 15.0,
}
KEV_BONUS = 15.0
TAKEOVER_BONUS = 10.0
MAX_KEV_BONUSES = 3
SATURATION = 70.0  # raw points at which the score reaches ~63
TOP_FACTORS = 10


def _bonus(finding: dict[str, Any], kev_seen: int) -> tuple[float, bool]:
    fid = finding.get("id", "")
    if fid.startswith("cve_lookup.cve.") and "(known exploited)" in finding.get("title", ""):
        return (KEV_BONUS if kev_seen < MAX_KEV_BONUSES else 0.0), True
    if fid.startswith("takeover.possible."):
        return TAKEOVER_BONUS, False
    return HEAVY_BONUS.get(fid, 0.0), False


def calculate(findings: list[dict[str, Any]]) -> tuple[int, list[dict[str, Any]]]:
    """Return (score, top factors). Saturating curve: many small issues can't exceed a few big ones."""
    raw = 0.0
    factors: list[dict[str, Any]] = []
    kev_seen = 0
    for f in findings:
        sev = f.get("severity", "info")
        bonus, is_kev = _bonus(f, kev_seen)
        kev_seen += int(is_kev)
        points = SEVERITY_POINTS.get(sev, 0.0) + bonus
        if points <= 0:
            continue
        raw += points
        factors.append({"label": f.get("title", "Finding"), "points": points, "severity": sev})

    score = round(100 * (1 - math.exp(-raw / SATURATION))) if raw > 0 else 0
    factors.sort(key=lambda x: x["points"], reverse=True)
    # Express each factor as its share of the final score (sums to <= score).
    top = []
    for fac in factors[:TOP_FACTORS]:
        share = score * fac["points"] / raw if raw else 0
        top.append({"label": fac["label"], "points": round(share, 1), "severity": fac["severity"]})
    return min(100, max(0, score)), top


def risk_level(score: int) -> str:
    if score >= 70:
        return "critical"
    if score >= 45:
        return "high"
    if score >= 20:
        return "medium"
    if score > 0:
        return "low"
    return "info"


async def risk_stage(_db: Any, _scan_id: Any, state: dict[str, Any]) -> dict[str, Any]:
    score, factors = calculate(state["findings"])
    return {"risk_score": score, "score_factors": factors}
