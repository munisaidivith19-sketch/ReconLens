"""VirusTotal v3 domain reputation (free tier: 4 requests/minute, 500/day)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pymongo import ReturnDocument

from app.config import get_settings
from app.core.cache import api_cache_get, api_cache_set
from app.core.rate_limit import AsyncRateLimiter
from app.models.finding import Severity
from app.scanners.base import ScanContext, Scanner, ScannerResult

VT_URL = "https://www.virustotal.com/api/v3/domains/"
VT_DAILY_LIMIT = 480  # a little under the 500/day free quota
vt_limiter = AsyncRateLimiter(max_calls=4, period=60)


def _skipped(message: str) -> ScannerResult:
    return ScannerResult(data={"status": "skipped", "message": message})


async def _daily_budget_ok(db: Any) -> bool:
    key = f"vt_daily:{datetime.now(UTC):%Y-%m-%d}"
    doc = await db.api_cache.find_one_and_update(
        {"key": key},
        {"$inc": {"value": 1}, "$setOnInsert": {"created_at": datetime.now(UTC)}},
        upsert=True,
        return_document=ReturnDocument.AFTER,
    )
    return int((doc or {}).get("value", 1)) <= VT_DAILY_LIMIT


def parse_vt(doc: dict[str, Any], domain: str) -> dict[str, Any]:
    attrs = (doc.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    cats = attrs.get("categories") or {}
    return {
        "status": "ok",
        "stats": {k: int(v) for k, v in stats.items() if isinstance(v, int | float)},
        "reputation": attrs.get("reputation"),
        # list instead of a dict: engine names can contain dots (not valid Mongo keys)
        "categories": [{"engine": str(k)[:60], "category": str(v)[:80]} for k, v in list(cats.items())[:20]],
        "permalink": f"https://www.virustotal.com/gui/domain/{domain}",
    }


class VirusTotalScanner(Scanner):
    name = "virustotal"
    label = "VirusTotal reputation"
    category = "Reputation"
    timeout = 45.0

    async def run(self, ctx: ScanContext) -> ScannerResult:
        api_key = get_settings().VT_API_KEY
        if not api_key:
            return _skipped("reputation check skipped: VirusTotal API key not configured")

        cache_key = f"vt:{ctx.domain}"
        data = await api_cache_get(ctx.db, cache_key)
        if data is None:
            if not await vt_limiter.acquire(max_wait=20):
                return _skipped("reputation check skipped: rate limit")
            if not await _daily_budget_ok(ctx.db):
                return _skipped("reputation check skipped: daily VirusTotal quota used up")
            resp = await ctx.client.get(
                VT_URL + ctx.domain,
                headers={"x-apikey": api_key, "Accept": "application/json"},
                max_bytes=2 * 1024 * 1024,
            )
            if resp.status_code == 429:
                return _skipped("reputation check skipped: rate limit")
            if resp.status_code == 404:
                data = {"status": "not_found", "message": "VirusTotal has no record for this domain."}
            elif resp.status_code != 200:
                return _skipped(f"reputation check skipped: VirusTotal returned HTTP {resp.status_code}")
            else:
                data = parse_vt(resp.json(), ctx.domain)
            await api_cache_set(ctx.db, cache_key, data)

        result = ScannerResult(data=data)
        if data.get("status") != "ok":
            return result
        stats = data.get("stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        if malicious:
            result.findings.append(
                self.finding(
                    "malicious",
                    f"{malicious} security vendor(s) flag this domain as malicious",
                    Severity.HIGH if malicious >= 3 else Severity.MEDIUM,
                    evidence=f"VirusTotal: {malicious} malicious, {suspicious} suspicious.",
                    recommendation=(
                        "Investigate for compromise (injected scripts, phishing pages, malware hosting), clean up, "
                        "then request a re-review from the flagging vendors."
                    ),
                    references=[data["permalink"]],
                )
            )
        elif suspicious:
            result.findings.append(
                self.finding(
                    "suspicious",
                    f"{suspicious} security vendor(s) flag this domain as suspicious",
                    Severity.LOW,
                    evidence=f"VirusTotal: {suspicious} suspicious.",
                    recommendation="Review the vendor verdicts on VirusTotal.",
                    references=[data["permalink"]],
                )
            )
        rep = data.get("reputation")
        if isinstance(rep, int) and rep < 0:
            result.findings.append(
                self.finding(
                    "negative_reputation",
                    "Negative community reputation on VirusTotal",
                    Severity.LOW,
                    evidence=f"Reputation score {rep}.",
                    recommendation="Check community comments on VirusTotal for reports of abuse.",
                    references=[data["permalink"]],
                )
            )
        return result
