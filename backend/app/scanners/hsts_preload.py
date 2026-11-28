"""HSTS preload status from hstspreload.org, plus whether the current header would qualify.

Preloading puts the domain in browsers' built-in HTTPS-only list, so even the very first
visit can't be downgraded to plain HTTP.
"""

from __future__ import annotations

import re
from typing import Any

from app.core.cache import api_cache_get, api_cache_set
from app.models.finding import Severity
from app.scanners.base import ScanContext, Scanner, ScannerResult

STATUS_URL = "https://hstspreload.org/api/v2/status"
MIN_MAX_AGE = 31536000  # one year, required by hstspreload.org


def parse_hsts(value: str | None) -> dict[str, Any]:
    if not value:
        return {"present": False, "max_age": None, "include_subdomains": False, "preload": False}
    directives = [d.strip().lower() for d in value.split(";") if d.strip()]
    max_age = None
    for d in directives:
        m = re.fullmatch(r'max-age\s*=\s*"?(\d+)"?', d)
        if m:
            max_age = int(m.group(1))
    return {
        "present": True,
        "max_age": max_age,
        "include_subdomains": "includesubdomains" in directives,
        "preload": "preload" in directives,
    }


def eligibility_problems(hsts: dict[str, Any]) -> list[str]:
    problems = []
    if not hsts["present"]:
        return ["no Strict-Transport-Security header"]
    if (hsts["max_age"] or 0) < MIN_MAX_AGE:
        problems.append(f"max-age must be at least {MIN_MAX_AGE} (one year)")
    if not hsts["include_subdomains"]:
        problems.append("includeSubDomains is missing")
    if not hsts["preload"]:
        problems.append("preload directive is missing")
    return problems


class HstsPreloadScanner(Scanner):
    name = "hsts_preload"
    label = "HSTS preload list"
    category = "TLS"
    timeout = 20.0
    depends_on = ("whois_rdap", "security_headers")

    async def _status(self, ctx: ScanContext, domain: str) -> dict[str, Any] | None:
        key = f"hstspreload:{domain}"
        cached = await api_cache_get(ctx.db, key)
        if cached is not None:
            return cached
        resp = await ctx.client.get(
            STATUS_URL, params={"domain": domain}, headers={"Accept": "application/json"}, timeout=15.0
        )
        if resp.status_code != 200:
            return None
        doc = resp.json()
        out = {
            "status": str(doc.get("status") or "unknown"),
            "preloaded_domain": doc.get("preloadedDomain"),
            "bulk": bool(doc.get("bulk")),
        }
        await api_cache_set(ctx.db, key, out)
        return out

    async def run(self, ctx: ScanContext) -> ScannerResult:
        registrable = (ctx.results.get("whois_rdap") or {}).get("registrable_domain") or ctx.domain
        headers = ctx.results.get("security_headers") or {}
        hsts = parse_hsts((headers.get("headers_present") or {}).get("strict-transport-security"))
        problems = eligibility_problems(hsts)

        status = await self._status(ctx, registrable)
        if status is None:
            raise RuntimeError("hstspreload.org is unavailable")
        preloaded = status["status"] == "preloaded"
        # A parent like a TLD (.dev, .app) or an included registrable domain covers this host too.
        covered = preloaded or bool(status.get("preloaded_domain"))
        data = {
            "domain": registrable,
            **status,
            "covered": covered,
            "header": hsts,
            "eligible": not problems,
            "problems": problems,
            "https": bool(headers.get("https")),
        }
        result = ScannerResult(data=data)
        if covered or not headers.get("https"):
            return result

        if status["status"] == "pending":
            return result
        if hsts["preload"] and problems:
            result.findings.append(
                self.finding(
                    "requested_ineligible",
                    "HSTS header asks for preload but doesn't meet the requirements",
                    Severity.LOW,
                    evidence="; ".join(problems),
                    recommendation=(
                        "Fix the header so it reads max-age=31536000; includeSubDomains; preload, then submit "
                        f"{registrable} at https://hstspreload.org/."
                    ),
                    references=["https://hstspreload.org/#deployment-recommendations"],
                )
            )
        else:
            result.findings.append(
                self.finding(
                    "not_preloaded",
                    f"{registrable} is not on the browser HSTS preload list",
                    Severity.INFO,
                    evidence=f"hstspreload.org status: {status['status']}"
                    + (
                        f"; to qualify: {'; '.join(problems)}"
                        if problems
                        else "; the current header qualifies"
                    ),
                    recommendation=(
                        "Once every subdomain serves HTTPS, send max-age=31536000; includeSubDomains; preload "
                        "and submit the domain at https://hstspreload.org/. Removal is slow, so check first."
                    ),
                    references=["https://hstspreload.org/"],
                )
            )
        return result
