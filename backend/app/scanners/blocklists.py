"""Open blocklists: Spamhaus DBL (DNS) and abuse.ch URLhaus (API, with a free Auth-Key).

Complements VirusTotal with community-run sources. Spamhaus DBL is free for low-volume,
non-commercial use; it refuses queries sent through large public resolvers, which is
reported as "unavailable" rather than "clean".
"""

from __future__ import annotations

from typing import Any

import httpx

from app.config import get_settings
from app.core.cache import api_cache_get, api_cache_set
from app.core.ssrf_guard import BlockedTargetError, ResponseTooLargeError
from app.models.finding import Severity
from app.scanners import base
from app.scanners.base import ScanContext, Scanner, ScannerResult, describe_error

URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/host/"

DBL_CODES = {
    "127.0.1.2": "spam domain",
    "127.0.1.4": "phishing domain",
    "127.0.1.5": "malware domain",
    "127.0.1.6": "botnet C&C domain",
    "127.0.1.102": "abused legitimate domain (spam)",
    "127.0.1.103": "abused legitimate domain (spammed redirector)",
    "127.0.1.104": "abused legitimate domain (phishing)",
    "127.0.1.105": "abused legitimate domain (malware)",
    "127.0.1.106": "abused legitimate domain (botnet C&C)",
}
DBL_ERRORS = {
    "127.255.255.252": "query format error",
    "127.255.255.254": "Spamhaus refuses queries from public DNS resolvers",
    "127.255.255.255": "query limit exceeded",
}


def interpret_dbl(answers: list[str]) -> dict[str, Any]:
    if not answers:
        return {"status": "not_listed", "reasons": []}
    errors = [DBL_ERRORS[a] for a in answers if a in DBL_ERRORS]
    if errors:
        return {"status": "unavailable", "reasons": [], "message": errors[0]}
    reasons = [DBL_CODES.get(a, f"listed ({a})") for a in answers]
    return {"status": "listed", "reasons": sorted(set(reasons))}


def summarize_urlhaus(doc: dict[str, Any]) -> dict[str, Any]:
    status = doc.get("query_status")
    if status == "no_results":
        return {"status": "not_listed", "url_count": 0, "online": 0, "urls": []}
    if status != "ok":
        return {"status": "unavailable", "message": str(status)[:100]}
    urls = doc.get("urls") or []
    return {
        "status": "listed" if urls else "not_listed",
        "url_count": int(doc.get("url_count") or len(urls)),
        "online": sum(1 for u in urls if u.get("url_status") == "online"),
        "first_seen": doc.get("firstseen"),
        "reference": doc.get("urlhaus_reference"),
        "urls": [
            {
                "url": (u.get("url") or "")[:300],
                "status": u.get("url_status"),
                "threat": u.get("threat"),
                "date_added": u.get("date_added"),
                "tags": (u.get("tags") or [])[:5],
            }
            for u in urls[:10]
        ],
    }


class BlocklistsScanner(Scanner):
    name = "blocklists"
    label = "Blocklists (Spamhaus, URLhaus)"
    category = "Reputation"
    timeout = 25.0
    depends_on = ("whois_rdap",)

    async def _dbl(self, domain: str) -> dict[str, Any]:
        try:
            answers = await base.dns_query(f"{domain}.dbl.spamhaus.org", "A")
        except base.DnsLookupError as exc:
            return {"status": "unavailable", "reasons": [], "message": str(exc)}
        return interpret_dbl(answers)

    async def _urlhaus(self, ctx: ScanContext, domain: str) -> dict[str, Any]:
        key = get_settings().ABUSECH_AUTH_KEY
        if not key:
            return {
                "status": "skipped",
                "message": "Set ABUSECH_AUTH_KEY (free abuse.ch account) to enable URLhaus.",
            }
        cache_key = f"urlhaus:{domain}"
        cached = await api_cache_get(ctx.db, cache_key)
        if cached is not None:
            return cached
        try:
            resp = await ctx.client.post_form(
                URLHAUS_URL,
                data={"host": domain},
                headers={"Auth-Key": key, "Accept": "application/json"},
                max_bytes=2 * 1024 * 1024,
                timeout=15.0,
            )
        except (httpx.HTTPError, ResponseTooLargeError, BlockedTargetError, TimeoutError) as exc:
            return {"status": "unavailable", "message": describe_error(exc)}
        if resp.status_code != 200:
            return {"status": "unavailable", "message": f"HTTP {resp.status_code}"}
        try:
            out = summarize_urlhaus(resp.json())
        except ValueError:
            return {"status": "unavailable", "message": "invalid response"}
        if out["status"] != "unavailable":
            await api_cache_set(ctx.db, cache_key, out)
        return out

    async def run(self, ctx: ScanContext) -> ScannerResult:
        registrable = (ctx.results.get("whois_rdap") or {}).get("registrable_domain") or ctx.domain
        names = [ctx.domain] if registrable == ctx.domain else [ctx.domain, registrable]
        dbl = {n: await self._dbl(n) for n in names}
        urlhaus = await self._urlhaus(ctx, ctx.domain)
        data = {"spamhaus_dbl": dbl, "urlhaus": urlhaus}
        result = ScannerResult(data=data)

        listed = {n: r for n, r in dbl.items() if r["status"] == "listed"}
        if listed:
            result.findings.append(
                self.finding(
                    "spamhaus_listed",
                    "Domain is listed on the Spamhaus Domain Blocklist",
                    Severity.HIGH,
                    evidence="; ".join(f"{n}: {', '.join(r['reasons'])}" for n, r in listed.items()),
                    recommendation=(
                        "Mail and links using this domain are likely blocked. Find and remove the abuse "
                        "(compromised pages, open redirects, spam), then request delisting at "
                        "https://check.spamhaus.org/."
                    ),
                    references=["https://www.spamhaus.org/blocklists/domain-blocklist/"],
                )
            )
        if urlhaus.get("status") == "listed":
            online = urlhaus.get("online", 0)
            result.findings.append(
                self.finding(
                    "urlhaus_online" if online else "urlhaus_listed",
                    f"URLhaus lists {urlhaus['url_count']} malware URL(s) on this host"
                    + (f", {online} still online" if online else ""),
                    Severity.HIGH if online else Severity.MEDIUM,
                    evidence="; ".join(
                        f"{u['url']} ({u['status']}, {u['threat']})" for u in urlhaus["urls"][:5]
                    ),
                    recommendation=(
                        "The site has served malware. Remove the files, find how they were uploaded (outdated "
                        "CMS or plugins, stolen credentials) and rotate access. URLhaus marks URLs offline "
                        "automatically once they stop responding."
                    ),
                    references=[urlhaus.get("reference") or "https://urlhaus.abuse.ch/"],
                )
            )
        return result
