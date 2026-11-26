"""Subdomain takeover and dangling DNS, detected from DNS alone.

For each subdomain found in certificate transparency logs, read its CNAME. If the CNAME
target no longer exists (NXDOMAIN), the record is dangling: anyone who registers that
target name may serve content on the subdomain. When the target belongs to a cloud
service where names can be claimed, this is a likely subdomain takeover.

Passive only: DNS lookups, no HTTP requests to discovered hosts.
"""

import asyncio

from app.models.finding import Severity
from app.scanners import base
from app.scanners.base import ScanContext, Scanner, ScannerResult
from app.services.dns_signatures import takeover_service

MAX_CHECKED = 80
PARALLEL = 10
TIME_BUDGET = 35.0  # seconds; report what was checked if DNS is slow


class TakeoverScanner(Scanner):
    name = "takeover"
    label = "Subdomain takeover & dangling DNS"
    category = "Attack surface"
    timeout = 45.0
    depends_on = ("subdomains",)

    async def run(self, ctx: ScanContext) -> ScannerResult:
        subs = (ctx.results.get("subdomains") or {}).get("subdomains") or []
        current = set((ctx.results.get("subdomains") or {}).get("current") or [])
        # Names on valid certificates first, they are the likeliest to still be in DNS.
        names = sorted(subs, key=lambda n: (n not in current, n))[:MAX_CHECKED]

        limit = asyncio.Semaphore(PARALLEL)
        checked: list[dict] = []

        async def check(name: str) -> None:
            async with limit:
                try:
                    cnames = await base.dns_query(name, "CNAME")
                except base.DnsLookupError:
                    return
                try:
                    # The A lookup follows any CNAME chain; origin_hints compares these IPs.
                    ips = sorted(set(await base.dns_query(name, "A")))[:4]
                except base.DnsLookupError:
                    ips = []
                if not cnames:
                    checked.append({"name": name, "cname": None, "ips": ips})
                    return
                target = cnames[0].rstrip(".").lower()
                exists = await base.dns_name_exists(target)
            service = takeover_service(target)
            checked.append(
                {
                    "name": name,
                    "cname": target,
                    "ips": ips,
                    "target_exists": exists,
                    "service": service[0] if service else None,
                    "reference": service[1] if service else None,
                }
            )

        tasks = [asyncio.create_task(check(n)) for n in names]
        timed_out = False
        if tasks:
            _done, pending = await asyncio.wait(tasks, timeout=TIME_BUDGET)
            for t in pending:
                t.cancel()
            timed_out = bool(pending)

        with_cname = sorted((c for c in checked if c["cname"]), key=lambda c: c["name"])
        dangling = [c for c in with_cname if c["target_exists"] is False]
        takeover = [c for c in dangling if c["service"]]
        plain_dangling = [c for c in dangling if not c["service"]]
        cloud = [c for c in with_cname if c["service"] and c["target_exists"] is not False]

        data = {
            "checked": len(checked),
            "total": len(subs),
            "timed_out": timed_out,
            "cnames": with_cname[:200],
            "takeover": takeover,
            "dangling": plain_dangling,
            "cloud_hosted": cloud[:100],
            # name -> IPv4 addresses, for the origin_hints scanner (not shown directly).
            "resolved": {c["name"]: c["ips"] for c in checked if c.get("ips")},
        }
        result = ScannerResult(data=data)

        for c in takeover:
            result.findings.append(
                self.finding(
                    f"possible.{c['name']}",
                    f"Possible subdomain takeover: {c['name']} ({c['service']})",
                    Severity.HIGH,
                    evidence=f"{c['name']} is a CNAME to {c['cname']}, which no longer exists (NXDOMAIN).",
                    recommendation=(
                        f"Delete the CNAME record for {c['name']}, or re-create the {c['service']} resource it "
                        "points to. Until then, anyone who claims that name can serve content on your domain."
                    ),
                    references=[c["reference"]] if c["reference"] else [],
                )
            )
        if plain_dangling:
            result.findings.append(
                self.finding(
                    "dangling",
                    f"{len(plain_dangling)} dangling CNAME record(s)",
                    Severity.MEDIUM,
                    evidence=", ".join(f"{c['name']} -> {c['cname']}" for c in plain_dangling[:10]),
                    recommendation=(
                        "These subdomains point to names that no longer exist. Remove the records, or check "
                        "whether the target domain could be registered by someone else."
                    ),
                )
            )
        return result
