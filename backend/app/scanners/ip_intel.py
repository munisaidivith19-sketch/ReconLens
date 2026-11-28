"""IP ownership: which network (ASN) and which cloud, CDN or hosting company runs each address.

Uses Team Cymru's free IP-to-ASN service over DNS (origin.asn.cymru.com / origin6 /
ASnnn.asn.cymru.com TXT records), so there are no HTTP requests and no large IP-range files to
keep in memory. Covers the main domain and the subdomain addresses already resolved by the
takeover stage.
"""

from __future__ import annotations

import asyncio
import ipaddress
from typing import Any

from app.core.cache import api_cache_get, api_cache_set
from app.models.finding import Severity
from app.scanners import base
from app.scanners.base import ScanContext, Scanner, ScannerResult

MAX_IPS = 40
PARALLEL = 8

# (keyword in the AS name, provider, kind). First match wins, so specific names come first.
PROVIDERS: tuple[tuple[str, str, str], ...] = (
    ("CLOUDFLARE", "Cloudflare", "cdn"),
    ("LINODE", "Linode (Akamai)", "hosting"),
    ("AKAMAI", "Akamai", "cdn"),
    ("FASTLY", "Fastly", "cdn"),
    ("INCAPSULA", "Imperva", "cdn"),
    ("IMPERVA", "Imperva", "cdn"),
    ("SUCURI", "Sucuri", "cdn"),
    ("STACKPATH", "StackPath", "cdn"),
    ("HIGHWINDS", "StackPath", "cdn"),
    ("EDGECAST", "Edgio", "cdn"),
    ("EDGIO", "Edgio", "cdn"),
    ("LIMELIGHT", "Edgio", "cdn"),
    ("CDN77", "CDN77", "cdn"),
    ("DATACAMP", "CDN77 / DataCamp", "cdn"),
    ("BUNNY", "Bunny CDN", "cdn"),
    ("AMAZON", "AWS", "cloud"),
    ("GOOGLE", "Google Cloud", "cloud"),
    ("MICROSOFT", "Microsoft Azure", "cloud"),
    ("ORACLE", "Oracle Cloud", "cloud"),
    ("ALIBABA", "Alibaba Cloud", "cloud"),
    ("TENCENT", "Tencent Cloud", "cloud"),
    ("HUAWEI", "Huawei Cloud", "cloud"),
    ("IBM", "IBM Cloud", "cloud"),
    ("SOFTLAYER", "IBM Cloud", "cloud"),
    ("DIGITALOCEAN", "DigitalOcean", "hosting"),
    ("HETZNER", "Hetzner", "hosting"),
    ("OVH", "OVHcloud", "hosting"),
    ("VULTR", "Vultr", "hosting"),
    ("CHOOPA", "Vultr", "hosting"),
    ("CONTABO", "Contabo", "hosting"),
    ("SCALEWAY", "Scaleway", "hosting"),
    ("HOSTINGER", "Hostinger", "hosting"),
    ("GODADDY", "GoDaddy", "hosting"),
    ("UNIFIEDLAYER", "Newfold Digital (Bluehost/HostGator)", "hosting"),
    ("IONOS", "IONOS", "hosting"),
    ("1&1", "IONOS", "hosting"),
    ("NAMECHEAP", "Namecheap", "hosting"),
    ("LEASEWEB", "Leaseweb", "hosting"),
    ("A2HOSTING", "A2 Hosting", "hosting"),
    ("LIQUIDWEB", "Liquid Web", "hosting"),
    ("RACKSPACE", "Rackspace", "hosting"),
    ("SITEGROUND", "SiteGround", "hosting"),
    ("WPENGINE", "WP Engine", "hosting"),
    ("KINSTA", "Kinsta", "hosting"),
    ("AUTOMATTIC", "WordPress.com", "saas"),
    ("SHOPIFY", "Shopify", "saas"),
    ("SQUARESPACE", "Squarespace", "saas"),
    ("WIX", "Wix", "saas"),
    ("GITHUB", "GitHub", "saas"),
    ("NETLIFY", "Netlify", "saas"),
    ("VERCEL", "Vercel", "saas"),
    ("HEROKU", "Heroku", "saas"),
    ("ZOHO", "Zoho", "saas"),
    ("SALESFORCE", "Salesforce", "saas"),
    ("ZENDESK", "Zendesk", "saas"),
    ("HUBSPOT", "HubSpot", "saas"),
)


def classify(as_name: str | None) -> tuple[str | None, str]:
    if not as_name:
        return None, "unknown"
    upper = as_name.upper()
    for keyword, provider, kind in PROVIDERS:
        if keyword in upper:
            return provider, kind
    return None, "other"


def cymru_origin_name(ip: str) -> str | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.version == 4:
        return ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
    nibbles = addr.exploded.replace(":", "")
    return ".".join(reversed(nibbles)) + ".origin6.asn.cymru.com"


def parse_origin(txt: str) -> dict[str, Any] | None:
    """'15169 | 8.8.8.0/24 | US | arin | 2023-12-28' -> fields. Multi-origin prefixes list several ASNs."""
    parts = [p.strip() for p in txt.strip('"').split("|")]
    if len(parts) < 3 or not parts[0]:
        return None
    asn = parts[0].split()[0]
    if not asn.isdigit():
        return None
    return {"asn": int(asn), "prefix": parts[1] or None, "country": parts[2] or None}


def parse_as_name(txt: str) -> str | None:
    """'15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US' -> 'GOOGLE - Google LLC, US'."""
    parts = [p.strip() for p in txt.strip('"').split("|")]
    return parts[4] if len(parts) >= 5 and parts[4] else None


class IpIntelScanner(Scanner):
    name = "ip_intel"
    label = "IP ownership & hosting"
    category = "Attack surface"
    timeout = 30.0
    depends_on = ("dns_records", "takeover")

    async def _txt(self, name: str) -> list[str]:
        try:
            return await base.dns_query(name, "TXT")
        except base.DnsLookupError:
            return []

    async def _as_name(self, ctx: ScanContext, asn: int) -> str | None:
        key = f"asname:{asn}"
        cached = await api_cache_get(ctx.db, key)
        if cached is not None:
            return cached.get("name")
        name = next((n for t in await self._txt(f"AS{asn}.asn.cymru.com") if (n := parse_as_name(t))), None)
        await api_cache_set(ctx.db, key, {"name": name})
        return name

    async def run(self, ctx: ScanContext) -> ScannerResult:
        records = (ctx.results.get("dns_records") or {}).get("records") or {}
        names_by_ip: dict[str, list[str]] = {}
        for ip in (records.get("A") or [])[:4] + (records.get("AAAA") or [])[:2]:
            names_by_ip.setdefault(ip, []).append(ctx.domain)
        resolved = (ctx.results.get("takeover") or {}).get("resolved") or {}
        for name, ips in sorted(resolved.items()):
            for ip in ips:
                if len(names_by_ip) >= MAX_IPS and ip not in names_by_ip:
                    continue
                names_by_ip.setdefault(ip, []).append(name)

        limit = asyncio.Semaphore(PARALLEL)
        as_names: dict[int, str | None] = {}

        async def lookup(ip: str) -> dict[str, Any]:
            entry: dict[str, Any] = {"ip": ip, "names": sorted(set(names_by_ip[ip]))[:10]}
            qname = cymru_origin_name(ip)
            if not qname:
                return entry
            async with limit:
                origin = next((o for t in await self._txt(qname) if (o := parse_origin(t))), None)
                if origin and origin["asn"] not in as_names:
                    as_names[origin["asn"]] = await self._as_name(ctx, origin["asn"])
            if origin:
                as_name = as_names.get(origin["asn"])
                provider, kind = classify(as_name)
                entry.update(origin, as_name=as_name, provider=provider, kind=kind)
            else:
                entry.update(asn=None, kind="unknown")
            return entry

        hosts = await asyncio.gather(*(lookup(ip) for ip in names_by_ip))
        hosts.sort(key=lambda h: (ctx.domain not in h["names"], h.get("provider") or "~", h["ip"]))

        summary: dict[str, dict[str, Any]] = {}
        for h in hosts:
            label = h.get("provider") or h.get("as_name") or "Unknown network"
            s = summary.setdefault(
                label, {"provider": label, "kind": h.get("kind", "unknown"), "ips": 0, "names": set()}
            )
            s["ips"] += 1
            s["names"].update(h["names"])
        providers = sorted(
            ({**s, "names": len(s["names"])} for s in summary.values()),
            key=lambda s: (-s["ips"], s["provider"]),
        )
        main = [h for h in hosts if ctx.domain in h["names"]]
        data = {
            "hosts": hosts,
            "providers": providers,
            "asn_count": len({h["asn"] for h in hosts if h.get("asn")}),
            "main_kind": main[0]["kind"] if main else None,
            "main_provider": main[0].get("provider") if main else None,
            "source": "Team Cymru IP-to-ASN (DNS)",
        }
        result = ScannerResult(data=data)
        named = [p for p in providers if p["provider"] != "Unknown network"]
        if len(named) >= 3:
            result.findings.append(
                self.finding(
                    "spread",
                    f"Assets are spread across {len(named)} networks and providers",
                    Severity.INFO,
                    evidence=", ".join(f"{p['provider']} ({p['ips']} IP)" for p in named[:8]),
                    recommendation=(
                        "Check that every provider is known and managed (shadow IT). Each one is a separate "
                        "place where patching, firewall rules and account security must be kept up to date."
                    ),
                )
            )
        return result
