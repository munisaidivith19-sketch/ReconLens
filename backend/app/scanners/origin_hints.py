"""CDN bypass hints: subdomains that resolve outside the CDN protecting the main site.

When the main website sits behind a CDN or WAF, its origin server should only accept traffic
from the CDN. Subdomains found in certificate transparency (mail., dev., origin., cpanel. ...)
often point straight at that origin or at other servers in the same network. This scanner
reuses the DNS answers already collected by the dns_records and takeover stages.

Passive only: no new network requests at all.
"""

import ipaddress

from app.models.finding import Severity
from app.scanners.base import ScanContext, Scanner, ScannerResult

# CNAME / reverse-DNS suffixes that mean "served by a CDN or edge network", not an origin.
CDN_SUFFIXES = (
    "cloudflare.net",
    "cloudflare.com",
    "cdn.cloudflare.net",
    "cloudfront.net",
    "akamaiedge.net",
    "akamai.net",
    "akamaitechnologies.com",
    "edgekey.net",
    "edgesuite.net",
    "fastly.net",
    "fastlylb.net",
    "azureedge.net",
    "azurefd.net",
    "trafficmanager.net",
    "b-cdn.net",
    "cdn77.org",
    "stackpathdns.com",
    "incapdns.net",
    "impervadns.net",
    "sucuri.net",
    "netlify.app",
    "vercel-dns.com",
    "github.io",
    "googlehosted.com",
    "ghs.googlehosted.com",
    "edgecastcdn.net",
    "kxcdn.com",
    "gcdn.co",
    "hstgr.net",
    "bunnycdn.com",
    "wpengine.com",
)
# Names that usually point at a real server rather than the website itself.
ORIGIN_WORDS = (
    "origin",
    "direct",
    "backend",
    "mail",
    "smtp",
    "webmail",
    "cpanel",
    "cpcalendars",
    "cpcontacts",
    "webdisk",
    "autodiscover",
    "autoconfig",
    "whm",
    "ftp",
    "dev",
    "staging",
    "stage",
    "test",
    "uat",
    "old",
    "legacy",
    "admin",
    "vpn",
    "server",
    "host",
)
MAX_CANDIDATES = 50


def _network(ip: str) -> str | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    prefix = 24 if addr.version == 4 else 48
    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))


def _is_cdn_name(name: str | None) -> bool:
    if not name:
        return False
    name = name.rstrip(".").lower()
    return any(name == s or name.endswith("." + s) for s in CDN_SUFFIXES)


def _origin_word(name: str, domain: str) -> str | None:
    label = name[: -len(domain)].rstrip(".") if name.endswith(domain) else name
    parts = {p for chunk in label.split(".") for p in chunk.split("-")}
    return next((w for w in ORIGIN_WORDS if w in parts), None)


class OriginHintsScanner(Scanner):
    name = "origin_hints"
    label = "CDN bypass / origin hints"
    category = "Attack surface"
    timeout = 10.0
    depends_on = ("dns_records", "takeover", "security_headers", "ip_intel")

    async def run(self, ctx: ScanContext) -> ScannerResult:
        dns = ctx.results.get("dns_records") or {}
        records = dns.get("records") or {}
        main_ips = [ip for ip in (records.get("A") or []) + (records.get("AAAA") or []) if _network(ip)]
        main_nets = {_network(ip) for ip in main_ips}
        cdn = list((ctx.results.get("security_headers") or {}).get("waf_cdn") or [])
        takeover = ctx.results.get("takeover") or {}
        resolved: dict[str, list[str]] = takeover.get("resolved") or {}
        cname_of = {c["name"]: c.get("cname") for c in takeover.get("cnames") or []}
        ptr_names = {p["ip"]: p.get("names") or [] for p in dns.get("ptr") or []}
        ip_hosts = {h["ip"]: h for h in (ctx.results.get("ip_intel") or {}).get("hosts") or []}
        main_cdn = {
            ip_hosts[ip].get("provider") for ip in main_ips if ip_hosts.get(ip, {}).get("kind") == "cdn"
        }
        for provider in sorted(p for p in main_cdn if p):
            if not any(provider.lower() in c.lower() or c.lower() in provider.lower() for c in cdn):
                cdn.append(provider)

        # Group every resolved subdomain by IP: a map of the infrastructure.
        by_ip: dict[str, list[str]] = {}
        for name, ips in resolved.items():
            for ip in ips:
                by_ip.setdefault(ip, []).append(name)

        candidates = []
        for name, ips in sorted(resolved.items()):
            if _is_cdn_name(cname_of.get(name)):
                continue
            outside = [ip for ip in ips if ip not in main_ips]
            if not outside or not ips or len(outside) < len(ips):
                continue  # shares an address with the main site, so it is behind the same edge
            if all(ip_hosts.get(ip, {}).get("kind") == "cdn" for ip in outside):
                continue  # a CDN edge address (possibly another CDN), not an origin
            provider = next(
                (ip_hosts[ip].get("provider") for ip in outside if ip_hosts.get(ip, {}).get("provider")), None
            )
            same_net = any(_network(ip) in main_nets for ip in outside)
            candidates.append(
                {
                    "name": name,
                    "ips": outside,
                    "cname": cname_of.get(name),
                    "same_network": same_net,
                    "hint": _origin_word(name, ctx.domain),
                    "provider": provider,
                }
            )
        # Most interesting first: origin-like names, then everything else.
        candidates.sort(key=lambda c: (c["hint"] is None, c["name"]))

        data = {
            "behind_cdn": bool(cdn),
            "cdn": cdn,
            "main_ips": main_ips,
            "main_ptr": {ip: names for ip, names in ptr_names.items() if ip in main_ips},
            "resolved_count": len(resolved),
            "unique_ips": len(by_ip),
            "ip_groups": sorted(
                ({"ip": ip, "names": sorted(names)[:20], "count": len(names)} for ip, names in by_ip.items()),
                key=lambda g: (-g["count"], g["ip"]),
            )[:40],
            "candidates": candidates[:MAX_CANDIDATES],
        }
        result = ScannerResult(data=data)

        if cdn and candidates:
            named = [c for c in candidates if c["hint"]]
            sample = (named or candidates)[:8]
            result.findings.append(
                self.finding(
                    "outside_cdn",
                    f"{len(candidates)} subdomain(s) resolve outside the {', '.join(cdn)} edge",
                    Severity.LOW,
                    evidence="; ".join(f"{c['name']} -> {', '.join(c['ips'])}" for c in sample),
                    recommendation=(
                        "The main site is behind a CDN/WAF, but these subdomains point at other addresses. If any "
                        "of them is the web origin, an attacker can reach it directly and skip the WAF. Configure "
                        "the origin firewall to accept HTTP(S) only from the CDN's published IP ranges, and do not "
                        "host mail or admin panels on the same server as the website."
                    ),
                    references=[
                        "https://developers.cloudflare.com/fundamentals/concepts/cloudflare-ip-addresses/"
                    ],
                )
            )
        return result
