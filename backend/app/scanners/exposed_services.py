"""Exposed services from Shodan InternetDB (https://internetdb.shodan.io).

InternetDB is a free, keyless lookup of what Shodan's own internet-wide scans saw on an IP:
open ports, software (CPEs), tags and CVEs. ReconLens never scans ports itself; it only
reads this public data. Free for non-commercial use. Results are cached for 24 hours.
"""

import httpx

from app.core.cache import api_cache_get, api_cache_set
from app.core.ssrf_guard import BlockedTargetError, ResponseTooLargeError
from app.models.finding import Severity
from app.scanners.base import ScanContext, Scanner, ScannerResult, describe_error

INTERNETDB = "https://internetdb.shodan.io/"
MAX_IPS = 3
MAX_BYTES = 256 * 1024

# port -> (service, severity, why)
RISKY_PORTS: dict[int, tuple[str, Severity, str]] = {
    23: ("Telnet", Severity.HIGH, "sends credentials in clear text"),
    445: ("SMB", Severity.HIGH, "file sharing is a common ransomware entry point"),
    2375: ("Docker API (no TLS)", Severity.HIGH, "an open Docker API gives full control of the host"),
    3306: ("MySQL", Severity.HIGH, "databases should not be reachable from the internet"),
    5432: ("PostgreSQL", Severity.HIGH, "databases should not be reachable from the internet"),
    1433: ("Microsoft SQL Server", Severity.HIGH, "databases should not be reachable from the internet"),
    1521: ("Oracle DB", Severity.HIGH, "databases should not be reachable from the internet"),
    27017: ("MongoDB", Severity.HIGH, "databases should not be reachable from the internet"),
    6379: ("Redis", Severity.HIGH, "Redis often runs without authentication"),
    9200: ("Elasticsearch", Severity.HIGH, "Elasticsearch often runs without authentication"),
    11211: ("Memcached", Severity.HIGH, "can leak data and be abused for DDoS amplification"),
    5984: ("CouchDB", Severity.HIGH, "databases should not be reachable from the internet"),
    9042: ("Cassandra", Severity.HIGH, "databases should not be reachable from the internet"),
    3389: ("RDP", Severity.MEDIUM, "remote desktop is a frequent brute-force and exploit target"),
    5900: ("VNC", Severity.MEDIUM, "remote desktop is a frequent brute-force target"),
    161: ("SNMP", Severity.MEDIUM, "default community strings can leak device configuration"),
    2049: ("NFS", Severity.MEDIUM, "network file shares should not be public"),
    21: ("FTP", Severity.LOW, "sends credentials in clear text unless FTPS is enforced"),
    25: ("SMTP", Severity.INFO, "mail server"),
    22: ("SSH", Severity.INFO, "remote shell; make sure password login is disabled"),
}


class ExposedServicesScanner(Scanner):
    name = "exposed_services"
    label = "Exposed services (Shodan InternetDB)"
    category = "Attack surface"
    timeout = 30.0
    depends_on = ("dns_records",)

    async def run(self, ctx: ScanContext) -> ScannerResult:
        records = ((ctx.results.get("dns_records") or {}).get("records")) or {}
        ips = [ip for ip in records.get("A") or [] if ":" not in ip][:MAX_IPS]
        hosts: list[dict] = []
        errors: list[str] = []
        for ip in ips:
            try:
                hosts.append(await self._lookup(ctx, ip))
            except (
                httpx.HTTPError,
                ResponseTooLargeError,
                BlockedTargetError,
                TimeoutError,
                ValueError,
            ) as exc:
                errors.append(f"{ip}: {describe_error(exc)}")

        data = {
            "source": "Shodan InternetDB",
            "available": bool(hosts) or not ips,
            "hosts": hosts,
            "errors": errors,
            "message": None
            if hosts
            else ("No IPv4 address to look up." if not ips else "InternetDB unavailable."),
        }
        result = ScannerResult(data=data)
        result.findings.extend(self._findings(hosts))
        return result

    async def _lookup(self, ctx: ScanContext, ip: str) -> dict:
        key = f"internetdb:{ip}"
        cached = await api_cache_get(ctx.db, key)
        if cached is not None:
            return cached
        resp = await ctx.client.get(
            f"{INTERNETDB}{ip}", headers={"Accept": "application/json"}, max_bytes=MAX_BYTES, timeout=12.0
        )
        if resp.status_code == 404:
            host = {
                "ip": ip,
                "ports": [],
                "cpes": [],
                "hostnames": [],
                "tags": [],
                "vulns": [],
                "known": False,
            }
        elif resp.status_code == 200:
            raw = resp.json()
            if not isinstance(raw, dict):
                raise ValueError("unexpected InternetDB response")
            host = {
                "ip": ip,
                "ports": sorted(int(p) for p in raw.get("ports") or [] if str(p).isdigit())[:100],
                "cpes": [str(c)[:120] for c in raw.get("cpes") or []][:50],
                "hostnames": [str(h)[:200] for h in raw.get("hostnames") or []][:50],
                "tags": [str(t)[:40] for t in raw.get("tags") or []][:20],
                "vulns": sorted(str(v)[:30] for v in raw.get("vulns") or [])[:100],
                "known": True,
            }
        else:
            raise ValueError(f"InternetDB returned HTTP {resp.status_code}")
        await api_cache_set(ctx.db, key, host)
        return host

    def _findings(self, hosts: list[dict]) -> list:
        out = []
        for host in hosts:
            ip = host["ip"]
            behind_cdn = "cdn" in host["tags"]
            for port in host["ports"]:
                info = RISKY_PORTS.get(port)
                if not info or info[1] == Severity.INFO or behind_cdn:
                    continue
                service, severity, why = info
                out.append(
                    self.finding(
                        f"port.{ip}.{port}",
                        f"{service} (port {port}) is reachable on {ip}",
                        severity,
                        evidence=f"Shodan InternetDB lists port {port} open on {ip}. ReconLens did not connect to it.",
                        recommendation=f"Restrict port {port} with a firewall or VPN: {why}.",
                        references=[f"https://internetdb.shodan.io/{ip}"],
                    )
                )
            if host["vulns"] and not behind_cdn:
                out.append(
                    self.finding(
                        f"vulns.{ip}",
                        f"Shodan associates {len(host['vulns'])} CVE(s) with {ip}",
                        Severity.MEDIUM,
                        evidence=", ".join(host["vulns"][:15]) + (" …" if len(host["vulns"]) > 15 else ""),
                        recommendation=(
                            "These CVEs are inferred from service banners and versions, not confirmed exploits. "
                            "Verify the installed versions and patch."
                        ),
                        references=[f"https://internetdb.shodan.io/{ip}"],
                    )
                )
        return out
