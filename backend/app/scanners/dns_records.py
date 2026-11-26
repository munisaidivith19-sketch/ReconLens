"""DNS records and what they reveal.

Record types at the domain itself, TLSA for HTTPS, a fixed list of well-known SRV services
(not a wordlist), reverse DNS for the domain's IPs, wildcard detection, DNSSEC state,
the mail provider and third-party services verified through TXT records.
All of it is ordinary DNS lookups: nothing is sent to the target's servers.
"""

import asyncio
import ipaddress
import secrets

from app.models.finding import Severity
from app.scanners import base
from app.scanners.base import ScanContext, Scanner, ScannerResult
from app.services.dns_signatures import mail_providers, txt_services

RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "TXT", "NS", "CAA")
EXTRA_TYPES = ("SOA", "DS", "DNSKEY", "HTTPS", "SVCB", "SSHFP", "NAPTR", "URI", "LOC", "CERT")
MAX_PER_TYPE = 50
MAX_VALUE_LEN = 300
MAX_PTR_IPS = 4

# Well-known service records. Querying a fixed list of standard names is not brute-forcing.
SRV_SERVICES = (
    "_sip._tcp",
    "_sip._udp",
    "_sips._tcp",
    "_sipfederationtls._tcp",
    "_xmpp-client._tcp",
    "_xmpp-server._tcp",
    "_jabber._tcp",
    "_matrix._tcp",
    "_ldap._tcp",
    "_ldaps._tcp",
    "_gc._tcp",
    "_kerberos._tcp",
    "_kerberos._udp",
    "_kpasswd._tcp",
    "_vlmcs._tcp",
    "_autodiscover._tcp",
    "_caldav._tcp",
    "_caldavs._tcp",
    "_carddav._tcp",
    "_carddavs._tcp",
    "_imap._tcp",
    "_imaps._tcp",
    "_pop3._tcp",
    "_pop3s._tcp",
    "_submission._tcp",
    "_h323cs._tcp",
    "_minecraft._tcp",
    "_ts3._udp",
)
# Services that normally belong inside a corporate network (Active Directory, KMS activation).
INTERNAL_SRV = (
    "_ldap._tcp",
    "_ldaps._tcp",
    "_gc._tcp",
    "_kerberos._tcp",
    "_kerberos._udp",
    "_kpasswd._tcp",
    "_vlmcs._tcp",
)


class DnsRecordsScanner(Scanner):
    name = "dns_records"
    label = "DNS records"
    category = "DNS"
    timeout = 45.0

    async def run(self, ctx: ScanContext) -> ScannerResult:
        records: dict[str, list[str]] = {}
        errors: dict[str, str] = {}

        async def one(rdtype: str) -> None:
            try:
                values = await base.dns_query(ctx.domain, rdtype)
                records[rdtype] = sorted(set(values))[:MAX_PER_TYPE]
            except base.DnsLookupError as exc:
                errors[rdtype] = str(exc)
                records[rdtype] = []

        await asyncio.gather(*(one(t) for t in RECORD_TYPES))
        records = {t: records.get(t, []) for t in RECORD_TYPES}
        extra = await self._extra(ctx.domain, records, errors)
        result = ScannerResult(data={"records": records, "errors": errors, **extra})
        result.findings.extend(self._extra_findings(extra))

        if not records["A"] and not records["AAAA"] and not records["CNAME"]:
            result.findings.append(
                self.finding(
                    "no_address",
                    "Domain has no A/AAAA records",
                    Severity.INFO,
                    evidence="No IPv4 or IPv6 address records were returned.",
                    recommendation="If the domain should serve a website, add address records.",
                )
            )

        if records["NS"] and not records["CAA"]:
            result.findings.append(
                self.finding(
                    "no_caa",
                    "No CAA record restricts which CAs may issue certificates",
                    Severity.LOW,
                    evidence="No CAA records found.",
                    recommendation=(
                        'Publish CAA records (e.g. 0 issue "letsencrypt.org") so only your chosen '
                        "certificate authorities can issue certificates for this domain."
                    ),
                    references=["https://letsencrypt.org/docs/caa/"],
                )
            )

        if records["A"] and not records["AAAA"]:
            result.findings.append(
                self.finding(
                    "no_ipv6",
                    "No IPv6 (AAAA) records",
                    Severity.INFO,
                    evidence=f"{len(records['A'])} A record(s), no AAAA records.",
                    recommendation="Informational only. Consider IPv6 support.",
                )
            )

        if len(records["NS"]) == 1:
            result.findings.append(
                self.finding(
                    "single_ns",
                    "Only one nameserver is configured",
                    Severity.LOW,
                    evidence=f"NS: {records['NS'][0]}",
                    recommendation="Use at least two nameservers on separate networks for resilience.",
                )
            )
        return result

    async def _extra(self, domain: str, records: dict[str, list[str]], errors: dict[str, str]) -> dict:
        limit = asyncio.Semaphore(10)

        async def q(name: str, rdtype: str) -> list[str]:
            async with limit:
                try:
                    values = await base.dns_query(name, rdtype)
                except base.DnsLookupError:
                    return []
            return sorted({v[:MAX_VALUE_LEN] for v in values})[:MAX_PER_TYPE]

        async def extra_type(rdtype: str) -> None:
            async with limit:
                try:
                    values = await base.dns_query(domain, rdtype)
                except base.DnsLookupError as exc:
                    errors[rdtype] = str(exc)
                    values = []
            records[rdtype] = sorted({v[:MAX_VALUE_LEN] for v in values})[:MAX_PER_TYPE]

        async def srv(service: str) -> dict | None:
            values = await q(f"{service}.{domain}", "SRV")
            return {"service": service, "records": values} if values else None

        ips = (records.get("A") or [])[:MAX_PTR_IPS] + (records.get("AAAA") or [])[: max(0, MAX_PTR_IPS - 2)]

        async def ptr(ip: str) -> dict | None:
            try:
                rev = ipaddress.ip_address(ip).reverse_pointer
            except ValueError:
                return None
            names = await q(rev, "PTR")
            return {"ip": ip, "names": [n.rstrip(".") for n in names]} if names else None

        # A random label that cannot exist: if it resolves, the zone has a wildcard record.
        probe = f"rl-{secrets.token_hex(6)}.{domain}"

        results = await asyncio.gather(
            asyncio.gather(*(extra_type(t) for t in EXTRA_TYPES)),
            q(f"_443._tcp.{domain}", "TLSA"),
            asyncio.gather(*(srv(s) for s in SRV_SERVICES)),
            asyncio.gather(*(ptr(ip) for ip in ips)),
            q(probe, "A"),
        )
        _, tlsa, srv_results, ptr_results, wildcard_hits = results
        records["TLSA"] = tlsa

        return {
            "srv": [r for r in srv_results if r],
            "ptr": [r for r in ptr_results if r],
            "wildcard": bool(wildcard_hits),
            "dnssec": {
                "ds": bool(records.get("DS")),
                "dnskey": bool(records.get("DNSKEY")),
                "signed": bool(records.get("DS")) and bool(records.get("DNSKEY")),
            },
            "mail_providers": mail_providers(records.get("MX") or []),
            "services": txt_services(records.get("TXT") or []),
        }

    def _extra_findings(self, extra: dict) -> list:
        out = []
        if extra["wildcard"]:
            out.append(
                self.finding(
                    "wildcard",
                    "Wildcard DNS: every subdomain name resolves",
                    Severity.INFO,
                    evidence="A random, non-existent subdomain returned an address.",
                    recommendation=(
                        "Wildcard records make any typo or forgotten name reachable and can hide dangling "
                        "records. Use explicit records unless the wildcard is needed."
                    ),
                )
            )
        dnssec = extra["dnssec"]
        if dnssec["ds"] and not dnssec["dnskey"]:
            out.append(
                self.finding(
                    "dnssec_broken",
                    "DNSSEC is half configured (DS record without DNSKEY)",
                    Severity.MEDIUM,
                    evidence="The parent zone publishes a DS record, but the domain returns no DNSKEY.",
                    recommendation="Fix the DNSSEC chain or remove the DS record; validating resolvers may fail to resolve the domain.",
                )
            )
        internal = [r["service"] for r in extra["srv"] if r["service"] in INTERNAL_SRV]
        if internal:
            out.append(
                self.finding(
                    "internal_srv",
                    "Public DNS advertises internal directory services",
                    Severity.LOW,
                    evidence="SRV records: " + ", ".join(internal),
                    recommendation=(
                        "LDAP, Kerberos, Global Catalog and KMS records point attackers at Active Directory "
                        "infrastructure. Publish them only in internal (split-horizon) DNS."
                    ),
                )
            )
        if extra["srv"]:
            out.append(
                self.finding(
                    "srv_services",
                    f"{len(extra['srv'])} service(s) published through SRV records",
                    Severity.INFO,
                    evidence=", ".join(r["service"] for r in extra["srv"][:15]),
                    recommendation="Check that each advertised service is intended to be public and is patched.",
                )
            )
        if extra["services"]:
            out.append(
                self.finding(
                    "third_party_services",
                    f"TXT records reveal {len(extra['services'])} third-party service(s)",
                    Severity.INFO,
                    evidence=", ".join(s["service"] for s in extra["services"][:20]),
                    recommendation=(
                        "Verification records show which SaaS tools the organisation uses, which helps phishing "
                        "pretexts. Remove records for services no longer in use."
                    ),
                )
            )
        return out
