"""DNS records: A, AAAA, CNAME, MX, TXT, NS, CAA."""

import asyncio

from app.models.finding import Severity
from app.scanners import base
from app.scanners.base import ScanContext, Scanner, ScannerResult

RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "TXT", "NS", "CAA")
MAX_PER_TYPE = 50


class DnsRecordsScanner(Scanner):
    name = "dns_records"
    label = "DNS records"
    category = "DNS"
    timeout = 25.0

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
        result = ScannerResult(data={"records": records, "errors": errors})

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

        verification = [t for t in records["TXT"] if "verification" in t.lower() or "=" in t[:40]]
        if len(verification) >= 8:
            result.findings.append(
                self.finding(
                    "txt_sprawl",
                    "Many TXT verification records reveal third-party services",
                    Severity.INFO,
                    evidence=f"{len(verification)} TXT records look like service verification tokens.",
                    recommendation="Remove verification records for services you no longer use.",
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
