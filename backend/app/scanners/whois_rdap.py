"""Registration data via RDAP (the JSON successor to WHOIS), bootstrapped by rdap.org."""

from datetime import UTC, datetime
from typing import Any

from app.models.finding import Severity
from app.scanners.base import ScanContext, Scanner, ScannerResult

RDAP_BOOTSTRAP = "https://rdap.org/domain/"


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _vcard_name(entity: dict[str, Any]) -> str | None:
    vcard = entity.get("vcardArray")
    if isinstance(vcard, list) and len(vcard) == 2:
        for item in vcard[1]:
            if isinstance(item, list) and len(item) >= 4 and item[0] == "fn" and item[3]:
                return str(item[3])
    for pid in entity.get("publicIds", []) or []:
        if isinstance(pid, dict) and pid.get("identifier"):
            return f"IANA #{pid['identifier']}"
    return entity.get("handle")


def parse_rdap(doc: dict[str, Any]) -> dict[str, Any]:
    events = {
        e.get("eventAction"): e.get("eventDate") for e in doc.get("events", []) or [] if isinstance(e, dict)
    }
    registrar = None
    for ent in doc.get("entities", []) or []:
        if isinstance(ent, dict) and "registrar" in (ent.get("roles") or []):
            registrar = _vcard_name(ent)
            break
    nameservers = sorted(
        {
            str(ns.get("ldhName", "")).lower().rstrip(".")
            for ns in doc.get("nameservers", []) or []
            if isinstance(ns, dict) and ns.get("ldhName")
        }
    )
    created = _parse_date(events.get("registration"))
    expires = _parse_date(events.get("expiration"))
    updated = _parse_date(events.get("last changed") or events.get("last update of RDAP database"))
    days = None
    if expires:
        days = (expires - datetime.now(UTC)).days
    return {
        "registrar": registrar,
        "created": created.isoformat() if created else None,
        "expires": expires.isoformat() if expires else None,
        "updated": updated.isoformat() if updated else None,
        "nameservers": nameservers[:20],
        "status": [str(s) for s in (doc.get("status") or [])][:20],
        "days_until_expiry": days,
        "dnssec": bool((doc.get("secureDNS") or {}).get("delegationSigned")),
    }


class WhoisRdapScanner(Scanner):
    name = "whois_rdap"
    label = "Registration (RDAP)"
    category = "Domain registration"
    timeout = 30.0

    async def run(self, ctx: ScanContext) -> ScannerResult:
        labels = ctx.domain.split(".")
        doc = None
        registrable = ctx.domain
        # Walk up from the scanned name to find the registered domain (max 3 lookups).
        for i in range(min(3, len(labels) - 1)):
            candidate = ".".join(labels[i:])
            resp = await ctx.client.get(
                RDAP_BOOTSTRAP + candidate,
                headers={"Accept": "application/rdap+json, application/json"},
                max_bytes=1024 * 1024,
            )
            if resp.status_code == 200:
                doc = resp.json()
                registrable = candidate
                break
            if resp.status_code not in (404, 400):
                return ScannerResult(
                    data={"available": False, "message": f"RDAP service returned HTTP {resp.status_code}."}
                )

        if not isinstance(doc, dict):
            return ScannerResult(
                data={"available": False, "message": "No RDAP record found for this domain or its parents."}
            )

        data = {"available": True, "registrable_domain": registrable, **parse_rdap(doc)}
        result = ScannerResult(data=data)
        days = data["days_until_expiry"]
        if days is not None:
            if days < 0:
                result.findings.append(
                    self.finding(
                        "expired",
                        "Domain registration has expired",
                        Severity.CRITICAL,
                        evidence=f"Expiry date {data['expires']} ({-days} days ago).",
                        recommendation="Renew the domain immediately to prevent takeover by a third party.",
                    )
                )
            elif days <= 30:
                result.findings.append(
                    self.finding(
                        "expiring_soon",
                        "Domain registration expires within 30 days",
                        Severity.HIGH,
                        evidence=f"Expires {data['expires']} (in {days} days).",
                        recommendation="Renew now and enable auto-renew. Expired domains can be re-registered by attackers.",
                    )
                )
            elif days <= 90:
                result.findings.append(
                    self.finding(
                        "expiring",
                        "Domain registration expires within 90 days",
                        Severity.MEDIUM,
                        evidence=f"Expires {data['expires']} (in {days} days).",
                        recommendation="Enable auto-renew with the registrar.",
                    )
                )
        statuses = " ".join(data["status"]).lower()
        if data["status"] and "transfer prohibited" not in statuses:
            result.findings.append(
                self.finding(
                    "no_transfer_lock",
                    "Registrar transfer lock is not enabled",
                    Severity.LOW,
                    evidence="Status: " + ", ".join(data["status"]),
                    recommendation="Enable clientTransferProhibited (registrar lock) to block unauthorized transfers.",
                )
            )
        if not data["dnssec"]:
            result.findings.append(
                self.finding(
                    "no_dnssec",
                    "DNSSEC is not enabled",
                    Severity.INFO,
                    evidence="The registry reports no signed delegation.",
                    recommendation="Consider enabling DNSSEC to protect DNS answers against spoofing.",
                )
            )
        return result
