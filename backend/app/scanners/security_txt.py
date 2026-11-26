"""security.txt (RFC 9116): does the organisation say how to report vulnerabilities?

Fetches the standard public file, like robots.txt. One or two small requests.
"""

from datetime import UTC, datetime

import httpx

from app.core.ssrf_guard import BlockedTargetError, ResponseTooLargeError
from app.models.finding import Severity
from app.scanners.base import ScanContext, Scanner, ScannerResult, describe_error

PATHS = ("/.well-known/security.txt", "/security.txt")
MAX_BYTES = 32 * 1024
FIELDS = (
    "contact",
    "expires",
    "encryption",
    "acknowledgments",
    "acknowledgements",
    "preferred-languages",
    "canonical",
    "policy",
    "hiring",
    "csaf",
)
BOUNTY_HINTS = (
    "hackerone.com",
    "bugcrowd.com",
    "intigriti.com",
    "yeswehack.com",
    "bounty",
    "vdp",
    "disclosure",
)


def parse_security_txt(text: str) -> dict[str, list[str]]:
    fields: dict[str, list[str]] = {}
    for raw in text.splitlines()[:300]:
        line = raw.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        if key in FIELDS and value.strip():
            fields.setdefault(key, []).append(value.strip()[:300])
    return fields


def _looks_like_security_txt(text: str) -> bool:
    head = text.lstrip()[:200].lower()
    if head.startswith("<") or "<html" in head:
        return False  # soft-404 HTML page
    return bool(parse_security_txt(text))


class SecurityTxtScanner(Scanner):
    name = "security_txt"
    label = "security.txt"
    category = "Disclosure"
    timeout = 20.0

    async def run(self, ctx: ScanContext) -> ScannerResult:
        last_error = None
        for path in PATHS:
            url = f"https://{ctx.domain}{path}"
            try:
                resp = await ctx.client.get(
                    url,
                    headers={"Accept": "text/plain"},
                    max_bytes=MAX_BYTES,
                    allow_truncate=True,
                    timeout=10.0,
                )
            except (httpx.HTTPError, ResponseTooLargeError, BlockedTargetError, TimeoutError) as exc:
                last_error = describe_error(exc)
                continue
            if resp.status_code == 200 and _looks_like_security_txt(resp.text):
                return self._found(url, resp.text)

        result = ScannerResult(data={"found": False, "message": last_error})
        result.findings.append(
            self.finding(
                "missing",
                "No security.txt file",
                Severity.INFO,
                evidence=f"Neither {PATHS[0]} nor {PATHS[1]} returned a security.txt file.",
                recommendation=(
                    "Publish /.well-known/security.txt with a Contact and Expires field so researchers know "
                    "how to report vulnerabilities (RFC 9116)."
                ),
                references=["https://securitytxt.org/", "https://www.rfc-editor.org/rfc/rfc9116"],
            )
        )
        return result

    def _found(self, url: str, text: str) -> ScannerResult:
        fields = parse_security_txt(text)
        expires_raw = (fields.get("expires") or [None])[0]
        expired = None
        if expires_raw:
            try:
                exp = datetime.fromisoformat(expires_raw.replace("Z", "+00:00"))
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=UTC)
                expired = exp < datetime.now(UTC)
            except ValueError:
                expired = None
        joined = " ".join(v for vals in fields.values() for v in vals).lower()
        data = {
            "found": True,
            "url": url,
            "fields": fields,
            "expired": expired,
            "bug_bounty_hint": any(h in joined for h in BOUNTY_HINTS),
        }
        result = ScannerResult(data=data)
        if expired:
            result.findings.append(
                self.finding(
                    "expired",
                    "security.txt has expired",
                    Severity.LOW,
                    evidence=f"Expires: {expires_raw}",
                    recommendation="Update the Expires field; an expired file signals the contact may be stale.",
                    references=["https://www.rfc-editor.org/rfc/rfc9116#section-2.5.5"],
                )
            )
        if not fields.get("contact"):
            result.findings.append(
                self.finding(
                    "no_contact",
                    "security.txt has no Contact field",
                    Severity.LOW,
                    evidence=url,
                    recommendation="Add at least one Contact field (email or URL).",
                )
            )
        return result
