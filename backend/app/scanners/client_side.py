"""Client-side code review: secrets, cloud storage buckets and API endpoints in JavaScript.

Reads the homepage HTML (already fetched) and the same-site JavaScript files that the homepage
itself loads, exactly what a browser downloads on a normal visit. Nothing discovered here is
requested: buckets, endpoints and source maps are only listed for the user to review.

Secrets are masked before they are stored; the full value never leaves this module.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

import httpx

from app.core.ssrf_guard import BlockedTargetError, ResponseTooLargeError
from app.models.finding import Severity
from app.scanners.base import HomepageUnavailableError, ScanContext, Scanner, ScannerResult, describe_error
from app.scanners.tech_stack import parse_page

MAX_SCRIPTS = 10
SCRIPT_MAX_BYTES = 2 * 1024 * 1024
PARALLEL = 3
MAX_ENDPOINTS = 150
MAX_HOSTS = 100


@dataclass(frozen=True)
class SecretRule:
    key: str
    label: str
    severity: Severity
    pattern: re.Pattern[str]
    note: str


def _rx(p: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(p, flags)


# Self-written patterns for well-known, high-signal key formats.
SECRET_RULES: tuple[SecretRule, ...] = (
    SecretRule(
        "private_key",
        "Private key",
        Severity.CRITICAL,
        _rx(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"),
        "A private key must never be shipped to browsers. Revoke and replace it.",
    ),
    SecretRule(
        "aws_access_key",
        "AWS access key ID",
        Severity.HIGH,
        _rx(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        "Deactivate the key in AWS IAM and check CloudTrail for its use.",
    ),
    SecretRule(
        "stripe_secret",
        "Stripe live secret key",
        Severity.CRITICAL,
        _rx(r"\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b"),
        "Roll the key in the Stripe dashboard immediately; it allows charges and refunds.",
    ),
    SecretRule(
        "github_token",
        "GitHub token",
        Severity.HIGH,
        _rx(r"\b(?:gh[pousr]_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{40,})\b"),
        "Revoke the token on GitHub (Settings -> Developer settings).",
    ),
    SecretRule(
        "slack_token",
        "Slack token",
        Severity.HIGH,
        _rx(r"\bxox[abposr]-[0-9A-Za-z-]{10,}\b"),
        "Revoke the token in the Slack app configuration.",
    ),
    SecretRule(
        "slack_webhook",
        "Slack incoming webhook",
        Severity.MEDIUM,
        _rx(r"https://hooks\.slack\.com/services/T[0-9A-Z]{6,}/B[0-9A-Z]{6,}/[0-9A-Za-z]{20,}"),
        "Anyone can post messages to the channel. Regenerate the webhook URL.",
    ),
    SecretRule(
        "sendgrid_key",
        "SendGrid API key",
        Severity.HIGH,
        _rx(r"\bSG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}\b"),
        "Delete the key in SendGrid; it can send email as your domain.",
    ),
    SecretRule(
        "mailgun_key",
        "Mailgun API key",
        Severity.HIGH,
        _rx(r"\bkey-[0-9a-f]{32}\b"),
        "Rotate the key in Mailgun.",
    ),
    SecretRule(
        "twilio_key",
        "Twilio API key SID",
        Severity.MEDIUM,
        _rx(r"\bSK[0-9a-f]{32}\b"),
        "Check whether the matching secret is also exposed, and rotate the key in Twilio.",
    ),
    SecretRule(
        "openai_key",
        "OpenAI-style API key",
        Severity.HIGH,
        _rx(r"\bsk-(?:proj-|svcacct-)?[0-9A-Za-z_-]{32,}\b"),
        "Revoke the key with the provider; it is billed to your account.",
    ),
    SecretRule(
        "google_api_key",
        "Google API key",
        Severity.LOW,
        _rx(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        "Browser keys (Maps, Firebase) are expected to be public, but restrict them by HTTP referrer "
        "and to the APIs you use in Google Cloud Console.",
    ),
    SecretRule(
        "jwt",
        "JSON Web Token",
        Severity.LOW,
        _rx(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "Hard-coded JWTs are often public 'anon' keys (Supabase) but can be long-lived service tokens. "
        "Decode it and check its role and expiry.",
    ),
)

# Cloud storage references: (provider, regex with a 'name' group).
BUCKET_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "AWS S3",
        _rx(r"\b(?P<name>[a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.s3[.-](?:[a-z0-9-]+\.)?amazonaws\.com", re.I),
    ),
    (
        "AWS S3",
        _rx(
            r"(?<![\w.-])s3[.-](?:[a-z0-9-]+\.)?amazonaws\.com/(?P<name>[a-z0-9][a-z0-9.-]{1,61}[a-z0-9])",
            re.I,
        ),
    ),
    ("Azure Blob", _rx(r"\b(?P<name>[a-z0-9]{3,24})\.blob\.core\.windows\.net", re.I)),
    (
        "Google Cloud Storage",
        _rx(r"\bstorage\.googleapis\.com/(?P<name>[a-z0-9][a-z0-9._-]{1,61}[a-z0-9])", re.I),
    ),
    (
        "Google Cloud Storage",
        _rx(r"\b(?P<name>[a-z0-9][a-z0-9._-]{1,61}[a-z0-9])\.storage\.googleapis\.com", re.I),
    ),
    ("Firebase Realtime DB", _rx(r"\b(?P<name>[a-z0-9-]{3,})\.firebaseio\.com", re.I)),
    ("Firebase Storage", _rx(r"\b(?P<name>[a-z0-9-]{3,})\.(?:appspot\.com|firebasestorage\.app)", re.I)),
    ("DigitalOcean Spaces", _rx(r"\b(?P<name>[a-z0-9-]{3,63})\.[a-z0-9]+\.digitaloceanspaces\.com", re.I)),
    ("Cloudflare R2", _rx(r"\b(?P<name>pub-[0-9a-f]{32})\.r2\.dev", re.I)),
)

ENDPOINT_RX = _rx(
    r"""["'`](/(?:api|v\d+|graphql|gql|rest|internal|admin|auth|oauth|rpc|ajax|ws|webhook|services?)"""
    r"""(?:/[A-Za-z0-9_\-.{}:$]*)*)(?:\?[^"'`\s]*)?["'`]"""
)
URL_RX = _rx(
    r"""https?://([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)""", re.I
)
SOURCEMAP_RX = _rx(r"(?://|/\*)[#@]\s*sourceMappingURL=([^\s*'\"]+)")
# Hosts that show up in almost every bundle and say nothing about the target.
NOISE_HOSTS = ("w3.org", "schema.org", "reactjs.org", "react.dev", "mozilla.org", "github.com", "npmjs.com")


def mask(value: str) -> str:
    if len(value) <= 12:
        return value[:2] + "…"
    return f"{value[:6]}…{value[-4:]}"


def _same_site(host: str, domain: str) -> bool:
    host = host.lower().rstrip(".")
    return host == domain or host.endswith("." + domain)


def analyse(text: str, source: str, domain: str, acc: dict) -> None:
    """Scan one HTML/JS document and merge what it contains into acc."""
    for rule in SECRET_RULES:
        for m in rule.pattern.finditer(text):
            masked = mask(m.group(0))
            bucket = acc["secrets"].setdefault(rule.key, {"values": {}, "rule": rule})
            if len(bucket["values"]) < 10:
                bucket["values"].setdefault(masked, source)
    for provider, rx in BUCKET_RULES:
        for m in rx.finditer(text):
            key = (provider, m.group("name").lower())
            if key not in acc["buckets"] and len(acc["buckets"]) < 50:
                acc["buckets"][key] = {
                    "provider": provider,
                    "name": key[1],
                    "url": m.group(0),
                    "source": source,
                }
    for m in ENDPOINT_RX.finditer(text):
        path = m.group(1)[:200]
        if len(acc["endpoints"]) < MAX_ENDPOINTS:
            acc["endpoints"].setdefault(path, source)
    for m in URL_RX.finditer(text):
        host = m.group(1).lower()
        if any(host == n or host.endswith("." + n) for n in NOISE_HOSTS):
            continue
        target = acc["in_scope_hosts"] if _same_site(host, domain) else acc["third_party_hosts"]
        if len(target) < MAX_HOSTS:
            target.add(host)
    for m in SOURCEMAP_RX.finditer(text):
        ref = m.group(1)
        if not ref.startswith("data:") and len(acc["source_maps"]) < 20:
            acc["source_maps"][urljoin(source, ref)] = source


class ClientSideScanner(Scanner):
    name = "client_side"
    label = "JavaScript secrets, buckets & endpoints"
    category = "Client-side code"
    timeout = 60.0

    async def run(self, ctx: ScanContext) -> ScannerResult:
        try:
            page = await ctx.homepage()
        except HomepageUnavailableError as exc:
            return ScannerResult(data={"status": "unavailable", "message": str(exc)})

        html = page.text
        _meta, srcs = parse_page(html)
        acc: dict = {
            "secrets": {},
            "buckets": {},
            "endpoints": {},
            "in_scope_hosts": set(),
            "third_party_hosts": set(),
            "source_maps": {},
        }
        analyse(html, page.url, ctx.domain, acc)

        scripts: list[str] = []
        external = 0
        for src in srcs:
            url = urljoin(page.url, src)
            parts = urlsplit(url)
            if parts.scheme not in ("http", "https") or not parts.hostname:
                continue
            if not _same_site(parts.hostname, ctx.domain):
                external += 1
                continue
            if url not in scripts:
                scripts.append(url)
        fetched: list[dict] = []
        limit = asyncio.Semaphore(PARALLEL)

        async def fetch(url: str) -> None:
            async with limit:
                try:
                    resp = await ctx.client.get(
                        url,
                        headers={"Accept": "*/*", "Referer": page.url},
                        max_bytes=SCRIPT_MAX_BYTES,
                        allow_truncate=True,
                        timeout=15.0,
                    )
                except (httpx.HTTPError, ResponseTooLargeError, BlockedTargetError, TimeoutError) as exc:
                    fetched.append({"url": url, "status": None, "error": describe_error(exc)})
                    return
                entry = {
                    "url": url,
                    "status": resp.status_code,
                    "bytes": len(resp.content),
                    "truncated": resp.truncated,
                }
                fetched.append(entry)
                if resp.status_code == 200:
                    analyse(resp.text, url, ctx.domain, acc)
                    if resp.headers.get("sourcemap") or resp.headers.get("x-sourcemap"):
                        ref = resp.headers.get("sourcemap") or resp.headers.get("x-sourcemap")
                        acc["source_maps"].setdefault(urljoin(url, ref), url)

        await asyncio.gather(*(fetch(u) for u in scripts[:MAX_SCRIPTS]))

        secrets = [
            {
                "type": key,
                "label": b["rule"].label,
                "severity": b["rule"].severity.value,
                "matches": [{"value": v, "source": s} for v, s in b["values"].items()],
            }
            for key, b in acc["secrets"].items()
        ]
        data = {
            "status": "ok",
            "scripts_found": len(scripts),
            "scripts_external": external,
            "scripts": sorted(fetched, key=lambda f: f["url"]),
            "secrets": secrets,
            "buckets": list(acc["buckets"].values()),
            "endpoints": [{"path": p, "source": s} for p, s in sorted(acc["endpoints"].items())],
            "in_scope_hosts": sorted(acc["in_scope_hosts"] - {ctx.domain}),
            "third_party_hosts": sorted(acc["third_party_hosts"]),
            "source_maps": [{"url": u, "source": s} for u, s in acc["source_maps"].items()],
        }
        result = ScannerResult(data=data)
        self._findings(result, acc)
        return result

    def _findings(self, result: ScannerResult, acc: dict) -> None:
        for key, b in acc["secrets"].items():
            rule: SecretRule = b["rule"]
            examples = "; ".join(f"{v} in {s}" for v, s in list(b["values"].items())[:3])
            result.findings.append(
                self.finding(
                    f"secret.{key}",
                    f"{rule.label} found in client-side code",
                    rule.severity,
                    evidence=f"{len(b['values'])} match(es), masked: {examples}",
                    recommendation=(
                        f"{rule.note} Then remove it from the front-end and keep secrets on the server; "
                        "anything in JavaScript is readable by every visitor."
                    ),
                    references=["https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"],
                )
            )
        if acc["buckets"]:
            items = list(acc["buckets"].values())
            result.findings.append(
                self.finding(
                    "cloud_buckets",
                    f"{len(items)} cloud storage bucket(s) referenced in client-side code",
                    Severity.INFO,
                    evidence=", ".join(f"{b['provider']}: {b['name']}" for b in items[:10]),
                    recommendation=(
                        "Make sure each bucket only allows the access it needs: no public listing, no anonymous "
                        "writes, and Firebase security rules that do not allow open read/write."
                    ),
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Secure_Cloud_Architecture_Cheat_Sheet.html"
                    ],
                )
            )
        if acc["source_maps"]:
            result.findings.append(
                self.finding(
                    "source_maps",
                    "JavaScript source maps are referenced",
                    Severity.INFO,
                    evidence=", ".join(list(acc["source_maps"])[:5]),
                    recommendation=(
                        "Public source maps can expose original source code, comments and internal paths. "
                        "Do not deploy .map files to production, or restrict access to them."
                    ),
                )
            )
