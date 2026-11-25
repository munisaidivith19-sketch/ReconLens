"""Passive subdomain discovery from certificate transparency logs (crt.sh). No brute-forcing."""

import json
import re

import httpx

from app.core.ssrf_guard import ResponseTooLargeError
from app.models.finding import Severity
from app.scanners.base import ScanContext, Scanner, ScannerResult, describe_error

CRT_SH = "https://crt.sh/"
MAX_BYTES = 6 * 1024 * 1024
MAX_STORED = 500
_NAME_VALUE_RE = re.compile(r'"name_value"\s*:\s*"((?:[^"\\]|\\.)*)"')
_HOST_RE = re.compile(r"^(?:\*\.)?([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")

INTERESTING = (
    "admin",
    "api",
    "auth",
    "backup",
    "beta",
    "ci",
    "confluence",
    "dev",
    "git",
    "grafana",
    "internal",
    "jenkins",
    "jira",
    "kibana",
    "legacy",
    "old",
    "portal",
    "qa",
    "sso",
    "stage",
    "staging",
    "test",
    "uat",
    "vpn",
)


def extract_names(raw: bytes, domain: str) -> set[str]:
    """Pull hostnames from crt.sh JSON. Works on truncated JSON as well (regex based)."""
    names: set[str] = set()
    text = raw.decode("utf-8", errors="replace")
    for m in _NAME_VALUE_RE.finditer(text):
        try:
            value = json.loads(f'"{m.group(1)}"')
        except json.JSONDecodeError:
            continue
        for line in value.split("\n"):
            host = line.strip().lower().rstrip(".")
            if host.startswith("*."):
                host = host[2:]
            if not host or not _HOST_RE.match(host):
                continue
            if host == domain or host.endswith("." + domain):
                names.add(host)
    names.discard(domain)
    return names


def interesting_names(names: list[str], domain: str) -> list[str]:
    out = []
    for n in names:
        labels = n[: -len(domain) - 1].split(".")
        if any(lbl in INTERESTING or any(lbl.startswith(k + "-") for k in INTERESTING) for lbl in labels):
            out.append(n)
    return out


class SubdomainsScanner(Scanner):
    name = "subdomains"
    label = "Subdomains (certificate transparency)"
    category = "Attack surface"
    timeout = 60.0

    async def run(self, ctx: ScanContext) -> ScannerResult:
        try:
            resp = await ctx.client.get(
                CRT_SH,
                params={"q": f"%.{ctx.domain}", "output": "json", "exclude": "expired"},
                headers={"Accept": "application/json"},
                max_bytes=MAX_BYTES,
                allow_truncate=True,
                timeout=httpx.Timeout(connect=10.0, read=45.0, write=10.0, pool=5.0),
            )
        except (httpx.TimeoutException, TimeoutError):
            return self._unavailable(
                "crt.sh did not respond in time. Certificate transparency data is unavailable."
            )
        except (httpx.HTTPError, ResponseTooLargeError) as exc:
            return self._unavailable(f"crt.sh could not be reached ({describe_error(exc)}).")

        if resp.status_code != 200:
            return self._unavailable(f"crt.sh returned HTTP {resp.status_code}; source unavailable.")

        names = sorted(extract_names(resp.content, ctx.domain))
        interesting = interesting_names(names, ctx.domain)
        data = {
            "source": "crt.sh",
            "available": True,
            "count": len(names),
            "subdomains": names[:MAX_STORED],
            "truncated": len(names) > MAX_STORED or resp.truncated,
            "interesting": interesting[:100],
        }
        result = ScannerResult(data=data)
        if names:
            result.findings.append(
                self.finding(
                    "count",
                    f"{len(names)} subdomain(s) found in certificate transparency logs",
                    Severity.INFO,
                    evidence=", ".join(names[:10]) + (" …" if len(names) > 10 else ""),
                    recommendation="Review the list for forgotten or unmaintained hosts and decommission them.",
                )
            )
        if interesting:
            result.findings.append(
                self.finding(
                    "interesting",
                    "Subdomains suggest non-production or administrative systems",
                    Severity.LOW,
                    evidence=", ".join(interesting[:15]) + (" …" if len(interesting) > 15 else ""),
                    recommendation=(
                        "Make sure staging, admin and internal hosts are access-controlled and not exposed "
                        "to the internet unless they need to be."
                    ),
                )
            )
        return result

    def _unavailable(self, message: str) -> ScannerResult:
        return ScannerResult(
            data={
                "source": "crt.sh",
                "available": False,
                "count": 0,
                "subdomains": [],
                "interesting": [],
                "message": message,
            }
        )
