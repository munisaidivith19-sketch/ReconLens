"""Scanner interface and the shared per-scan context."""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, ClassVar

from app.core.ssrf_guard import BlockedTargetError, SafeHttpClient, SafeResponse
from app.models.finding import Finding, Severity

HOMEPAGE_MAX_BYTES = 2 * 1024 * 1024


@dataclass
class ScannerResult:
    data: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)


class HomepageUnavailableError(Exception):
    pass


@dataclass
class ScanContext:
    """State shared by all scanners in one scan.

    The homepage is fetched once (through the SSRF guard) and reused by every scanner
    that needs it, so a scan makes as few requests to the target as possible.
    """

    domain: str
    db: Any
    client: SafeHttpClient
    results: dict[str, Any] = field(default_factory=dict)
    _homepage: SafeResponse | None = None
    _homepage_error: str | None = None
    _homepage_done: bool = False
    _homepage_lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def homepage(self) -> SafeResponse:
        async with self._homepage_lock:
            if not self._homepage_done:
                await self._fetch_homepage()
                self._homepage_done = True
        if self._homepage is None:
            raise HomepageUnavailableError(self._homepage_error or "Homepage could not be fetched")
        return self._homepage

    async def _fetch_homepage(self) -> None:
        errors: list[str] = []
        for scheme in ("https", "http"):
            try:
                self._homepage = await self.client.get(
                    f"{scheme}://{self.domain}/",
                    headers={"Accept": "text/html,application/xhtml+xml,*/*;q=0.8"},
                    max_bytes=HOMEPAGE_MAX_BYTES,
                    allow_truncate=True,
                )
                return
            except BlockedTargetError as exc:
                errors.append(exc.message)
                break  # a blocked redirect will be blocked on http too
            except Exception as exc:  # noqa: BLE001 - try the next scheme
                errors.append(f"{scheme}: {describe_error(exc)}")
        self._homepage_error = "; ".join(errors) or "Homepage could not be fetched"


def describe_error(exc: BaseException) -> str:
    """Short, safe description of an exception (no stack traces, no internals)."""
    if isinstance(exc, BlockedTargetError):
        return exc.message
    if isinstance(exc, TimeoutError | asyncio.TimeoutError):
        return "timed out"
    name = type(exc).__name__
    msg = str(exc).strip().splitlines()[0] if str(exc).strip() else ""
    if len(msg) > 160:
        msg = msg[:157] + "..."
    return f"{name}: {msg}" if msg else name


class DnsLookupError(Exception):
    pass


async def dns_query(name: str, rdtype: str) -> list[str]:
    """Resolve one record type. Returns [] when the name or record does not exist.

    Scanners call this as ``base.dns_query`` so tests can patch a single function.
    """
    import dns.asyncresolver
    import dns.exception
    import dns.resolver

    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 6.0
    resolver.timeout = 3.0
    try:
        answer = await resolver.resolve(name, rdtype)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.resolver.NoNameservers as exc:
        raise DnsLookupError("no nameserver answered") from exc
    except dns.exception.Timeout as exc:
        raise DnsLookupError("DNS lookup timed out") from exc
    out: list[str] = []
    for r in answer:
        if rdtype == "TXT":
            out.append(b"".join(r.strings).decode("utf-8", errors="replace"))
        else:
            out.append(r.to_text())
    return out


class Scanner(ABC):
    name: ClassVar[str]
    label: ClassVar[str]
    category: ClassVar[str]
    timeout: ClassVar[float] = 30.0
    depends_on: ClassVar[tuple[str, ...]] = ()

    @abstractmethod
    async def run(self, ctx: ScanContext) -> ScannerResult:
        """Run passive checks for ctx.domain and return data plus findings."""

    def finding(
        self,
        key: str,
        title: str,
        severity: Severity,
        evidence: str = "",
        recommendation: str = "",
        references: list[str] | None = None,
        category: str | None = None,
    ) -> Finding:
        return Finding(
            id=f"{self.name}.{key}",
            title=title,
            severity=severity,
            category=category or self.category,
            scanner=self.name,
            evidence=evidence[:2000],
            recommendation=recommendation[:2000],
            references=references or [],
        )
