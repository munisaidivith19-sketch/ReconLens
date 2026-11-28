"""SSRF guard: target validation and the only HTTP/TLS client allowed to leave the process.

Every outbound network request that touches a user-supplied host (and, for one audited
choke point, every third-party API call as well) goes through this module:

* ``normalize_target`` turns user input into a validated hostname (punycode, no IPs,
  no credentials, http/https only, ports 80/443 only).
* ``resolve_and_validate`` resolves A/AAAA and rejects the host if ANY address is
  non-public.
* ``SafeHttpClient`` connects only to the validated IP while sending the real Host header
  and TLS SNI (defeats DNS rebinding), follows redirects manually with re-validation of
  every hop, caps the body size, and uses strict timeouts.
* ``tls_handshake`` opens a TLS connection to a validated IP for certificate inspection.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import ssl
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlsplit

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx
import idna

USER_AGENT = (
    "ReconLens/1.0 (+passive attack-surface analysis; https://github.com/munisaidivith19-sketch/ReconLens)"
)
DEFAULT_MAX_BYTES = 2 * 1024 * 1024
MAX_REDIRECTS = 5
ALLOWED_SCHEMES = {"http": 80, "https": 443}
DEFAULT_TIMEOUT = httpx.Timeout(connect=5.0, read=10.0, write=5.0, pool=5.0)

_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_TLD_RE = re.compile(r"^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$")
_BLOCKED_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".intranet",
    ".lan",
    ".home",
    ".corp",
    ".localdomain",
    ".arpa",
    ".test",
    ".invalid",
    ".example",
    ".onion",
)

# Networks that are never acceptable as a destination, on top of the ipaddress flags.
_EXTRA_BLOCKED_NETS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),  # CGNAT
    ipaddress.ip_network("169.254.0.0/16"),  # link-local incl. cloud metadata
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("64:ff9b::/96"),  # NAT64 (may embed private IPv4)
    ipaddress.ip_network("64:ff9b:1::/48"),
    ipaddress.ip_network("100::/64"),  # discard-only
    ipaddress.ip_network("2001::/23"),  # IETF protocol assignments (Teredo etc.)
    ipaddress.ip_network("2001:db8::/32"),  # documentation
    ipaddress.ip_network("2002::/16"),  # 6to4 (may embed private IPv4)
    ipaddress.ip_network("fc00::/7"),  # unique-local
    ipaddress.ip_network("fe80::/10"),  # link-local
    ipaddress.ip_network("fec0::/10"),  # site-local (deprecated)
    ipaddress.ip_network("ff00::/8"),  # multicast
]


class BlockedTargetError(ValueError):
    """Raised when a target (or a redirect hop) is not allowed."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class ResponseTooLargeError(Exception):
    pass


@dataclass(frozen=True)
class Target:
    scheme: str
    host: str  # ASCII / punycode, lowercase, no trailing dot
    port: int
    path: str  # path + query, always starts with "/"

    @property
    def origin(self) -> str:
        default = ALLOWED_SCHEMES[self.scheme]
        port = "" if self.port == default else f":{self.port}"
        return f"{self.scheme}://{self.host}{port}"

    @property
    def url(self) -> str:
        return self.origin + self.path


# --------------------------------------------------------------------------- validation


def is_ip_blocked(ip: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True if the address is not a globally routable unicast address."""
    try:
        addr = ipaddress.ip_address(ip) if isinstance(ip, str) else ip
    except ValueError:
        return True

    if isinstance(addr, ipaddress.IPv6Address):
        # IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible (::a.b.c.d) addresses
        if addr.ipv4_mapped is not None:
            return is_ip_blocked(addr.ipv4_mapped)
        if addr.sixtofour is not None:
            return True
        if addr.teredo is not None:
            return True
        packed = addr.packed
        if packed[:12] == b"\x00" * 12:
            return True  # IPv4-compatible / unspecified / loopback forms

    if (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
        or not addr.is_global
    ):
        return True
    return any(addr in net for net in _EXTRA_BLOCKED_NETS if net.version == addr.version)


def _is_ip_literal(host: str) -> bool:
    h = host.strip("[]")
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        pass
    # Legacy numeric forms that some resolvers/libraries accept: 2130706433, 0x7f.1, 0177.0.0.1
    if re.fullmatch(r"(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}", h, re.IGNORECASE):
        return True
    return False


def _to_ascii_host(host: str) -> str:
    host = host.strip().rstrip(".").lower()
    if not host:
        raise BlockedTargetError("invalid_host", "Enter a domain name, for example example.com.")
    if _is_ip_literal(host):
        raise BlockedTargetError(
            "ip_address",
            "Raw IP addresses can't be scanned. Enter a domain name instead.",
        )
    try:
        ascii_host = idna.encode(host, uts46=True).decode("ascii")
    except idna.IDNAError as exc:
        raise BlockedTargetError("invalid_host", "That domain name is not valid.") from exc
    ascii_host = ascii_host.lower()
    if len(ascii_host) > 253:
        raise BlockedTargetError("invalid_host", "That domain name is too long.")
    labels = ascii_host.split(".")
    if len(labels) < 2 or not all(_LABEL_RE.match(lbl) for lbl in labels):
        raise BlockedTargetError(
            "invalid_host", "Enter a full domain name with a public suffix, like example.com."
        )
    if not _TLD_RE.match(labels[-1]):
        raise BlockedTargetError("invalid_host", "That domain does not have a valid top-level domain.")
    if ascii_host == "localhost" or ascii_host.endswith(_BLOCKED_SUFFIXES):
        raise BlockedTargetError("internal_host", "Internal or reserved hostnames can't be scanned.")
    return ascii_host


def normalize_target(raw: str) -> Target:
    """Validate and normalize a user-supplied domain or URL (no DNS lookups)."""
    if not isinstance(raw, str):
        raise BlockedTargetError("invalid_host", "Enter a domain name.")
    raw = raw.strip()
    if not raw or len(raw) > 2048:
        raise BlockedTargetError("invalid_host", "Enter a domain name, for example example.com.")
    if any(ch.isspace() for ch in raw) or any(ord(ch) < 0x20 for ch in raw):
        raise BlockedTargetError("invalid_host", "The target must not contain spaces.")
    if "\\" in raw:
        raise BlockedTargetError("invalid_host", "The target contains invalid characters.")

    # "javascript:...", "data:...", "mailto:..." etc. (but not "host:443")
    scheme_like = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*):(?!\d)", raw)
    if scheme_like and scheme_like.group(1).lower() not in ALLOWED_SCHEMES:
        raise BlockedTargetError("scheme", "Only http and https targets are supported.")

    candidate = raw if "://" in raw else f"https://{raw}"
    if raw.startswith("//"):
        candidate = f"https:{raw}"
    try:
        parts = urlsplit(candidate)
    except ValueError as exc:
        raise BlockedTargetError("invalid_host", "That URL could not be parsed.") from exc

    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise BlockedTargetError("scheme", "Only http and https targets are supported.")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise BlockedTargetError("credentials", "URLs containing credentials are not allowed.")

    try:
        port = parts.port
    except ValueError as exc:
        raise BlockedTargetError("port", "That port is not valid.") from exc
    if port is None:
        port = ALLOWED_SCHEMES[scheme]
    if port not in (80, 443):
        raise BlockedTargetError("port", "Only the standard web ports 80 and 443 are allowed.")

    host = parts.hostname or ""
    if parts.netloc.startswith("[") or ":" in host:
        raise BlockedTargetError(
            "ip_address", "Raw IP addresses can't be scanned. Enter a domain name instead."
        )
    ascii_host = _to_ascii_host(host)

    path = parts.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    if parts.query:
        path = f"{path}?{parts.query}"
    return Target(scheme=scheme, host=ascii_host, port=port, path=path)


# --------------------------------------------------------------------------- resolution


async def _dns_lookup(host: str) -> list[str]:
    """Return all A and AAAA addresses for host. Separated out so tests can patch it."""
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 5.0
    resolver.timeout = 3.0
    addrs: list[str] = []
    for rdtype in ("A", "AAAA"):
        try:
            answer = await resolver.resolve(host, rdtype)
            addrs.extend(r.to_text() for r in answer)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            continue
        except (dns.resolver.NoNameservers, dns.exception.Timeout):
            continue
    return addrs


async def resolve_and_validate(host: str) -> list[str]:
    """Resolve host and return its addresses; raise if none, or if ANY is non-public."""
    host = _to_ascii_host(host)
    addrs = await _dns_lookup(host)
    if not addrs:
        raise BlockedTargetError("unresolvable", f"{host} does not resolve to any address.")
    for a in addrs:
        if is_ip_blocked(a):
            raise BlockedTargetError(
                "private_ip",
                f"{host} resolves to a private or reserved address, which can't be scanned.",
            )
    # Prefer IPv4 for connectivity on hosts without IPv6 egress.
    addrs.sort(key=lambda a: ipaddress.ip_address(a).version)
    return addrs


async def validate_target(raw: str) -> tuple[Target, list[str]]:
    target = normalize_target(raw)
    ips = await resolve_and_validate(target.host)
    return target, ips


# --------------------------------------------------------------------------- HTTP client


@dataclass
class SafeResponse:
    url: str
    status_code: int
    headers: httpx.Headers
    content: bytes
    truncated: bool = False
    redirects: list[str] = field(default_factory=list)
    ip: str = ""

    @property
    def text(self) -> str:
        charset = "utf-8"
        ctype = self.headers.get("content-type", "")
        m = re.search(r"charset=([\w-]+)", ctype, re.IGNORECASE)
        if m:
            charset = m.group(1)
        try:
            return self.content.decode(charset, errors="replace")
        except LookupError:
            return self.content.decode("utf-8", errors="replace")

    def json(self) -> Any:
        import json

        return json.loads(self.content)

    @property
    def set_cookie_headers(self) -> list[str]:
        return self.headers.get_list("set-cookie")


def _url_for_ip(scheme: str, ip: str, port: int, path: str) -> str:
    host = f"[{ip}]" if ":" in ip else ip
    default = ALLOWED_SCHEMES[scheme]
    port_part = "" if port == default else f":{port}"
    return f"{scheme}://{host}{port_part}{path}"


class SafeHttpClient:
    """HTTP client that only talks to validated public IPs.

    Use as an async context manager::

        async with SafeHttpClient() as client:
            resp = await client.get("https://example.com/")
    """

    def __init__(
        self,
        *,
        timeout: httpx.Timeout | float = DEFAULT_TIMEOUT,
        verify: bool = True,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self._verify = verify
        self._client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,  # never route via env proxies
            verify=verify,
            transport=transport,
            headers={"User-Agent": USER_AGENT, "Accept-Encoding": "gzip, deflate"},
        )

    async def __aenter__(self) -> SafeHttpClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        max_bytes: int = DEFAULT_MAX_BYTES,
        allow_truncate: bool = False,
        follow_redirects: bool = True,
        max_redirects: int = MAX_REDIRECTS,
        timeout: httpx.Timeout | float | None = None,
    ) -> SafeResponse:
        current = url
        if params:
            query = str(httpx.QueryParams(params))
            current = f"{url}{'&' if '?' in url else '?'}{query}"
        redirects: list[str] = []

        for _hop in range(max_redirects + 1):
            target = normalize_target(current)
            if "://" not in current:
                raise BlockedTargetError("invalid_host", "An absolute URL is required.")
            ips = await resolve_and_validate(target.host)
            ip = ips[0]
            resp = await self._request_once(target, ip, headers, max_bytes, allow_truncate, timeout)
            resp.redirects = list(redirects)
            if follow_redirects and resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("location")
                if not location:
                    return resp
                nxt = urljoin(target.url, location.strip())
                redirects.append(nxt)
                current = nxt
                continue
            return resp
        raise BlockedTargetError("too_many_redirects", "The target redirected too many times.")

    async def post_form(
        self,
        url: str,
        *,
        data: dict[str, str],
        headers: dict[str, str] | None = None,
        max_bytes: int = DEFAULT_MAX_BYTES,
        timeout: httpx.Timeout | float | None = None,
    ) -> SafeResponse:
        """POST a small form to a fixed third-party API (never to a scan target). No redirects."""
        target = normalize_target(url)
        if "://" not in url:
            raise BlockedTargetError("invalid_host", "An absolute URL is required.")
        ips = await resolve_and_validate(target.host)
        body = str(httpx.QueryParams(data)).encode()
        form_headers = {"Content-Type": "application/x-www-form-urlencoded", **(headers or {})}
        return await self._request_once(
            target, ips[0], form_headers, max_bytes, False, timeout, method="POST", content=body
        )

    async def _request_once(
        self,
        target: Target,
        ip: str,
        headers: dict[str, str] | None,
        max_bytes: int,
        allow_truncate: bool,
        timeout: httpx.Timeout | float | None = None,
        *,
        method: str = "GET",
        content: bytes | None = None,
    ) -> SafeResponse:
        default_port = ALLOWED_SCHEMES[target.scheme]
        host_header = target.host if target.port == default_port else f"{target.host}:{target.port}"
        req_headers = {"Host": host_header, "Accept": "*/*"}
        if headers:
            req_headers.update({k: v for k, v in headers.items() if k.lower() != "host"})
        extensions = {"sni_hostname": target.host} if target.scheme == "https" else {}
        ip_url = _url_for_ip(target.scheme, ip, target.port, target.path)

        request = self._client.build_request(
            method,
            ip_url,
            headers=req_headers,
            content=content,
            extensions=extensions,
            **({"timeout": timeout} if timeout is not None else {}),
        )
        response = await self._client.send(request, stream=True)
        try:
            declared = response.headers.get("content-length")
            if declared and declared.isdigit() and int(declared) > max_bytes and not allow_truncate:
                raise ResponseTooLargeError(f"Response larger than {max_bytes} bytes")
            chunks: list[bytes] = []
            size = 0
            truncated = False
            async for chunk in response.aiter_bytes():
                size += len(chunk)
                if size > max_bytes:
                    if not allow_truncate:
                        raise ResponseTooLargeError(f"Response larger than {max_bytes} bytes")
                    keep = max_bytes - (size - len(chunk))
                    chunks.append(chunk[:keep])
                    truncated = True
                    break
                chunks.append(chunk)
        finally:
            await response.aclose()
            self._client.cookies.clear()

        return SafeResponse(
            url=target.url,
            status_code=response.status_code,
            headers=response.headers,
            content=b"".join(chunks),
            truncated=truncated,
            ip=ip,
        )


# --------------------------------------------------------------------------- TLS


@dataclass
class TlsHandshakeResult:
    ip: str
    protocol: str | None
    cipher: str | None
    der_cert: bytes | None
    chain_der: list[bytes]
    verified: bool
    error: str | None = None


def _tls_context(verify: bool, version: ssl.TLSVersion | None) -> ssl.SSLContext:
    if verify:
        ctx = ssl.create_default_context()
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if version is not None:
        ctx.minimum_version = version
        ctx.maximum_version = version
        if version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
            try:
                ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
            except ssl.SSLError:
                pass
    return ctx


async def tls_handshake(
    host: str,
    *,
    port: int = 443,
    verify: bool = True,
    version: ssl.TLSVersion | None = None,
    handshake_timeout: float = 8.0,
) -> TlsHandshakeResult:
    """Perform a TLS handshake against a validated public IP of ``host`` and close."""
    if port != 443:
        raise BlockedTargetError("port", "Only port 443 is allowed for TLS checks.")
    host = _to_ascii_host(host)
    ips = await resolve_and_validate(host)
    ip = ips[0]
    ctx = _tls_context(verify, version)
    writer = None
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx, server_hostname=host), timeout=handshake_timeout
        )
        sslobj = writer.get_extra_info("ssl_object")
        der = sslobj.getpeercert(binary_form=True) if sslobj else None
        chain: list[bytes] = []
        if sslobj is not None:
            getter = getattr(sslobj, "get_verified_chain", None) if verify else None
            getter = getter or getattr(sslobj, "get_unverified_chain", None)
            if getter:
                try:
                    chain = [c if isinstance(c, bytes) else c.public_bytes() for c in (getter() or [])]
                except Exception:  # noqa: BLE001 - chain retrieval is best effort
                    chain = []
        cipher = sslobj.cipher()[0] if sslobj and sslobj.cipher() else None
        return TlsHandshakeResult(
            ip=ip,
            protocol=sslobj.version() if sslobj else None,
            cipher=cipher,
            der_cert=der,
            chain_der=chain,
            verified=verify,
        )
    finally:
        if writer is not None:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=2)
            except Exception:  # noqa: BLE001, S110 - closing is best effort
                pass
