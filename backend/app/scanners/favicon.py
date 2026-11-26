"""Favicon fingerprint: the hash Shodan and FOFA index, for finding related hosts.

Downloads the favicon a browser would load (the <link rel="icon"> from the homepage, or
/favicon.ico) and computes Shodan's ``http.favicon.hash`` (MurmurHash3 of the base64 body).
Searching that hash shows other servers with the same icon, often the origin server behind a CDN,
staging copies or other assets of the same organisation. ReconLens only builds the search links;
it does not query Shodan or FOFA.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
from html.parser import HTMLParser
from urllib.parse import quote, urljoin, urlsplit

import httpx

from app.core.ssrf_guard import BlockedTargetError, ResponseTooLargeError
from app.models.finding import Severity
from app.scanners.base import HomepageUnavailableError, ScanContext, Scanner, ScannerResult, describe_error

MAX_BYTES = 200 * 1024


def murmur3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86 32-bit, returned as a signed int (same as Python's mmh3.hash)."""
    c1, c2, mask = 0xCC9E2D51, 0x1B873593, 0xFFFFFFFF
    h = seed & mask
    n = len(data) // 4 * 4
    for i in range(0, n, 4):
        k = int.from_bytes(data[i : i + 4], "little")
        k = (k * c1) & mask
        k = ((k << 15) | (k >> 17)) & mask
        k = (k * c2) & mask
        h ^= k
        h = ((h << 13) | (h >> 19)) & mask
        h = (h * 5 + 0xE6546B64) & mask
    tail = data[n:]
    k = 0
    if len(tail) >= 3:
        k ^= tail[2] << 16
    if len(tail) >= 2:
        k ^= tail[1] << 8
    if tail:
        k ^= tail[0]
        k = (k * c1) & mask
        k = ((k << 15) | (k >> 17)) & mask
        k = (k * c2) & mask
        h ^= k
    h ^= len(data)
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & mask
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & mask
    h ^= h >> 16
    return h - (1 << 32) if h & 0x80000000 else h


def shodan_favicon_hash(content: bytes) -> int:
    # Shodan hashes the MIME-style base64 (newline every 76 chars, trailing newline).
    return murmur3_32(base64.encodebytes(content))


class _IconParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.icons: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "link" or len(self.icons) >= 10:
            return
        a = {k.lower(): (v or "") for k, v in attrs}
        rel = a.get("rel", "").lower().split()
        if "icon" in rel and a.get("href") and not a["href"].startswith("data:"):
            self.icons.append(a["href"][:500])


def icon_candidates(html: str, page_url: str) -> list[str]:
    parser = _IconParser()
    with contextlib.suppress(Exception):  # malformed HTML: keep what was parsed
        parser.feed(html)
    urls = [urljoin(page_url, h) for h in parser.icons]
    default = urljoin(page_url, "/favicon.ico")
    out: list[str] = []
    for u in [*urls, default]:
        if urlsplit(u).scheme in ("http", "https") and u not in out:
            out.append(u)
    return out[:3]


def _looks_like_image(content: bytes, ctype: str) -> bool:
    head = content[:64].lstrip().lower()
    if head.startswith((b"<!doctype html", b"<html")) or "text/html" in ctype:
        return False  # soft-404 page
    return len(content) > 0


class FaviconScanner(Scanner):
    name = "favicon"
    label = "Favicon fingerprint"
    category = "Attack surface"
    timeout = 25.0

    async def run(self, ctx: ScanContext) -> ScannerResult:
        try:
            page = await ctx.homepage()
            candidates = icon_candidates(page.text, page.url)
        except HomepageUnavailableError:
            candidates = [f"https://{ctx.domain}/favicon.ico"]

        errors: list[str] = []
        for url in candidates:
            try:
                resp = await ctx.client.get(
                    url, headers={"Accept": "image/*,*/*;q=0.8"}, max_bytes=MAX_BYTES, timeout=10.0
                )
            except (httpx.HTTPError, ResponseTooLargeError, BlockedTargetError, TimeoutError) as exc:
                errors.append(f"{url}: {describe_error(exc)}")
                continue
            ctype = resp.headers.get("content-type", "")
            if resp.status_code != 200 or not _looks_like_image(resp.content, ctype):
                errors.append(f"{url}: HTTP {resp.status_code}")
                continue
            return self._found(resp.url, resp.content, ctype)

        return ScannerResult(data={"found": False, "message": "; ".join(errors)[:500] or "No favicon found."})

    def _found(self, url: str, content: bytes, ctype: str) -> ScannerResult:
        mmh3 = shodan_favicon_hash(content)
        shodan_q = f"http.favicon.hash:{mmh3}"
        fofa_q = f'icon_hash="{mmh3}"'
        data = {
            "found": True,
            "url": url,
            "bytes": len(content),
            "content_type": ctype.split(";")[0].strip() or None,
            "mmh3": mmh3,
            "md5": hashlib.md5(content, usedforsecurity=False).hexdigest(),
            "sha256": hashlib.sha256(content).hexdigest(),
            "searches": [
                {
                    "engine": "Shodan",
                    "query": shodan_q,
                    "url": f"https://www.shodan.io/search?query={quote(shodan_q)}",
                },
                {
                    "engine": "FOFA",
                    "query": fofa_q,
                    "url": "https://en.fofa.info/result?qbase64="
                    + quote(base64.b64encode(fofa_q.encode()).decode()),
                },
                {
                    "engine": "ZoomEye",
                    "query": f'iconhash:"{mmh3}"',
                    "url": f"https://www.zoomeye.ai/searchResult?q={quote(f'iconhash:{mmh3}')}",
                },
            ],
        }
        result = ScannerResult(data=data)
        result.findings.append(
            self.finding(
                "hash",
                f"Favicon hash {mmh3}: search it to find related hosts",
                Severity.INFO,
                evidence=f"{url} ({len(content)} bytes). Shodan: {shodan_q}",
                recommendation=(
                    "Search the hash to find servers that serve the same icon. If the origin server behind "
                    "your CDN shows up, restrict it to accept traffic only from the CDN."
                ),
                references=[data["searches"][0]["url"]],
            )
        )
        return result
