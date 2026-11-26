"""Passive GET/POST endpoint discovery: homepage <form>s and Wayback Machine archived URLs.

Discovered endpoints are only listed. They are NEVER requested.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlsplit

import httpx

from app.core.cache import api_cache_get, api_cache_set
from app.models.finding import Severity
from app.scanners.base import HomepageUnavailableError, ScanContext, Scanner, ScannerResult, describe_error

CDX_URL = "https://web.archive.org/cdx/search/cdx"
CDX_LIMIT = 1500
MAX_PATHS = 300
MAX_PARAMS = 200
MAX_FORMS = 20

SENSITIVE_RE = re.compile(
    r"(\.env\b|\.git\b|\.svn\b|\.bak\b|\.old\b|\.sql\b|\.zip\b|\.tar\b|\.gz\b|\.config\b|\.ini\b|\.log\b|"
    r"backup|dump|wp-config|config\.php|phpinfo|\.htpasswd|\.ds_store|id_rsa)",
    re.IGNORECASE,
)
INTERESTING_RE = re.compile(
    r"(admin|login|signin|auth|oauth|sso|api|graphql|upload|debug|console|test|staging|internal|"
    r"swagger|openapi|actuator|metrics|reset|token|callback|redirect|export|import)",
    re.IGNORECASE,
)
# Parameter names grouped by the bug class testers usually check them for. Hints only:
# ReconLens never sends requests with these parameters.
PARAM_CLASSES: tuple[tuple[str, str, frozenset[str]], ...] = (
    (
        "redirect",
        "Open redirect / SSRF",
        frozenset(
            "url uri redirect redirect_uri redirect_url redirecturl return returnurl return_url returnto return_to "
            "next goto dest destination continue target link out callback forward rurl u to image_url feed "
            "host domain site proxy".split()
        ),
    ),
    (
        "file",
        "File inclusion / path traversal",
        frozenset(
            "file filename path filepath page include inc template tpl doc document folder dir download load "
            "read view layout module conf config lang locale".split()
        ),
    ),
    (
        "idor",
        "IDOR / access control",
        frozenset(
            "id uid user userid user_id account accountid account_id order orderid order_id invoice no number "
            "pid profile profile_id customer customer_id member memberid doc_id report_id key".split()
        ),
    ),
    (
        "injection",
        "SQL injection / search input",
        frozenset(
            "q query search s keyword keywords filter sort sortby sort_by order_by orderby category cat type where".split()
        ),
    ),
    (
        "xss",
        "Reflected XSS candidates",
        frozenset("message msg comment name title text content error err alert callback jsonp html".split()),
    ),
    (
        "command",
        "Command injection",
        frozenset("cmd exec command execute ping ip run shell process daemon".split()),
    ),
    (
        "debug",
        "Debug / feature flags",
        frozenset("debug test dev admin preview mode env verbose trace beta internal".split()),
    ),
    (
        "auth",
        "Tokens & secrets in URLs",
        frozenset(
            "token access_token auth key api_key apikey secret password pass pwd session sessionid sid code "
            "state jwt signature sig".split()
        ),
    ),
)


def classify_parameters(params: list[str]) -> list[dict[str, object]]:
    out = []
    lowered = {p: p.lower().replace("-", "_") for p in params}
    for key, label, names in PARAM_CLASSES:
        hits = sorted(p for p, low in lowered.items() if low in names)
        if hits:
            out.append({"class": key, "label": label, "params": hits[:50]})
    return out


_PARAM_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_\-\[\].]{0,59}$")
_STATIC_EXT = re.compile(
    r"\.(png|jpe?g|gif|svg|webp|ico|css|woff2?|ttf|eot|mp4|webm|mp3|avif)$", re.IGNORECASE
)


class _FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[dict[str, Any]] = []
        self._current: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._current = {
                "method": (a.get("method") or "GET").upper()[:10],
                "action": a.get("action", "")[:500],
                "inputs": [],
            }
            self.forms.append(self._current)
        elif tag in ("input", "select", "textarea", "button") and self._current is not None:
            name = a.get("name")
            if name and len(self._current["inputs"]) < 40:
                itype = a.get("type", "text" if tag == "input" else tag).lower()[:20]
                self._current["inputs"].append({"name": name[:100], "type": itype})

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._current = None


def parse_forms(html: str, page_url: str) -> list[dict[str, Any]]:
    parser = _FormParser()
    try:
        parser.feed(html[:1_000_000])
        parser.close()
    except Exception:  # noqa: BLE001, S110 - partial results are fine
        pass
    page_https = page_url.startswith("https://")
    out = []
    for form in parser.forms[:MAX_FORMS]:
        action = urljoin(page_url, form["action"]) if form["action"] else page_url
        if not action.lower().startswith(("http://", "https://")):
            action = page_url
        out.append(
            {
                "method": form["method"],
                "action": action[:500],
                "inputs": form["inputs"],
                "has_password": any(i["type"] == "password" for i in form["inputs"]),
                "insecure_action": page_https and action.lower().startswith("http://"),
            }
        )
    return out


def analyze_archive(urls: list[str], domain: str) -> dict[str, Any]:
    paths: dict[str, None] = {}
    params: dict[str, None] = {}
    interesting: list[dict[str, str]] = []
    seen_interesting: set[str] = set()
    for u in urls:
        try:
            parts = urlsplit(u if "://" in u else "http://" + u)
        except ValueError:
            continue
        host = (parts.hostname or "").lower()
        if host != domain and not host.endswith("." + domain):
            continue
        path = parts.path or "/"
        if _STATIC_EXT.search(path):
            continue
        for name, _ in parse_qsl(parts.query, keep_blank_values=True):
            if _PARAM_RE.match(name):
                params[name] = None
        key = path if host == domain else f"{host}{path}"
        paths[key[:300]] = None
        if key in seen_interesting:
            continue
        if SENSITIVE_RE.search(path):
            interesting.append({"path": key[:300], "reason": "sensitive-looking file or backup"})
            seen_interesting.add(key)
        elif INTERESTING_RE.search(path):
            interesting.append({"path": key[:300], "reason": "admin, auth, API or debug surface"})
            seen_interesting.add(key)
    return {
        "total_urls": len(urls),
        "paths": sorted(paths)[:MAX_PATHS],
        "parameters": sorted(params)[:MAX_PARAMS],
        "parameter_classes": classify_parameters(sorted(params)[:MAX_PARAMS]),
        "interesting": interesting[:100],
    }


class EndpointsScanner(Scanner):
    name = "endpoints"
    label = "Endpoints (forms & Wayback Machine)"
    category = "Attack surface"
    timeout = 60.0

    async def _wayback(self, ctx: ScanContext) -> dict[str, Any]:
        cache_key = f"wayback:{ctx.domain}"
        cached = await api_cache_get(ctx.db, cache_key)
        if cached is not None:
            return cached
        try:
            resp = await ctx.client.get(
                CDX_URL,
                params={
                    "url": f"{ctx.domain}/*",
                    "output": "json",
                    "fl": "original",
                    "collapse": "urlkey",
                    "limit": str(CDX_LIMIT),
                },
                max_bytes=4 * 1024 * 1024,
                timeout=httpx.Timeout(connect=10.0, read=40.0, write=10.0, pool=5.0),
            )
        except Exception as exc:  # noqa: BLE001 - the archive is often slow
            return {
                "available": False,
                "message": f"Wayback Machine unavailable ({describe_error(exc)}).",
                "total_urls": 0,
                "paths": [],
                "parameters": [],
                "interesting": [],
            }
        if resp.status_code != 200:
            return {
                "available": False,
                "message": f"Wayback Machine returned HTTP {resp.status_code}.",
                "total_urls": 0,
                "paths": [],
                "parameters": [],
                "interesting": [],
            }
        try:
            rows = resp.json() if resp.content.strip() else []
        except ValueError:
            rows = []
        urls = [r[0] for r in rows[1:] if isinstance(r, list) and r and isinstance(r[0], str)]
        data = {"available": True, **analyze_archive(urls, ctx.domain)}
        await api_cache_set(ctx.db, cache_key, data)
        return data

    async def run(self, ctx: ScanContext) -> ScannerResult:
        forms: list[dict[str, Any]] = []
        homepage_error = None
        try:
            resp = await ctx.homepage()
            if "html" in resp.headers.get("content-type", "html").lower():
                forms = parse_forms(resp.text, resp.url)
        except HomepageUnavailableError as exc:
            homepage_error = str(exc)

        wayback = await self._wayback(ctx)
        result = ScannerResult(data={"forms": forms, "wayback": wayback, "homepage_error": homepage_error})
        f = result.findings

        insecure = [fm for fm in forms if fm["insecure_action"]]
        if insecure:
            f.append(
                self.finding(
                    "insecure_form",
                    "Form submits data over plain HTTP",
                    Severity.HIGH if any(fm["has_password"] for fm in insecure) else Severity.MEDIUM,
                    evidence="; ".join(f"{fm['method']} {fm['action']}" for fm in insecure[:5]),
                    recommendation="Point form actions at HTTPS URLs so submitted data is encrypted.",
                )
            )
        login_forms = [fm for fm in forms if fm["has_password"]]
        if login_forms:
            f.append(
                self.finding(
                    "login_form",
                    "Login form on the homepage",
                    Severity.INFO,
                    evidence="; ".join(f"{fm['method']} {fm['action']}" for fm in login_forms[:3]),
                    recommendation="Make sure login is rate-limited and protected by MFA where possible.",
                )
            )
        sensitive = [i for i in wayback.get("interesting", []) if i["reason"].startswith("sensitive")]
        surfaces = [i for i in wayback.get("interesting", []) if not i["reason"].startswith("sensitive")]
        if sensitive:
            f.append(
                self.finding(
                    "archived_sensitive",
                    "Archived URLs reference sensitive-looking files (not verified)",
                    Severity.LOW,
                    evidence=", ".join(i["path"] for i in sensitive[:10]),
                    recommendation=(
                        "ReconLens did not request these URLs. Check that none of them are still reachable, "
                        "and remove backups, config files and VCS folders from the web root."
                    ),
                )
            )
        if surfaces:
            f.append(
                self.finding(
                    "archived_surfaces",
                    "Archived URLs reveal admin, auth or API endpoints",
                    Severity.INFO,
                    evidence=", ".join(i["path"] for i in surfaces[:10]),
                    recommendation="Review these endpoints for access control. They are known to the public archive.",
                )
            )
        if wayback.get("parameters"):
            f.append(
                self.finding(
                    "archived_parameters",
                    f"{len(wayback['parameters'])} GET parameter names found in archived URLs",
                    Severity.INFO,
                    evidence=", ".join(wayback["parameters"][:20]),
                    recommendation="Parameters are input points. Make sure each is validated server-side.",
                )
            )
        classes = {c["class"]: c for c in wayback.get("parameter_classes") or []}
        if "auth" in classes:
            f.append(
                self.finding(
                    "archived_secrets_in_urls",
                    "Archived URLs carry tokens or credentials as parameters",
                    Severity.LOW,
                    evidence="Parameters: " + ", ".join(classes["auth"]["params"][:15]),
                    recommendation=(
                        "Tokens in URLs end up in logs, browser history and public archives like this one. "
                        "Move them to headers or POST bodies and rotate any that were exposed."
                    ),
                )
            )
        if "redirect" in classes:
            f.append(
                self.finding(
                    "archived_redirect_params",
                    "Archived URLs use redirect-style parameters",
                    Severity.INFO,
                    evidence="Parameters: " + ", ".join(classes["redirect"]["params"][:15]),
                    recommendation=(
                        "Parameters like these are common open-redirect and SSRF entry points. Validate them "
                        "against an allowlist of destinations."
                    ),
                )
            )
        return result
