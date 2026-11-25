"""HTTP security headers, cookie flags, WAF/CDN markers and version disclosure (one homepage GET)."""

import re

from app.core.ssrf_guard import BlockedTargetError
from app.models.finding import Severity
from app.scanners.base import ScanContext, Scanner, ScannerResult

MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/"
CHECKED_HEADERS = (
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
)
DISCLOSURE_HEADERS = (
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "via",
)

# (name, header name or None for any, regex on header value / name)
WAF_MARKERS: list[tuple[str, str, str]] = [
    ("Cloudflare", "cf-ray", ""),
    ("Cloudflare", "server", r"cloudflare"),
    ("Akamai", "server", r"akamai"),
    ("Akamai", "x-akamai-transformed", ""),
    ("Amazon CloudFront", "x-amz-cf-id", ""),
    ("Amazon CloudFront", "via", r"cloudfront"),
    ("Fastly", "x-served-by", r"cache-"),
    ("Fastly", "x-fastly-request-id", ""),
    ("Sucuri", "x-sucuri-id", ""),
    ("Sucuri", "server", r"sucuri"),
    ("Imperva Incapsula", "x-iinfo", ""),
    ("Imperva Incapsula", "x-cdn", r"incapsula"),
    ("Azure Front Door", "x-azure-ref", ""),
    ("Google Cloud", "via", r"1\.1 google"),
    ("Vercel", "x-vercel-id", ""),
    ("Netlify", "x-nf-request-id", ""),
    ("Varnish", "x-varnish", ""),
    ("F5 BIG-IP", "server", r"big-?ip"),
    ("StackPath", "x-sp-url", ""),
    ("Bunny CDN", "server", r"bunnycdn"),
]
WAF_COOKIES = {"__cf_bm": "Cloudflare", "incap_ses": "Imperva Incapsula", "visid_incap": "Imperva Incapsula"}
_VERSION_RE = re.compile(r"\d+\.\d+")


def parse_set_cookie(header: str) -> dict:
    name = header.split("=", 1)[0].strip()
    attrs = [a.strip().lower() for a in header.split(";")[1:]]
    samesite = None
    for a in attrs:
        if a.startswith("samesite="):
            samesite = a.split("=", 1)[1].strip().capitalize()
    return {
        "name": name[:100],
        "secure": "secure" in attrs,
        "httponly": "httponly" in attrs,
        "samesite": samesite,
    }


def detect_waf(headers: dict[str, str], cookie_names: list[str]) -> list[str]:
    found: list[str] = []
    for name, header, pattern in WAF_MARKERS:
        value = headers.get(header)
        if value is None:
            continue
        if not pattern or re.search(pattern, value, re.IGNORECASE):
            found.append(name)
    for cookie in cookie_names:
        for prefix, name in WAF_COOKIES.items():
            if cookie.lower().startswith(prefix):
                found.append(name)
    return sorted(set(found))


class SecurityHeadersScanner(Scanner):
    name = "security_headers"
    label = "Security headers & cookies"
    category = "HTTP security"
    timeout = 30.0

    async def run(self, ctx: ScanContext) -> ScannerResult:
        resp = await ctx.homepage()
        headers = {k.lower(): v for k, v in resp.headers.items()}
        is_https = resp.url.startswith("https://")
        result = ScannerResult()
        f = result.findings

        # Does plain HTTP redirect to HTTPS? (One extra request a browser would also make.)
        http_redirects = None
        if is_https:
            try:
                plain = await ctx.client.get(
                    f"http://{ctx.domain}/", follow_redirects=False, max_bytes=64 * 1024, allow_truncate=True
                )
                loc = plain.headers.get("location", "")
                http_redirects = plain.status_code in (301, 302, 307, 308) and loc.lower().startswith(
                    "https://"
                )
            except BlockedTargetError:
                http_redirects = None
            except Exception:  # noqa: BLE001 - port 80 closed is fine
                http_redirects = None

        present = {h: headers[h][:500] for h in CHECKED_HEADERS if h in headers}
        csp = headers.get("content-security-policy", "")
        xfo = headers.get("x-frame-options")
        missing: list[str] = []

        if not is_https:
            f.append(
                self.finding(
                    "no_https",
                    "Site is served over plain HTTP",
                    Severity.HIGH,
                    evidence=f"Homepage loaded from {resp.url}.",
                    recommendation="Serve the site only over HTTPS and redirect all HTTP requests to HTTPS.",
                )
            )
        elif http_redirects is False:
            f.append(
                self.finding(
                    "http_no_redirect",
                    "HTTP does not redirect to HTTPS",
                    Severity.MEDIUM,
                    evidence=f"http://{ctx.domain}/ did not answer with a redirect to https://.",
                    recommendation="Redirect all plain-HTTP requests to HTTPS with a 301.",
                )
            )

        if "strict-transport-security" not in headers:
            missing.append("Strict-Transport-Security")
            if is_https:
                f.append(
                    self.finding(
                        "missing_hsts",
                        "HSTS header missing",
                        Severity.MEDIUM,
                        evidence="No Strict-Transport-Security header on the HTTPS response.",
                        recommendation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
                        references=[MDN + "Strict-Transport-Security"],
                    )
                )
        else:
            m = re.search(r"max-age=(\d+)", headers["strict-transport-security"])
            if not m or int(m.group(1)) < 15552000:
                f.append(
                    self.finding(
                        "weak_hsts",
                        "HSTS max-age is shorter than 180 days",
                        Severity.LOW,
                        evidence=f"Strict-Transport-Security: {headers['strict-transport-security'][:200]}",
                        recommendation="Use max-age of at least 15552000 (180 days); 31536000 is common.",
                    )
                )

        if not csp:
            missing.append("Content-Security-Policy")
            f.append(
                self.finding(
                    "missing_csp",
                    "Content-Security-Policy header missing",
                    Severity.MEDIUM,
                    evidence="No Content-Security-Policy header.",
                    recommendation="Define a CSP that restricts script sources; start in Report-Only mode.",
                    references=[MDN + "Content-Security-Policy"],
                )
            )
        else:
            weak = []
            if "'unsafe-inline'" in csp and "nonce-" not in csp and "strict-dynamic" not in csp:
                weak.append("'unsafe-inline'")
            if "'unsafe-eval'" in csp:
                weak.append("'unsafe-eval'")
            if re.search(r"(script-src|default-src)[^;]*\s\*(\s|;|$)", csp):
                weak.append("wildcard source")
            if weak:
                f.append(
                    self.finding(
                        "weak_csp",
                        "Content-Security-Policy allows unsafe sources",
                        Severity.LOW,
                        evidence=f"CSP contains {', '.join(weak)}.",
                        recommendation="Remove unsafe-inline/unsafe-eval and wildcards; use nonces or hashes.",
                    )
                )

        if not xfo and "frame-ancestors" not in csp:
            missing.append("X-Frame-Options / frame-ancestors")
            f.append(
                self.finding(
                    "missing_clickjacking",
                    "No clickjacking protection",
                    Severity.LOW,
                    evidence="Neither X-Frame-Options nor CSP frame-ancestors is set.",
                    recommendation="Add 'Content-Security-Policy: frame-ancestors 'self'' or 'X-Frame-Options: DENY'.",
                )
            )
        if headers.get("x-content-type-options", "").lower() != "nosniff":
            missing.append("X-Content-Type-Options")
            f.append(
                self.finding(
                    "missing_xcto",
                    "X-Content-Type-Options: nosniff missing",
                    Severity.LOW,
                    evidence="Browsers may MIME-sniff responses.",
                    recommendation="Add 'X-Content-Type-Options: nosniff'.",
                )
            )
        if "referrer-policy" not in headers:
            missing.append("Referrer-Policy")
            f.append(
                self.finding(
                    "missing_referrer_policy",
                    "Referrer-Policy header missing",
                    Severity.INFO,
                    evidence="Browser defaults apply.",
                    recommendation="Add 'Referrer-Policy: strict-origin-when-cross-origin'.",
                )
            )
        if "permissions-policy" not in headers:
            missing.append("Permissions-Policy")
            f.append(
                self.finding(
                    "missing_permissions_policy",
                    "Permissions-Policy header missing",
                    Severity.INFO,
                    evidence="Powerful browser features are not explicitly restricted.",
                    recommendation="Add a Permissions-Policy disabling features you don't use (camera, geolocation…).",
                )
            )

        # Cookies
        cookies = [parse_set_cookie(h) for h in resp.set_cookie_headers][:30]
        no_secure = [c["name"] for c in cookies if not c["secure"]] if is_https else []
        no_httponly = [c["name"] for c in cookies if not c["httponly"]]
        no_samesite = [c["name"] for c in cookies if not c["samesite"]]
        if no_secure:
            f.append(
                self.finding(
                    "cookie_no_secure",
                    "Cookies set without the Secure flag",
                    Severity.LOW,
                    evidence="Cookies: " + ", ".join(no_secure[:10]),
                    recommendation="Set the Secure flag so cookies are never sent over plain HTTP.",
                )
            )
        if no_httponly:
            f.append(
                self.finding(
                    "cookie_no_httponly",
                    "Cookies set without the HttpOnly flag",
                    Severity.LOW,
                    evidence="Cookies: " + ", ".join(no_httponly[:10]),
                    recommendation="Set HttpOnly on session cookies so scripts cannot read them.",
                )
            )
        if no_samesite:
            f.append(
                self.finding(
                    "cookie_no_samesite",
                    "Cookies set without a SameSite attribute",
                    Severity.INFO,
                    evidence="Cookies: " + ", ".join(no_samesite[:10]),
                    recommendation="Set SameSite=Lax (or Strict) to limit cross-site request forgery.",
                )
            )

        # Disclosure
        disclosure = {h: headers[h][:200] for h in DISCLOSURE_HEADERS if h in headers}
        versioned = {h: v for h, v in disclosure.items() if _VERSION_RE.search(v) and h != "via"}
        if versioned:
            f.append(
                self.finding(
                    "version_disclosure",
                    "Server software versions disclosed in headers",
                    Severity.LOW,
                    evidence="; ".join(f"{k}: {v}" for k, v in versioned.items()),
                    recommendation="Remove version numbers from Server / X-Powered-By headers.",
                )
            )

        waf = detect_waf(headers, [c["name"] for c in cookies])
        result.data = {
            "url": resp.url,
            "final_url": resp.redirects[-1] if resp.redirects else resp.url,
            "status_code": resp.status_code,
            "https": is_https,
            "http_redirects_to_https": http_redirects,
            "headers_present": present,
            "missing": missing,
            "cookies": cookies,
            "waf_cdn": waf,
            "disclosure": disclosure,
        }
        return result
