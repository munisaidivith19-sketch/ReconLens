import httpx
import respx

from app.scanners.security_headers import SecurityHeadersScanner, detect_waf, parse_set_cookie

IP = "93.184.216.34"


@respx.mock
async def test_missing_headers_and_cookie_flags(ctx):
    respx.get(f"https://{IP}/").mock(
        return_value=httpx.Response(
            200,
            text="<html></html>",
            headers=[
                ("Server", "Apache/2.4.49 (Unix)"),
                ("X-Powered-By", "PHP/7.4.3"),
                ("Set-Cookie", "PHPSESSID=abc; path=/"),
                ("Set-Cookie", "pref=1; Secure; HttpOnly; SameSite=Lax"),
            ],
        )
    )
    respx.get(f"http://{IP}/").mock(return_value=httpx.Response(200, text="plain"))
    res = await SecurityHeadersScanner().run(ctx)
    ids = {f.id: f.severity for f in res.findings}
    assert ids["security_headers.missing_hsts"] == "medium"
    assert ids["security_headers.missing_csp"] == "medium"
    assert "security_headers.missing_clickjacking" in ids
    assert "security_headers.http_no_redirect" in ids
    assert "security_headers.version_disclosure" in ids
    assert "security_headers.cookie_no_secure" in ids
    assert res.data["http_redirects_to_https"] is False
    phpsess = next(c for c in res.data["cookies"] if c["name"] == "PHPSESSID")
    assert phpsess == {"name": "PHPSESSID", "secure": False, "httponly": False, "samesite": None}


@respx.mock
async def test_well_configured_site(ctx):
    respx.get(f"https://{IP}/").mock(
        return_value=httpx.Response(
            200,
            headers={
                "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
                "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "camera=()",
                "Server": "cloudflare",
                "CF-RAY": "abc-LHR",
            },
        )
    )
    respx.get(f"http://{IP}/").mock(
        return_value=httpx.Response(301, headers={"Location": "https://example.com/"})
    )
    res = await SecurityHeadersScanner().run(ctx)
    assert res.findings == []
    assert res.data["waf_cdn"] == ["Cloudflare"]
    assert res.data["http_redirects_to_https"] is True


@respx.mock
async def test_weak_csp_flagged(ctx):
    respx.get(f"https://{IP}/").mock(
        return_value=httpx.Response(
            200, headers={"Content-Security-Policy": "script-src 'self' 'unsafe-inline' 'unsafe-eval'"}
        )
    )
    respx.get(f"http://{IP}/").mock(side_effect=httpx.ConnectError("closed"))
    res = await SecurityHeadersScanner().run(ctx)
    assert any(f.id == "security_headers.weak_csp" for f in res.findings)
    assert res.data["http_redirects_to_https"] is None


def test_parse_set_cookie_samesite():
    c = parse_set_cookie("sid=1; Path=/; Secure; HttpOnly; SameSite=strict")
    assert c["samesite"] == "Strict" and c["secure"] and c["httponly"]


def test_detect_waf_from_cookie():
    assert detect_waf({}, ["incap_ses_123"]) == ["Imperva Incapsula"]
