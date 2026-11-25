import httpx
import respx

from app.scanners.endpoints import EndpointsScanner, analyze_archive, parse_forms

IP = "93.184.216.34"
WB_IP = "207.241.224.2"

HTML = """<html><body>
<form action="/search" method="get"><input name="q" type="search"></form>
<form action="http://example.com/login" method="POST">
  <input name="user"><input name="pass" type="password"><button name="go">Go</button>
</form>
</body></html>"""


def test_parse_forms():
    forms = parse_forms(HTML, "https://example.com/")
    assert forms[0]["method"] == "GET"
    assert forms[0]["action"] == "https://example.com/search"
    assert forms[1]["method"] == "POST"
    assert forms[1]["has_password"] is True
    assert forms[1]["insecure_action"] is True
    assert {"name": "pass", "type": "password"} in forms[1]["inputs"]


def test_analyze_archive():
    data = analyze_archive(
        [
            "http://example.com/admin/login.php?next=/home",
            "https://example.com/.env",
            "https://example.com/static/logo.png",
            "https://api.example.com/v1/users?id=3&token=x",
            "https://other.org/admin",
        ],
        "example.com",
    )
    assert "/admin/login.php" in data["paths"]
    assert "/static/logo.png" not in data["paths"]
    assert "api.example.com/v1/users" in data["paths"]
    assert not any("other.org" in p for p in data["paths"])
    assert data["parameters"] == ["id", "next", "token"]
    reasons = {i["path"]: i["reason"] for i in data["interesting"]}
    assert reasons["/.env"].startswith("sensitive")
    assert "/admin/login.php" in reasons


@respx.mock
async def test_endpoints_scanner_never_requests_discovered_urls(ctx, public_dns):
    public_dns["web.archive.org"] = [WB_IP]
    respx.get(f"https://{IP}/").mock(
        return_value=httpx.Response(200, text=HTML, headers={"Content-Type": "text/html"})
    )
    cdx = respx.get(url__startswith=f"https://{WB_IP}/cdx/search/cdx").mock(
        return_value=httpx.Response(
            200, json=[["original"], ["https://example.com/backup.zip"], ["https://example.com/api/v2?key=1"]]
        )
    )
    res = await EndpointsScanner().run(ctx)
    assert cdx.calls.last.request.url.params["url"] == "example.com/*"
    # Only the homepage and the CDX API were contacted, never the discovered paths.
    assert len(respx.calls) == 2
    ids = {f.id: f.severity for f in res.findings}
    assert ids["endpoints.insecure_form"] == "high"
    assert ids["endpoints.archived_sensitive"] == "low"
    assert res.data["wayback"]["parameters"] == ["key"]


@respx.mock
async def test_wayback_unavailable(ctx, public_dns):
    public_dns["web.archive.org"] = [WB_IP]
    respx.get(f"https://{IP}/").mock(return_value=httpx.Response(200, text="<html></html>"))
    respx.get(url__startswith=f"https://{WB_IP}/").mock(side_effect=httpx.ReadTimeout("slow"))
    res = await EndpointsScanner().run(ctx)
    assert res.data["wayback"]["available"] is False
