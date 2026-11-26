"""Client-side JavaScript analysis and CDN origin hints."""

import httpx
import respx

from app.scanners.client_side import ClientSideScanner, mask
from app.scanners.origin_hints import OriginHintsScanner

TARGET_IP = "93.184.216.34"

FAKE_AWS = "AKIA" + "ABCDEFGHIJKLMNOP"
FAKE_GOOGLE = "AIza" + "S" * 35

HTML = f"""<html><head>
<script src="/static/app.js"></script>
<script src="https://cdn.example.com/vendor.js"></script>
<script src="https://www.googletagmanager.com/gtag/js"></script>
</head><body><script>var k = "{FAKE_GOOGLE}";</script></body></html>"""

APP_JS = f"""
const cfg = {{ key: "{FAKE_AWS}", bucket: "https://assets-prod.s3.amazonaws.com/x.png" }};
fetch("/api/v2/users/{{id}}"); fetch('/graphql'); fetch("/static/logo.png");
const db = "https://my-app-123.firebaseio.com";
const api = "https://internal-api.example.com/v1";
//# sourceMappingURL=app.js.map
"""


@respx.mock
async def test_client_side_finds_secrets_buckets_endpoints(ctx):
    respx.get(f"https://{TARGET_IP}/").mock(
        return_value=httpx.Response(200, text=HTML, headers={"content-type": "text/html"})
    )
    respx.get(f"https://{TARGET_IP}/static/app.js").mock(return_value=httpx.Response(200, text=APP_JS))
    respx.get(f"https://{TARGET_IP}/vendor.js").mock(return_value=httpx.Response(200, text="var x=1;"))
    # Third-party scripts are never requested.
    gtm = respx.get(url__regex=r".*/gtag/js").mock(return_value=httpx.Response(200))

    res = await ClientSideScanner().run(ctx)
    d = res.data
    assert d["status"] == "ok"
    assert d["scripts_found"] == 2
    assert d["scripts_external"] == 1
    assert not gtm.called

    types = {s["type"] for s in d["secrets"]}
    assert types == {"aws_access_key", "google_api_key"}
    # Values are masked; the full key is never stored.
    stored = str(d)
    assert FAKE_AWS not in stored and FAKE_GOOGLE not in stored

    assert {(b["provider"], b["name"]) for b in d["buckets"]} == {
        ("AWS S3", "assets-prod"),
        ("Firebase Realtime DB", "my-app-123"),
    }
    paths = {e["path"] for e in d["endpoints"]}
    assert {"/api/v2/users/{id}", "/graphql"} <= paths
    assert "/static/logo.png" not in paths
    assert "internal-api.example.com" in d["in_scope_hosts"]
    assert d["source_maps"][0]["url"].endswith("/static/app.js.map")

    ids = {f.id for f in res.findings}
    assert ids == {
        "client_side.secret.aws_access_key",
        "client_side.secret.google_api_key",
        "client_side.cloud_buckets",
        "client_side.source_maps",
    }


@respx.mock
async def test_client_side_homepage_unavailable(ctx):
    respx.get(url__startswith="https://").mock(side_effect=httpx.ConnectError("down"))
    respx.get(url__startswith="http://").mock(side_effect=httpx.ConnectError("down"))
    res = await ClientSideScanner().run(ctx)
    assert res.data["status"] == "unavailable"
    assert res.findings == []


def test_mask():
    assert mask("AKIAABCDEFGHIJKLMNOP") == "AKIAAB…MNOP"
    assert mask("short") == "sh…"


async def test_origin_hints_behind_cdn(ctx):
    ctx.results["dns_records"] = {"records": {"A": ["104.16.1.1"], "AAAA": []}, "ptr": []}
    ctx.results["security_headers"] = {"waf_cdn": ["Cloudflare"]}
    ctx.results["takeover"] = {
        "cnames": [
            {"name": "shop.example.com", "cname": "shops.myshopify.com"},
            {"name": "cdn.example.com", "cname": "x.cloudfront.net"},
        ],
        "resolved": {
            "www.example.com": ["104.16.1.1"],
            "mail.example.com": ["203.0.113.10"],
            "cdn.example.com": ["13.32.0.1"],
            "shop.example.com": ["23.227.38.1"],
        },
    }
    res = await OriginHintsScanner().run(ctx)
    d = res.data
    assert d["behind_cdn"] is True
    names = [c["name"] for c in d["candidates"]]
    assert names == ["mail.example.com", "shop.example.com"]  # origin-like names first, CDN CNAMEs skipped
    assert d["candidates"][0]["hint"] == "mail"
    assert d["unique_ips"] == 4
    assert [f.id for f in res.findings] == ["origin_hints.outside_cdn"]


async def test_origin_hints_no_cdn_no_finding(ctx):
    ctx.results["dns_records"] = {"records": {"A": ["198.51.100.1"]}}
    ctx.results["takeover"] = {"resolved": {"dev.example.com": ["198.51.100.9"]}}
    res = await OriginHintsScanner().run(ctx)
    assert res.data["behind_cdn"] is False
    assert res.data["candidates"][0]["same_network"] is True
    assert res.findings == []
