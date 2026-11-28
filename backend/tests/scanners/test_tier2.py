"""IP ownership, blocklists, HSTS preload and WordPress plugin versions."""

import httpx
import pytest
import respx

from app.config import get_settings
from app.scanners import cve_lookup
from app.scanners.blocklists import BlocklistsScanner, interpret_dbl, summarize_urlhaus
from app.scanners.hsts_preload import HstsPreloadScanner, eligibility_problems, parse_hsts
from app.scanners.ip_intel import IpIntelScanner, classify, cymru_origin_name, parse_as_name, parse_origin
from app.scanners.origin_hints import OriginHintsScanner
from app.scanners.wordpress import WordPressScanner, extract_components, wp_cpe
from app.services import threat_intel

TARGET_IP = "93.184.216.34"
API_IP = "104.16.5.5"

# ---------------------------------------------------------------- IP ownership


def test_cymru_names_and_parsing():
    assert cymru_origin_name("93.184.216.34") == "34.216.184.93.origin.asn.cymru.com"
    v6 = cymru_origin_name("2606:4700::1")
    assert v6 and v6.endswith(".0.0.7.4.6.0.6.2.origin6.asn.cymru.com")
    assert cymru_origin_name("nope") is None
    assert parse_origin('"13335 | 104.16.0.0/13 | US | arin | 2014-03-28"') == {
        "asn": 13335,
        "prefix": "104.16.0.0/13",
        "country": "US",
    }
    assert parse_origin('"13335 209242 | 104.16.0.0/13 | US | arin |"')["asn"] == 13335
    assert parse_origin("garbage") is None
    assert parse_as_name('"13335 | US | arin | 2010-07-14 | CLOUDFLARENET - Cloudflare, Inc., US"') == (
        "CLOUDFLARENET - Cloudflare, Inc., US"
    )
    assert classify("CLOUDFLARENET - Cloudflare, Inc., US") == ("Cloudflare", "cdn")
    assert classify("AMAZON-02 - Amazon.com, Inc., US") == ("AWS", "cloud")
    assert classify("Some ISP") == (None, "other")
    assert classify(None) == (None, "unknown")


def _cymru(fake_dns, ip, asn, name):
    fake_dns[(cymru_origin_name(ip), "TXT")] = [f'"{asn} | {ip}/24 | US | arin | 2010-01-01"']
    fake_dns[(f"AS{asn}.asn.cymru.com", "TXT")] = [f'"{asn} | US | arin | 2010-01-01 | {name}"']


async def test_ip_intel_maps_providers_and_feeds_origin_hints(ctx, fake_dns):
    _cymru(fake_dns, "104.16.1.1", 13335, "CLOUDFLARENET - Cloudflare, Inc., US")
    _cymru(fake_dns, "151.101.1.1", 54113, "FASTLY - Fastly, Inc., US")
    _cymru(fake_dns, "5.6.7.8", 24940, "HETZNER-AS, DE")
    _cymru(fake_dns, "9.9.9.9", 16509, "AMAZON-02 - Amazon.com, Inc., US")
    ctx.results["dns_records"] = {"records": {"A": ["104.16.1.1"]}}
    ctx.results["takeover"] = {
        "resolved": {
            "cdn2.example.com": ["151.101.1.1"],
            "origin.example.com": ["5.6.7.8"],
            "s3.example.com": ["9.9.9.9"],
        },
        "cnames": [],
    }
    res = await IpIntelScanner().run(ctx)
    hosts = {h["ip"]: h for h in res.data["hosts"]}
    assert hosts["104.16.1.1"]["provider"] == "Cloudflare" and hosts["104.16.1.1"]["kind"] == "cdn"
    assert hosts["5.6.7.8"]["kind"] == "hosting" and hosts["5.6.7.8"]["asn"] == 24940
    assert res.data["main_provider"] == "Cloudflare" and res.data["asn_count"] == 4
    assert [f.id for f in res.findings] == ["ip_intel.spread"]

    # origin_hints: no waf header, but the IPs say Cloudflare; Fastly edge IPs are not origins.
    ctx.results["ip_intel"] = res.data
    ctx.results["security_headers"] = {"waf_cdn": []}
    oh = await OriginHintsScanner().run(ctx)
    assert oh.data["behind_cdn"] and "Cloudflare" in oh.data["cdn"]
    names = {c["name"]: c for c in oh.data["candidates"]}
    assert "cdn2.example.com" not in names
    assert names["origin.example.com"]["provider"] == "Hetzner"
    assert [f.id for f in oh.findings] == ["origin_hints.outside_cdn"]


# ---------------------------------------------------------------- blocklists


def test_interpret_dbl():
    assert interpret_dbl([])["status"] == "not_listed"
    assert interpret_dbl(["127.0.1.4"]) == {"status": "listed", "reasons": ["phishing domain"]}
    out = interpret_dbl(["127.255.255.254"])
    assert out["status"] == "unavailable" and "public DNS" in out["message"]


def test_summarize_urlhaus():
    assert summarize_urlhaus({"query_status": "no_results"})["status"] == "not_listed"
    assert summarize_urlhaus({"query_status": "invalid_host"})["status"] == "unavailable"
    out = summarize_urlhaus(
        {
            "query_status": "ok",
            "url_count": "2",
            "urls": [
                {"url": "http://example.com/a.exe", "url_status": "online", "threat": "malware_download"},
                {"url": "http://example.com/b.exe", "url_status": "offline", "threat": "malware_download"},
            ],
        }
    )
    assert out["status"] == "listed" and out["url_count"] == 2 and out["online"] == 1


async def test_blocklists_without_key_checks_spamhaus_only(ctx, fake_dns, monkeypatch):
    monkeypatch.setattr(get_settings(), "ABUSECH_AUTH_KEY", "")
    fake_dns[("example.com.dbl.spamhaus.org", "A")] = ["127.0.1.2"]
    res = await BlocklistsScanner().run(ctx)
    assert res.data["urlhaus"]["status"] == "skipped"
    assert [f.id for f in res.findings] == ["blocklists.spamhaus_listed"]
    assert res.findings[0].severity.value == "high"


@respx.mock
async def test_blocklists_urlhaus_with_key(ctx, fake_dns, public_dns, monkeypatch):
    monkeypatch.setattr(get_settings(), "ABUSECH_AUTH_KEY", "k")
    public_dns["urlhaus-api.abuse.ch"] = [API_IP]
    route = respx.post(f"https://{API_IP}/v1/host/").mock(
        return_value=httpx.Response(
            200,
            json={
                "query_status": "ok",
                "url_count": 1,
                "urls": [
                    {"url": "http://example.com/x.exe", "url_status": "online", "threat": "malware_download"}
                ],
            },
        )
    )
    res = await BlocklistsScanner().run(ctx)
    req = route.calls.last.request
    assert req.headers["Auth-Key"] == "k" and req.content == b"host=example.com"
    assert res.data["spamhaus_dbl"]["example.com"]["status"] == "not_listed"
    assert [f.id for f in res.findings] == ["blocklists.urlhaus_online"]
    await BlocklistsScanner().run(ctx)
    assert route.call_count == 1  # cached


# ---------------------------------------------------------------- HSTS preload


def test_parse_hsts_and_eligibility():
    good = parse_hsts("max-age=63072000; includeSubDomains; preload")
    assert good == {"present": True, "max_age": 63072000, "include_subdomains": True, "preload": True}
    assert eligibility_problems(good) == []
    weak = parse_hsts("max-age=300; preload")
    assert len(eligibility_problems(weak)) == 2
    assert eligibility_problems(parse_hsts(None)) == ["no Strict-Transport-Security header"]


@respx.mock
@pytest.mark.parametrize(
    ("status", "header", "expected"),
    [
        ("preloaded", "max-age=63072000; includeSubDomains; preload", []),
        ("unknown", "max-age=300; preload", ["hsts_preload.requested_ineligible"]),
        ("unknown", "max-age=31536000", ["hsts_preload.not_preloaded"]),
        ("pending", "max-age=63072000; includeSubDomains; preload", []),
    ],
)
async def test_hsts_preload_scanner(ctx, public_dns, status, header, expected):
    public_dns["hstspreload.org"] = [API_IP]
    respx.get(url__startswith=f"https://{API_IP}/api/v2/status").mock(
        return_value=httpx.Response(200, json={"name": "example.com", "status": status, "bulk": True})
    )
    ctx.results["security_headers"] = {
        "https": True,
        "headers_present": {"strict-transport-security": header},
    }
    res = await HstsPreloadScanner().run(ctx)
    assert [f.id for f in res.findings] == expected
    assert res.data["covered"] is (status == "preloaded")


# ---------------------------------------------------------------- WordPress

WP_HTML = """<html><head>
<link rel='stylesheet' href='https://example.com/wp-content/plugins/contact-form-7/includes/css/styles.css?ver=5.3.1' />
<script src='https://example.com/wp-content/plugins/elementor/assets/js/frontend.min.js?ver=6.5.2'></script>
<script src='https://example.com/wp-content/plugins/jetpack/x.js?ver=6.5.2'></script>
<script src='https://example.com/wp-content/plugins/cachebuster/x.js?ver=1700000000'></script>
<link href='https://example.com/wp-content/themes/astra/style.css?foo=1&#038;ver=4.1.0' rel='stylesheet'>
<img src='/wp-content/plugins/revslider/public/assets/img/x.png'>
</head></html>"""


def test_extract_components_skips_core_version_and_timestamps():
    comps = {c["slug"]: c for c in extract_components(WP_HTML, "6.5.2")}
    assert comps["contact-form-7"]["version"] == "5.3.1"
    assert comps["elementor"]["version"] is None  # same as core: WordPress default, not the plugin's
    assert comps["cachebuster"]["version"] is None
    assert comps["revslider"]["version"] is None and comps["revslider"]["type"] == "plugin"
    assert comps["astra"]["type"] == "theme"
    assert wp_cpe("contact-form-7", "5.3.1") == "cpe:2.3:a:*:contact_form_7:5.3.1:*:*:*:*:wordpress:*:*"


@respx.mock
async def test_wordpress_scanner_finds_plugin_cves(ctx, public_dns):
    public_dns["services.nvd.nist.gov"] = ["104.16.1.1"]
    public_dns["www.cisa.gov"] = ["104.16.1.2"]
    threat_intel.reset_memory()
    cve_lookup.nvd_limiter_anon.reset()
    cve_lookup.nvd_limiter_keyed.reset()
    respx.get(f"https://{TARGET_IP}/").mock(
        return_value=httpx.Response(200, text=WP_HTML, headers={"content-type": "text/html"})
    )

    def nvd(request):
        hit = "contact_form_7" in str(request.url)
        vulns = [
            {
                "cve": {
                    "id": "CVE-2020-35489",
                    "descriptions": [{"lang": "en", "value": "Unrestricted file upload"}],
                    "metrics": {
                        "cvssMetricV31": [{"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL"}}]
                    },
                }
            }
        ]
        return httpx.Response(200, json={"vulnerabilities": vulns if hit else []})

    respx.get(url__startswith="https://104.16.1.1/rest/json/cves/2.0").mock(side_effect=nvd)
    respx.get(url__startswith="https://104.16.1.2/").mock(
        return_value=httpx.Response(200, json={"vulnerabilities": []})
    )
    ctx.results["tech_stack"] = {"technologies": [{"name": "WordPress", "version": "6.5.2"}]}
    res = await WordPressScanner().run(ctx)
    assert res.data["detected"] and res.data["plugin_count"] == 5 and res.data["theme_count"] == 1
    assert [f.id for f in res.findings] == ["wordpress.plugin.contact-form-7"]
    assert res.findings[0].severity.value == "critical"


@respx.mock
async def test_wordpress_scanner_not_wordpress(ctx):
    respx.get(f"https://{TARGET_IP}/").mock(return_value=httpx.Response(200, text="<html>plain</html>"))
    res = await WordPressScanner().run(ctx)
    assert res.data == {"detected": False, "components": []}
