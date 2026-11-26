"""DNS extras, takeover detection, security.txt, InternetDB and parameter classification."""

import httpx
import pytest
import respx

from app.scanners import base
from app.scanners.dns_records import DnsRecordsScanner
from app.scanners.endpoints import classify_parameters
from app.scanners.exposed_services import ExposedServicesScanner
from app.scanners.security_txt import SecurityTxtScanner, parse_security_txt
from app.scanners.takeover import TakeoverScanner
from app.services.dns_signatures import mail_providers, takeover_service, txt_services

TARGET_IP = "93.184.216.34"
SHODAN_IP = "104.18.0.1"


# ---------------------------------------------------------------- DNS extras


async def test_dns_extras_srv_ptr_mail_and_services(ctx, fake_dns):
    fake_dns[("example.com", "A")] = [TARGET_IP]
    fake_dns[("example.com", "MX")] = ["1 aspmx.l.google.com."]
    fake_dns[("example.com", "TXT")] = ["google-site-verification=abc", "MS=ms123", "v=spf1 -all"]
    fake_dns[("example.com", "SOA")] = ["ns1.example.com. admin.example.com. 1 7200 3600 1209600 300"]
    fake_dns[("_ldap._tcp.example.com", "SRV")] = ["0 100 389 dc1.example.com."]
    fake_dns[("_sip._tcp.example.com", "SRV")] = ["0 0 5060 sip.example.com."]
    fake_dns[("34.216.184.93.in-addr.arpa", "PTR")] = ["host.provider.net."]

    res = await DnsRecordsScanner().run(ctx)
    d = res.data
    assert d["records"]["SOA"]
    assert {s["service"] for s in d["srv"]} == {"_ldap._tcp", "_sip._tcp"}
    assert d["ptr"] == [{"ip": TARGET_IP, "names": ["host.provider.net"]}]
    assert d["mail_providers"] == ["Google Workspace"]
    assert {s["service"] for s in d["services"]} == {"Google (Search Console / Workspace)", "Microsoft 365"}
    assert d["wildcard"] is False
    ids = {f.id for f in res.findings}
    assert {"dns_records.internal_srv", "dns_records.srv_services", "dns_records.third_party_services"} <= ids


async def test_dns_wildcard_and_broken_dnssec(ctx, fake_dns, monkeypatch):
    async def lookup(name, rdtype):
        if name.startswith("rl-") and rdtype == "A":
            return ["1.2.3.4"]
        if (name, rdtype) == ("example.com", "DS"):
            return ["12345 13 2 ABCDEF"]
        return []

    monkeypatch.setattr(base, "dns_query", lookup)
    res = await DnsRecordsScanner().run(ctx)
    assert res.data["wildcard"] is True
    assert res.data["dnssec"] == {"ds": True, "dnskey": False, "signed": False}
    ids = {f.id for f in res.findings}
    assert {"dns_records.wildcard", "dns_records.dnssec_broken"} <= ids


def test_signature_tables():
    assert mail_providers(["10 example-com.mail.protection.outlook.com."]) == ["Microsoft 365"]
    assert txt_services(["atlassian-domain-verification=x"])[0]["service"] == "Atlassian"
    assert takeover_service("myapp.azurewebsites.net") == (
        "Azure App Service",
        "https://github.com/EdOverflow/can-i-take-over-xyz/issues/35",
    )
    assert takeover_service("example.org") is None


# ---------------------------------------------------------------- takeover


async def test_takeover_and_dangling(ctx, fake_dns, monkeypatch):
    ctx.results["subdomains"] = {
        "subdomains": ["old.example.com", "gone.example.com", "www.example.com", "ok.example.com"],
        "current": ["www.example.com"],
    }
    fake_dns[("old.example.com", "CNAME")] = ["oldapp.azurewebsites.net."]
    fake_dns[("gone.example.com", "CNAME")] = ["shop.retired-vendor.example."]
    fake_dns[("ok.example.com", "CNAME")] = ["site.github.io."]

    async def exists(name):
        return name == "site.github.io"

    monkeypatch.setattr(base, "dns_name_exists", exists)
    res = await TakeoverScanner().run(ctx)
    d = res.data
    assert [c["name"] for c in d["takeover"]] == ["old.example.com"]
    assert [c["name"] for c in d["dangling"]] == ["gone.example.com"]
    assert [c["name"] for c in d["cloud_hosted"]] == ["ok.example.com"]
    ids = {f.id for f in res.findings}
    assert ids == {"takeover.possible.old.example.com", "takeover.dangling"}
    high = next(f for f in res.findings if f.id.startswith("takeover.possible"))
    assert high.severity == "high"


async def test_takeover_without_subdomains(ctx, fake_dns):
    res = await TakeoverScanner().run(ctx)
    assert res.data["checked"] == 0
    assert res.findings == []


# ---------------------------------------------------------------- security.txt


@respx.mock
async def test_security_txt_found_and_expired(ctx):
    body = "Contact: mailto:security@example.com\nExpires: 2020-01-01T00:00:00Z\nPolicy: https://hackerone.com/x\n"
    respx.get(f"https://{TARGET_IP}/.well-known/security.txt").mock(
        return_value=httpx.Response(200, text=body)
    )
    res = await SecurityTxtScanner().run(ctx)
    assert res.data["found"] is True
    assert res.data["expired"] is True
    assert res.data["bug_bounty_hint"] is True
    assert {f.id for f in res.findings} == {"security_txt.expired"}


@respx.mock
async def test_security_txt_soft_404_is_missing(ctx):
    html = "<!doctype html><html><body>Not found</body></html>"
    respx.get(url__startswith=f"https://{TARGET_IP}/").mock(return_value=httpx.Response(200, text=html))
    res = await SecurityTxtScanner().run(ctx)
    assert res.data["found"] is False
    assert {f.id for f in res.findings} == {"security_txt.missing"}


def test_parse_security_txt_ignores_comments():
    fields = parse_security_txt("# hi\nContact: https://example.com/report\nHiring: https://jobs\nFoo: bar\n")
    assert fields == {"contact": ["https://example.com/report"], "hiring": ["https://jobs"]}


# ---------------------------------------------------------------- InternetDB


@pytest.fixture
def shodan_dns(public_dns):
    public_dns["internetdb.shodan.io"] = [SHODAN_IP]
    return public_dns


@respx.mock
async def test_exposed_services_flags_database_and_vulns(ctx, shodan_dns):
    ctx.results["dns_records"] = {"records": {"A": [TARGET_IP]}}
    respx.get(f"https://{SHODAN_IP}/{TARGET_IP}").mock(
        return_value=httpx.Response(
            200,
            json={
                "ip": TARGET_IP,
                "ports": [22, 80, 443, 3306],
                "cpes": ["cpe:/a:mysql:mysql"],
                "hostnames": ["example.com"],
                "tags": [],
                "vulns": ["CVE-2021-1234"],
            },
        )
    )
    res = await ExposedServicesScanner().run(ctx)
    assert res.data["hosts"][0]["ports"] == [22, 80, 443, 3306]
    ids = {f.id for f in res.findings}
    assert ids == {f"exposed_services.port.{TARGET_IP}.3306", f"exposed_services.vulns.{TARGET_IP}"}
    # second run is served from the 24h cache
    respx.reset()
    res2 = await ExposedServicesScanner().run(ctx)
    assert res2.data["hosts"][0]["ports"] == [22, 80, 443, 3306]


@respx.mock
async def test_exposed_services_cdn_ip_is_not_flagged(ctx, shodan_dns):
    ctx.results["dns_records"] = {"records": {"A": [TARGET_IP]}}
    respx.get(f"https://{SHODAN_IP}/{TARGET_IP}").mock(
        return_value=httpx.Response(200, json={"ports": [3306], "tags": ["cdn"], "vulns": ["CVE-2020-1"]})
    )
    res = await ExposedServicesScanner().run(ctx)
    assert res.findings == []


@respx.mock
async def test_exposed_services_unknown_ip_and_errors(ctx, shodan_dns):
    ctx.results["dns_records"] = {"records": {"A": [TARGET_IP]}}
    respx.get(f"https://{SHODAN_IP}/{TARGET_IP}").mock(
        return_value=httpx.Response(404, json={"detail": "No information available"})
    )
    res = await ExposedServicesScanner().run(ctx)
    assert res.data["hosts"][0]["known"] is False
    assert res.findings == []


# ---------------------------------------------------------------- parameters


def test_classify_parameters():
    classes = {
        c["class"]: c["params"]
        for c in classify_parameters(["redirect_uri", "id", "q", "token", "utm_source"])
    }
    assert classes["redirect"] == ["redirect_uri"]
    assert classes["idor"] == ["id"]
    assert classes["injection"] == ["q"]
    assert classes["auth"] == ["token"]
    assert "utm_source" not in str(classes)
