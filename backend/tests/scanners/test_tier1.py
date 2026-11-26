"""Vulnerable JS libraries, SRI, favicon hash, lookalike domains and email transport hardening."""

import base64

import httpx
import respx

from app.scanners import base
from app.scanners.client_side import ClientSideScanner
from app.scanners.email_security import EmailSecurityScanner, parse_mta_sts_policy
from app.scanners.favicon import FaviconScanner, icon_candidates, murmur3_32, shodan_favicon_hash
from app.scanners.lookalikes import LookalikesScanner, permutations, split_registrable
from app.services import retire

TARGET_IP = "93.184.216.34"

# ---------------------------------------------------------------- Retire.js


def test_retire_version_compare():
    assert retire.is_at_or_above("1.12.4", "1.9.0")
    assert not retire.is_at_or_above("1.8.3", "1.9.0")
    assert retire.is_at_or_above("3.0.0", "3.0.0")
    assert not retire.is_at_or_above("3.0.0-rc1", "3.0.0")  # pre-release sorts before the release


def test_clean_version_drops_build_suffixes():
    assert retire.clean_version("1.8.3.min") == "1.8.3"
    assert retire.clean_version("2.2.4.slim.min") == "2.2.4"
    assert retire.clean_version("3.0.0-rc1") == "3.0.0-rc1"
    assert retire.clean_version("1.10.2-min") == "1.10.2"


def test_retire_detects_old_jquery_from_url_and_content():
    assert ("jquery", "1.8.3") in retire.detect_url("https://code.jquery.com/jquery-1.8.3.min.js")
    comp = retire.component("jquery")
    assert comp is not None
    assert retire.vulnerabilities_for(comp, "1.8.3")
    found = dict(retire.detect_content("/*! jQuery v3.7.1 | (c) OpenJS Foundation */"))
    assert found.get("jquery") == "3.7.1"
    assert retire.vulnerabilities_for(comp, "3.7.1") == []


HTML = """<html><head>
<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/1.8.3/jquery.min.js"></script>
<script src="https://www.googletagmanager.com/gtag/js?id=G-1"></script>
<script src="https://cdn.jsdelivr.net/npm/lib@1.0.0/x.js" integrity="sha384-abc" crossorigin="anonymous"></script>
<link rel="stylesheet" href="https://fonts.cdn-example.net/font.css">
<link rel="stylesheet" href="/local.css">
</head><body></body></html>"""


@respx.mock
async def test_client_side_libraries_and_sri(ctx):
    respx.get(f"https://{TARGET_IP}/").mock(
        return_value=httpx.Response(200, text=HTML, headers={"content-type": "text/html"})
    )
    third_party = respx.get(url__regex=r".*(cdnjs|googletagmanager|jsdelivr|cdn-example).*").mock(
        return_value=httpx.Response(200)
    )
    res = await ClientSideScanner().run(ctx)
    d = res.data
    assert not third_party.called  # third-party files are never fetched

    jq = next(lib for lib in d["libraries"] if lib["component"] == "jquery")
    assert jq["version"] == "1.8.3" and jq["detected_by"] == "script URL" and jq["vulnerabilities"]

    sri = d["sri"]
    assert sri["with_integrity"] == 1
    assert sri["missing_pinnable"] == 2  # cdnjs jquery + font.css; GTM is dynamic
    assert any(m["dynamic"] for m in sri["missing"])

    ids = {f.id for f in res.findings}
    assert {"client_side.vulnerable_lib.jquery", "client_side.no_sri"} <= ids
    lib_finding = next(f for f in res.findings if f.id == "client_side.vulnerable_lib.jquery")
    assert lib_finding.category == "Vulnerable components"
    assert "Upgrade jquery to" in lib_finding.recommendation


# ---------------------------------------------------------------- favicon


def test_murmur3_known_values():
    assert murmur3_32(b"") == 0
    assert murmur3_32(b"foo") == -156908512
    assert shodan_favicon_hash(b"abc") == murmur3_32(base64.encodebytes(b"abc"))


def test_icon_candidates_prefers_link_tag():
    html = (
        '<link rel="shortcut icon" href="/static/fav.png"><link rel="icon" href="data:image/png;base64,AA">'
    )
    assert icon_candidates(html, "https://example.com/") == [
        "https://example.com/static/fav.png",
        "https://example.com/favicon.ico",
    ]


@respx.mock
async def test_favicon_scanner_skips_soft_404(ctx):
    icon = b"\x00\x00\x01\x00fake-icon-bytes"
    respx.get(f"https://{TARGET_IP}/").mock(
        return_value=httpx.Response(200, text='<link rel="icon" href="/missing.png">')
    )
    respx.get(f"https://{TARGET_IP}/missing.png").mock(
        return_value=httpx.Response(
            200, text="<!doctype html><p>not found</p>", headers={"content-type": "text/html"}
        )
    )
    respx.get(f"https://{TARGET_IP}/favicon.ico").mock(
        return_value=httpx.Response(200, content=icon, headers={"content-type": "image/x-icon"})
    )
    res = await FaviconScanner().run(ctx)
    d = res.data
    assert d["found"] is True
    assert d["url"].endswith("/favicon.ico")
    assert d["mmh3"] == shodan_favicon_hash(icon)
    assert d["searches"][0]["query"] == f"http.favicon.hash:{d['mmh3']}"
    assert [f.id for f in res.findings] == ["favicon.hash"]


# ---------------------------------------------------------------- lookalikes


def test_split_registrable():
    assert split_registrable("example.com") == ("example", "com")
    assert split_registrable("shop.example.co.uk") == ("example", "co.uk")
    assert split_registrable("jnn.edu.in") == ("jnn", "edu.in")


def test_permutations_cover_common_techniques():
    perms = dict(permutations("paypal", "com"))
    assert perms["paypal.net"] == "other TLD"
    assert perms["paypa1.com"] == "look-alike character"
    assert perms["paypal-login.com"] == "added word"
    assert perms["paypl.com"] == "missing letter"
    assert perms["papyal.com"] == "swapped letters"
    assert "paypal.com" not in perms
    assert all(not d.startswith("-") for d in perms)


async def test_lookalikes_scanner(ctx, fake_dns, monkeypatch):
    ctx.results["whois_rdap"] = {"registrable_domain": "example.com"}
    live = {"example.net", "examp1e.com"}

    async def exists(name):
        return name in live

    monkeypatch.setattr(base, "dns_name_exists", exists)
    fake_dns[("examp1e.com", "A")] = ["203.0.113.7"]
    fake_dns[("examp1e.com", "MX")] = ["10 mail.examp1e.com."]
    fake_dns[("example.net", "A")] = ["198.51.100.2"]

    res = await LookalikesScanner().run(ctx)
    d = res.data
    assert d["base"] == "example.com"
    assert [r["domain"] for r in d["registered"]] == ["examp1e.com", "example.net"]  # mail-capable first
    assert d["registered"][0]["mx"] == ["mail.examp1e.com"]
    assert d["with_mail"] == 1
    f = res.findings[0]
    assert f.id == "lookalikes.registered" and f.severity == "low"


# ---------------------------------------------------------------- email hardening


def test_parse_mta_sts_policy():
    p = parse_mta_sts_policy("version: STSv1\nmode: enforce\nmx: *.mail.example.com\nmax_age: 604800\n")
    assert p == {"version": "STSv1", "mode": "enforce", "max_age": 604800, "mx": ["*.mail.example.com"]}


def _mail_dns(fake_dns):
    fake_dns[("example.com", "MX")] = ["10 mx.example.com."]
    fake_dns[("example.com", "TXT")] = ["v=spf1 -all"]
    fake_dns[("_dmarc.example.com", "TXT")] = ["v=DMARC1; p=reject"]
    fake_dns[("_mta-sts.example.com", "TXT")] = ["v=STSv1; id=2026"]


@respx.mock
async def test_mta_sts_enforced_with_tls_rpt_and_bimi(ctx, fake_dns):
    _mail_dns(fake_dns)
    fake_dns[("_smtp._tls.example.com", "TXT")] = ["v=TLSRPTv1; rua=mailto:tls@example.com"]
    fake_dns[("default._bimi.example.com", "TXT")] = ["v=BIMI1; l=https://example.com/logo.svg"]
    respx.get(f"https://{TARGET_IP}/.well-known/mta-sts.txt").mock(
        return_value=httpx.Response(
            200, text="version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: 86400\n"
        )
    )
    res = await EmailSecurityScanner().run(ctx)
    h = res.data["hardening"]
    assert h["mta_sts"]["policy"]["mode"] == "enforce"
    assert h["tls_rpt"]["rua"] == "mailto:tls@example.com"
    assert h["bimi"]["logo"] == "https://example.com/logo.svg"
    ids = {f.id for f in res.findings}
    assert not ids & {
        "email_security.no_mta_sts",
        "email_security.mta_sts_broken",
        "email_security.no_tls_rpt",
    }


@respx.mock
async def test_mta_sts_announced_but_policy_missing(ctx, fake_dns):
    _mail_dns(fake_dns)
    respx.get(f"https://{TARGET_IP}/.well-known/mta-sts.txt").mock(return_value=httpx.Response(404))
    res = await EmailSecurityScanner().run(ctx)
    ids = {f.id for f in res.findings}
    assert {"email_security.mta_sts_broken", "email_security.no_tls_rpt"} <= ids


async def test_no_mail_no_hardening_checks(ctx, fake_dns):
    fake_dns[("example.com", "TXT")] = ["v=spf1 -all"]
    fake_dns[("_dmarc.example.com", "TXT")] = ["v=DMARC1; p=reject"]
    res = await EmailSecurityScanner().run(ctx)
    assert res.data["hardening"] is None
    assert not any("mta_sts" in f.id or "tls_rpt" in f.id for f in res.findings)
