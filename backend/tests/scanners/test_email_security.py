from app.scanners.email_security import EmailSecurityScanner, analyze_dmarc, analyze_spf


async def test_no_spf_no_dmarc_is_spoofable(ctx, fake_dns):
    fake_dns[("example.com", "MX")] = ["10 mx.example.com."]
    res = await EmailSecurityScanner().run(ctx)
    assert res.data["spoofable"] is True
    assert res.data["verdict_level"] == "spoofable"
    ids = {f.id: f.severity for f in res.findings}
    assert ids["email_security.spoofable"] == "high"
    assert "email_security.no_spf" in ids
    assert "email_security.no_dmarc" in ids


async def test_enforced_dmarc_is_protected(ctx, fake_dns):
    fake_dns[("example.com", "TXT")] = ["v=spf1 include:_spf.google.com -all"]
    fake_dns[("_dmarc.example.com", "TXT")] = ["v=DMARC1; p=reject; rua=mailto:d@example.com"]
    fake_dns[("google._domainkey.example.com", "TXT")] = ["v=DKIM1; k=rsa; p=MIIB..."]
    fake_dns[("example.com", "MX")] = ["1 aspmx.l.google.com."]
    res = await EmailSecurityScanner().run(ctx)
    assert res.data["spoofable"] is False
    assert res.data["verdict_level"] == "protected"
    assert res.data["dkim"]["selectors_found"] == ["google"]
    assert res.findings == []


async def test_dmarc_none_is_spoofable(ctx, fake_dns):
    fake_dns[("example.com", "TXT")] = ["v=spf1 -all"]
    fake_dns[("_dmarc.example.com", "TXT")] = ["v=DMARC1; p=none; rua=mailto:d@example.com"]
    res = await EmailSecurityScanner().run(ctx)
    assert res.data["spoofable"] is True
    assert any(f.id == "email_security.dmarc_none" for f in res.findings)


async def test_subdomain_inherits_parent_dmarc(ctx, fake_dns):
    ctx.domain = "shop.example.com"
    fake_dns[("shop.example.com", "TXT")] = ["v=spf1 -all"]
    fake_dns[("_dmarc.example.com", "TXT")] = ["v=DMARC1; p=reject; sp=quarantine"]
    res = await EmailSecurityScanner().run(ctx)
    assert res.data["dmarc"]["inherited_from"] == "example.com"
    assert res.data["dmarc"]["policy"] == "quarantine"
    assert res.data["spoofable"] is False


def test_spf_plus_all():
    assert analyze_spf(["v=spf1 +all"])["all_qualifier"] == "+"
    assert analyze_spf(["v=spf1 a mx ~all"])["all_qualifier"] == "~"
    assert "Multiple SPF" in analyze_spf(["v=spf1 -all", "v=spf1 ~all"])["issues"][0]


def test_dmarc_pct():
    d = analyze_dmarc(["v=DMARC1; p=quarantine; pct=25; rua=mailto:x@example.com"])
    assert d["pct"] == 25
    assert any("25%" in i for i in d["issues"])
