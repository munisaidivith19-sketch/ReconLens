from app.scanners.base import DnsLookupError
from app.scanners.dns_records import DnsRecordsScanner


async def test_dns_records_collects_all_types(ctx, fake_dns):
    fake_dns[("example.com", "A")] = ["93.184.216.34"]
    fake_dns[("example.com", "MX")] = ["10 mail.example.com."]
    fake_dns[("example.com", "NS")] = ["a.iana-servers.net.", "b.iana-servers.net."]
    fake_dns[("example.com", "TXT")] = ["v=spf1 -all"]
    fake_dns[("example.com", "CAA")] = ['0 issue "letsencrypt.org"']

    res = await DnsRecordsScanner().run(ctx)
    recs = res.data["records"]
    assert recs["A"] == ["93.184.216.34"]
    assert recs["CAA"] == ['0 issue "letsencrypt.org"']
    ids = {f.id for f in res.findings}
    assert "dns_records.no_caa" not in ids
    assert "dns_records.no_ipv6" in ids


async def test_dns_missing_caa_and_single_ns(ctx, fake_dns):
    fake_dns[("example.com", "A")] = ["93.184.216.34"]
    fake_dns[("example.com", "NS")] = ["ns1.example.net."]
    res = await DnsRecordsScanner().run(ctx)
    ids = {f.id for f in res.findings}
    assert {"dns_records.no_caa", "dns_records.single_ns"} <= ids


async def test_dns_errors_are_reported_not_raised(ctx, fake_dns):
    fake_dns[("example.com", "A")] = DnsLookupError("DNS lookup timed out")
    res = await DnsRecordsScanner().run(ctx)
    assert res.data["errors"]["A"] == "DNS lookup timed out"
    assert res.data["records"]["A"] == []
