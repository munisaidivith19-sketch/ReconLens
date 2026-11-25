from datetime import UTC, datetime, timedelta

import httpx
import respx

from app.scanners.whois_rdap import WhoisRdapScanner

RDAP_IP = "104.16.0.10"


def rdap_doc(expires_in_days: int, statuses=None):
    exp = (datetime.now(UTC) + timedelta(days=expires_in_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "objectClassName": "domain",
        "ldhName": "EXAMPLE.COM",
        "status": statuses if statuses is not None else ["client transfer prohibited"],
        "events": [
            {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
            {"eventAction": "expiration", "eventDate": exp},
        ],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": [
                    "vcard",
                    [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar"]],
                ],
            }
        ],
        "nameservers": [{"ldhName": "A.IANA-SERVERS.NET"}, {"ldhName": "B.IANA-SERVERS.NET"}],
        "secureDNS": {"delegationSigned": True},
    }


@respx.mock
async def test_rdap_follows_redirect_and_parses(ctx, public_dns):
    public_dns["rdap.org"] = [RDAP_IP]
    public_dns["rdap.verisign.com"] = ["104.16.0.11"]
    respx.get(f"https://{RDAP_IP}/domain/example.com").mock(
        return_value=httpx.Response(
            302, headers={"Location": "https://rdap.verisign.com/com/v1/domain/example.com"}
        )
    )
    respx.get("https://104.16.0.11/com/v1/domain/example.com").mock(
        return_value=httpx.Response(200, json=rdap_doc(400))
    )
    res = await WhoisRdapScanner().run(ctx)
    assert res.data["registrar"] == "Example Registrar"
    assert res.data["nameservers"] == ["a.iana-servers.net", "b.iana-servers.net"]
    assert res.data["created"].startswith("1995-08-14")
    assert res.findings == []


@respx.mock
async def test_rdap_expiring_soon_flagged(ctx, public_dns):
    public_dns["rdap.org"] = [RDAP_IP]
    respx.get(f"https://{RDAP_IP}/domain/example.com").mock(
        return_value=httpx.Response(200, json=rdap_doc(10, statuses=["active"]))
    )
    res = await WhoisRdapScanner().run(ctx)
    ids = {f.id: f.severity for f in res.findings}
    assert ids["whois_rdap.expiring_soon"] == "high"
    assert "whois_rdap.no_transfer_lock" in ids


@respx.mock
async def test_rdap_not_found(ctx, public_dns):
    public_dns["rdap.org"] = [RDAP_IP]
    respx.get(f"https://{RDAP_IP}/domain/example.com").mock(return_value=httpx.Response(404))
    res = await WhoisRdapScanner().run(ctx)
    assert res.data["available"] is False
