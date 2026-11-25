import json

import httpx
import respx

from app.scanners.subdomains import SubdomainsScanner, extract_names

CRT_IP = "91.199.212.73"


def crt_json(names):
    return [{"name_value": n} for n in names]


@respx.mock
async def test_subdomains_deduplicated_and_filtered(ctx, public_dns):
    public_dns["crt.sh"] = [CRT_IP]
    route = respx.get(url__startswith=f"https://{CRT_IP}/").mock(
        return_value=httpx.Response(
            200,
            json=crt_json(
                [
                    "www.example.com",
                    "*.example.com",
                    "api.example.com\nwww.example.com",
                    "staging.example.com",
                    "evil.com",
                    "notexample.com",
                    "example.com",
                ]
            ),
        )
    )
    res = await SubdomainsScanner().run(ctx)
    assert route.called
    assert route.calls.last.request.url.params["q"] == "%.example.com"
    assert res.data["subdomains"] == ["api.example.com", "staging.example.com", "www.example.com"]
    assert "staging.example.com" in res.data["interesting"]
    assert {f.id for f in res.findings} == {"subdomains.count", "subdomains.interesting"}


@respx.mock
async def test_crtsh_timeout_returns_unavailable(ctx, public_dns):
    public_dns["crt.sh"] = [CRT_IP]
    respx.get(url__startswith=f"https://{CRT_IP}/").mock(side_effect=httpx.ReadTimeout("slow"))
    res = await SubdomainsScanner().run(ctx)
    assert res.data["available"] is False
    assert "did not respond" in res.data["message"]


@respx.mock
async def test_crtsh_error_status(ctx, public_dns):
    public_dns["crt.sh"] = [CRT_IP]
    respx.get(url__startswith=f"https://{CRT_IP}/").mock(return_value=httpx.Response(502))
    res = await SubdomainsScanner().run(ctx)
    assert res.data["available"] is False


def test_extract_names_from_truncated_json():
    raw = json.dumps(crt_json(["a.example.com", "b.example.com"])).encode()[:-15]
    assert "a.example.com" in extract_names(raw, "example.com")
