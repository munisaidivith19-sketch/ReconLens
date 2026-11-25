import httpx
import pytest
import respx

from app.core import ssrf_guard
from app.core.ssrf_guard import (
    BlockedTargetError,
    ResponseTooLargeError,
    SafeHttpClient,
    is_ip_blocked,
    normalize_target,
    resolve_and_validate,
)

PUBLIC_IP = "93.184.216.34"


# ------------------------------------------------------------------ IP classification


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "127.1.2.3",
        "10.0.0.1",
        "172.16.5.4",
        "172.31.255.255",
        "192.168.1.1",
        "169.254.169.254",  # cloud metadata
        "169.254.0.1",
        "100.64.0.1",  # CGNAT
        "100.127.255.254",
        "0.0.0.0",
        "0.1.2.3",
        "224.0.0.1",  # multicast
        "239.255.255.250",
        "240.0.0.1",  # reserved
        "255.255.255.255",
        "192.0.2.10",  # TEST-NET-1
        "198.18.0.1",  # benchmarking
        "::1",
        "::",
        "fe80::1",
        "fc00::1",
        "fd12:3456:789a::1",  # unique-local
        "ff02::1",  # multicast
        "::ffff:127.0.0.1",  # IPv4-mapped loopback
        "::ffff:169.254.169.254",  # IPv4-mapped metadata
        "::ffff:10.0.0.1",
        "::ffff:192.168.0.1",
        "::127.0.0.1",  # IPv4-compatible
        "2002:7f00:1::1",  # 6to4 embedding 127.0.0.1
        "2001:db8::1",  # documentation
        "64:ff9b::a00:1",  # NAT64 embedding 10.0.0.1
        "not-an-ip",
    ],
)
def test_blocked_ips(ip):
    assert is_ip_blocked(ip) is True


@pytest.mark.parametrize(
    "ip", ["93.184.216.34", "1.1.1.1", "8.8.8.8", "2606:4700:4700::1111", "::ffff:8.8.8.8"]
)
def test_public_ips_allowed(ip):
    assert is_ip_blocked(ip) is False


# ------------------------------------------------------------------ normalization


@pytest.mark.parametrize(
    ("raw", "host", "scheme"),
    [
        ("example.com", "example.com", "https"),
        ("  Example.COM.  ", "example.com", "https"),
        ("https://www.example.com/path?q=1", "www.example.com", "https"),
        ("http://example.com", "example.com", "http"),
        ("http://example.com:80/", "example.com", "http"),
        ("https://example.com:443", "example.com", "https"),
        ("bücher.de", "xn--bcher-kva.de", "https"),
        ("https://münchen.example.com/", "xn--mnchen-3ya.example.com", "https"),
    ],
)
def test_normalize_valid(raw, host, scheme):
    t = normalize_target(raw)
    assert t.host == host
    assert t.scheme == scheme


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        ("127.0.0.1", "ip_address"),
        ("http://127.0.0.1/", "ip_address"),
        ("http://[::1]/", "ip_address"),
        ("http://[::ffff:127.0.0.1]/", "ip_address"),
        ("2130706433", "ip_address"),  # decimal 127.0.0.1
        ("0x7f.0.0.1", "ip_address"),
        ("http://169.254.169.254/latest/meta-data/", "ip_address"),
        ("https://user:pass@example.com/", "credentials"),
        ("https://user@example.com/", "credentials"),
        ("ftp://example.com/", "scheme"),
        ("file:///etc/passwd", "scheme"),
        ("gopher://example.com/", "scheme"),
        ("javascript:alert(1)", "scheme"),
        ("https://example.com:8080/", "port"),
        ("https://example.com:22/", "port"),
        ("http://example.com:abc/", "port"),
        ("localhost", "invalid_host"),
        ("http://localhost/", "invalid_host"),
        ("printer.local", "internal_host"),
        ("db.internal", "internal_host"),
        ("example", "invalid_host"),
        ("", "invalid_host"),
        ("exa mple.com", "invalid_host"),
        ("-bad-.com", "invalid_host"),
        ("https://example.com\\@evil.com", "invalid_host"),
    ],
)
def test_normalize_rejects(raw, code):
    with pytest.raises(BlockedTargetError) as exc:
        normalize_target(raw)
    assert exc.value.code == code


# ------------------------------------------------------------------ resolution


async def test_resolve_rejects_private(public_dns):
    public_dns["evil.example.org"] = ["10.0.0.5"]
    with pytest.raises(BlockedTargetError) as exc:
        await resolve_and_validate("evil.example.org")
    assert exc.value.code == "private_ip"


async def test_resolve_rejects_if_any_address_private(public_dns):
    public_dns["mixed.example.org"] = [PUBLIC_IP, "169.254.169.254"]
    with pytest.raises(BlockedTargetError):
        await resolve_and_validate("mixed.example.org")


async def test_resolve_rejects_ipv6_private(public_dns):
    public_dns["v6.example.org"] = ["fd00::1"]
    with pytest.raises(BlockedTargetError):
        await resolve_and_validate("v6.example.org")


async def test_resolve_rejects_ipv4_mapped_ipv6(public_dns):
    public_dns["mapped.example.org"] = ["::ffff:127.0.0.1"]
    with pytest.raises(BlockedTargetError):
        await resolve_and_validate("mapped.example.org")


async def test_resolve_rejects_unresolvable(public_dns):
    public_dns["nothing.example.org"] = []
    with pytest.raises(BlockedTargetError) as exc:
        await resolve_and_validate("nothing.example.org")
    assert exc.value.code == "unresolvable"


async def test_resolve_ok_prefers_ipv4(public_dns):
    public_dns["ok.example.org"] = ["2606:4700:4700::1111", PUBLIC_IP]
    assert (await resolve_and_validate("ok.example.org"))[0] == PUBLIC_IP


# ------------------------------------------------------------------ safe client


@respx.mock
async def test_safe_client_connects_to_validated_ip_with_host_header(public_dns):
    route = respx.get(f"https://{PUBLIC_IP}/").mock(return_value=httpx.Response(200, text="hello"))
    async with SafeHttpClient() as client:
        resp = await client.get("https://example.com/")
    assert resp.status_code == 200
    assert resp.text == "hello"
    req = route.calls.last.request
    assert req.headers["host"] == "example.com"
    assert req.extensions.get("sni_hostname") == "example.com"
    assert "ReconLens" in req.headers["user-agent"]


@respx.mock
async def test_dns_rebinding_uses_first_validated_ip(public_dns, monkeypatch):
    """Resolution happens once per hop and the connection goes to that exact IP."""
    calls = {"n": 0}

    async def rebinding_lookup(host: str) -> list[str]:
        calls["n"] += 1
        return [PUBLIC_IP] if calls["n"] == 1 else ["127.0.0.1"]

    monkeypatch.setattr(ssrf_guard, "_dns_lookup", rebinding_lookup)
    route = respx.get(f"https://{PUBLIC_IP}/").mock(return_value=httpx.Response(200, text="ok"))
    async with SafeHttpClient() as client:
        resp = await client.get("https://rebind.example.org/")
    assert resp.ip == PUBLIC_IP
    assert route.called
    assert calls["n"] == 1


@respx.mock
async def test_redirect_to_localhost_blocked(public_dns):
    respx.get(f"https://{PUBLIC_IP}/").mock(
        return_value=httpx.Response(302, headers={"Location": "http://127.0.0.1/admin"})
    )
    async with SafeHttpClient() as client:
        with pytest.raises(BlockedTargetError) as exc:
            await client.get("https://example.com/")
    assert exc.value.code == "ip_address"


@respx.mock
async def test_redirect_to_metadata_blocked(public_dns):
    respx.get(f"https://{PUBLIC_IP}/").mock(
        return_value=httpx.Response(301, headers={"Location": "http://169.254.169.254/latest/meta-data/"})
    )
    async with SafeHttpClient() as client:
        with pytest.raises(BlockedTargetError):
            await client.get("https://example.com/")


@respx.mock
async def test_redirect_to_hostname_resolving_private_blocked(public_dns):
    public_dns["internal-looking.example.net"] = ["192.168.1.10"]
    respx.get(f"https://{PUBLIC_IP}/").mock(
        return_value=httpx.Response(302, headers={"Location": "https://internal-looking.example.net/"})
    )
    async with SafeHttpClient() as client:
        with pytest.raises(BlockedTargetError) as exc:
            await client.get("https://example.com/")
    assert exc.value.code == "private_ip"


@respx.mock
async def test_redirect_to_disallowed_port_blocked(public_dns):
    respx.get(f"https://{PUBLIC_IP}/").mock(
        return_value=httpx.Response(302, headers={"Location": "https://example.com:6379/"})
    )
    async with SafeHttpClient() as client:
        with pytest.raises(BlockedTargetError) as exc:
            await client.get("https://example.com/")
    assert exc.value.code == "port"


@respx.mock
async def test_redirect_ipv6_mapped_literal_blocked(public_dns):
    respx.get(f"https://{PUBLIC_IP}/").mock(
        return_value=httpx.Response(302, headers={"Location": "http://[::ffff:7f00:1]/"})
    )
    async with SafeHttpClient() as client:
        with pytest.raises(BlockedTargetError):
            await client.get("https://example.com/")


@respx.mock
async def test_redirects_followed_and_revalidated(public_dns):
    public_dns["www.example.com"] = ["93.184.216.35"]
    respx.get(f"http://{PUBLIC_IP}/").mock(
        return_value=httpx.Response(301, headers={"Location": "https://www.example.com/home"})
    )
    respx.get("https://93.184.216.35/home").mock(return_value=httpx.Response(200, text="home"))
    async with SafeHttpClient() as client:
        resp = await client.get("http://example.com/")
    assert resp.status_code == 200
    assert resp.url == "https://www.example.com/home"
    assert resp.redirects == ["https://www.example.com/home"]


@respx.mock
async def test_too_many_redirects(public_dns):
    respx.get(f"https://{PUBLIC_IP}/loop").mock(
        return_value=httpx.Response(302, headers={"Location": "/loop"})
    )
    async with SafeHttpClient() as client:
        with pytest.raises(BlockedTargetError) as exc:
            await client.get("https://example.com/loop")
    assert exc.value.code == "too_many_redirects"


@respx.mock
async def test_oversized_response_rejected(public_dns):
    big = b"a" * (ssrf_guard.DEFAULT_MAX_BYTES + 10)
    respx.get(f"https://{PUBLIC_IP}/").mock(return_value=httpx.Response(200, content=big))
    async with SafeHttpClient() as client:
        with pytest.raises(ResponseTooLargeError):
            await client.get("https://example.com/")


@respx.mock
async def test_oversized_response_truncated_when_allowed(public_dns):
    big = b"a" * 5000
    respx.get(f"https://{PUBLIC_IP}/").mock(return_value=httpx.Response(200, content=big))
    async with SafeHttpClient() as client:
        resp = await client.get("https://example.com/", max_bytes=1000, allow_truncate=True)
    assert resp.truncated is True
    assert len(resp.content) == 1000


@respx.mock
async def test_ipv6_target_uses_bracketed_url(public_dns):
    public_dns["v6only.example.org"] = ["2606:4700:4700::1111"]
    route = respx.get("https://[2606:4700:4700::1111]/").mock(return_value=httpx.Response(204))
    async with SafeHttpClient() as client:
        resp = await client.get("https://v6only.example.org/")
    assert resp.status_code == 204
    assert route.called


async def test_tls_handshake_rejects_private(public_dns):
    public_dns["tls.example.org"] = ["10.1.1.1"]
    with pytest.raises(BlockedTargetError):
        await ssrf_guard.tls_handshake("tls.example.org")


async def test_tls_handshake_rejects_other_ports(public_dns):
    with pytest.raises(BlockedTargetError):
        await ssrf_guard.tls_handshake("example.com", port=8443)
