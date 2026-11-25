import ssl
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.core import ssrf_guard
from app.core.ssrf_guard import TlsHandshakeResult
from app.scanners.tls_check import TlsCheckScanner, hostname_matches


def make_cert(names, days_valid=90, expired=False) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    now = datetime.now(UTC)
    start = now - timedelta(days=400 if expired else 1)
    end = now - timedelta(days=5) if expired else now + timedelta(days=days_valid)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(end)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


@pytest.fixture
def fake_tls(monkeypatch):
    state = {"der": make_cert(["example.com", "www.example.com"]), "verify_error": None, "legacy": False}

    async def handshake(host, *, port=443, verify=True, version=None, handshake_timeout=8.0):
        if version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
            if state["legacy"]:
                return TlsHandshakeResult("93.184.216.34", "TLSv1", "AES", state["der"], [], False)
            raise ssl.SSLError(1, "[SSL: TLSV1_ALERT_PROTOCOL_VERSION] tlsv1 alert protocol version")
        if verify and state["verify_error"]:
            err = ssl.SSLCertVerificationError(1, "certificate verify failed")
            err.verify_message = state["verify_error"]
            raise err
        return TlsHandshakeResult(
            "93.184.216.34", "TLSv1.3", "TLS_AES_256_GCM_SHA384", state["der"], [], verify
        )

    monkeypatch.setattr(ssrf_guard, "tls_handshake", handshake)
    return state


async def test_valid_certificate(ctx, fake_tls):
    res = await TlsCheckScanner().run(ctx)
    assert res.data["available"] is True
    assert res.data["protocol"] == "TLSv1.3"
    assert res.data["hostname_match"] is True
    assert res.data["trusted"] is True
    assert res.data["legacy_protocols"] == {"tls1_0": False, "tls1_1": False}
    assert res.findings == []


async def test_expired_certificate(ctx, fake_tls):
    fake_tls["der"] = make_cert(["example.com"], expired=True)
    fake_tls["verify_error"] = "certificate has expired"
    res = await TlsCheckScanner().run(ctx)
    ids = {f.id: f.severity for f in res.findings}
    assert ids["tls_check.expired"] == "critical"
    assert res.data["trusted"] is False


async def test_hostname_mismatch_and_untrusted(ctx, fake_tls):
    fake_tls["der"] = make_cert(["other.org"])
    fake_tls["verify_error"] = "self-signed certificate"
    res = await TlsCheckScanner().run(ctx)
    ids = {f.id for f in res.findings}
    assert {"tls_check.hostname_mismatch", "tls_check.untrusted"} <= ids


async def test_legacy_protocols_flagged(ctx, fake_tls):
    fake_tls["legacy"] = True
    res = await TlsCheckScanner().run(ctx)
    assert any(f.id == "tls_check.legacy_tls" for f in res.findings)


async def test_expiring_soon(ctx, fake_tls):
    fake_tls["der"] = make_cert(["example.com"], days_valid=7)
    res = await TlsCheckScanner().run(ctx)
    assert any(f.id == "tls_check.expiring_soon" for f in res.findings)


async def test_no_tls_service(ctx, monkeypatch):
    async def refuse(*a, **k):
        raise ConnectionRefusedError("refused")

    monkeypatch.setattr(ssrf_guard, "tls_handshake", refuse)
    res = await TlsCheckScanner().run(ctx)
    assert res.data["available"] is False


def test_wildcard_matching():
    assert hostname_matches("www.example.com", ["*.example.com"])
    assert not hostname_matches("a.b.example.com", ["*.example.com"])
    assert not hostname_matches("example.com", ["*.example.com"])
