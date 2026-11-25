"""TLS certificate and protocol checks (handshakes only, through the SSRF guard)."""

import asyncio
import ssl
from datetime import UTC, datetime
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from app.core import ssrf_guard
from app.models.finding import Severity
from app.scanners.base import ScanContext, Scanner, ScannerResult, describe_error


def _name(n: x509.Name) -> str:
    for oid in (NameOID.COMMON_NAME, NameOID.ORGANIZATION_NAME):
        attrs = n.get_attributes_for_oid(oid)
        if attrs:
            return str(attrs[0].value)
    return n.rfc4514_string()[:200]


def hostname_matches(host: str, names: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for name in names:
        name = name.lower().rstrip(".")
        if name == host:
            return True
        if name.startswith("*.") and host.count(".") == name.count(".") and host.endswith(name[1:]):
            return True
    return False


def parse_certificate(der: bytes) -> dict[str, Any]:
    cert = x509.load_der_x509_certificate(der)
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        key_desc, key_bits = "RSA", key.key_size
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key_desc, key_bits = f"EC {key.curve.name}", key.key_size
    elif isinstance(key, dsa.DSAPublicKey):
        key_desc, key_bits = "DSA", key.key_size
    else:
        key_desc, key_bits = type(key).__name__.replace("PublicKey", ""), None
    sig = cert.signature_hash_algorithm
    not_after = cert.not_valid_after_utc
    return {
        "subject": _name(cert.subject),
        "issuer": _name(cert.issuer),
        "sans": sans[:100],
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": not_after.isoformat(),
        "days_until_expiry": (not_after - datetime.now(UTC)).days,
        "self_signed": cert.issuer == cert.subject,
        "key_type": key_desc,
        "key_bits": key_bits,
        "signature_hash": sig.name if isinstance(sig, hashes.HashAlgorithm) else None,
        "serial": format(cert.serial_number, "x")[:64],
    }


def _chain_summary(chain: list[bytes]) -> list[dict[str, str]]:
    out = []
    for der in chain[:6]:
        try:
            c = x509.load_der_x509_certificate(der)
            out.append({"subject": _name(c.subject), "issuer": _name(c.issuer)})
        except ValueError:
            continue
    return out


async def _legacy_accepted(domain: str, version: ssl.TLSVersion) -> bool | None:
    """True if the server completes a handshake at exactly this version, None if untestable here."""
    try:
        await ssrf_guard.tls_handshake(domain, verify=False, version=version, handshake_timeout=6.0)
        return True
    except ssl.SSLError as exc:
        text = str(exc).upper()
        if "NO_PROTOCOLS_AVAILABLE" in text or "NO PROTOCOLS AVAILABLE" in text:
            return None  # the local TLS library cannot speak this version
        return False
    except ValueError:
        return None
    except (OSError, TimeoutError):
        return False


class TlsCheckScanner(Scanner):
    name = "tls_check"
    label = "TLS certificate & protocols"
    category = "TLS"
    timeout = 40.0

    async def run(self, ctx: ScanContext) -> ScannerResult:
        verify_error = None
        trusted = True
        try:
            hs = await ssrf_guard.tls_handshake(ctx.domain, verify=True)
        except ssl.SSLCertVerificationError as exc:
            trusted = False
            verify_error = (exc.verify_message or str(exc))[:200]
            hs = None
        except ssrf_guard.BlockedTargetError:
            raise
        except (OSError, TimeoutError, ssl.SSLError) as exc:
            return ScannerResult(
                data={"available": False, "message": f"No TLS service on port 443 ({describe_error(exc)})."}
            )

        if hs is None:
            try:
                hs = await ssrf_guard.tls_handshake(ctx.domain, verify=False)
            except (OSError, TimeoutError, ssl.SSLError) as exc:
                return ScannerResult(
                    data={
                        "available": False,
                        "trusted": False,
                        "verify_error": verify_error,
                        "message": f"TLS handshake failed ({describe_error(exc)}).",
                    }
                )

        if not hs.der_cert:
            return ScannerResult(
                data={"available": False, "message": "Server did not present a certificate."}
            )

        cert = parse_certificate(hs.der_cert)
        names = cert["sans"] or [cert["subject"]]
        host_ok = hostname_matches(ctx.domain, names)

        tls10, tls11 = await asyncio.gather(
            _legacy_accepted(ctx.domain, ssl.TLSVersion.TLSv1),
            _legacy_accepted(ctx.domain, ssl.TLSVersion.TLSv1_1),
        )

        data = {
            "available": True,
            "protocol": hs.protocol,
            "cipher": hs.cipher,
            **cert,
            "hostname_match": host_ok,
            "trusted": trusted,
            "verify_error": verify_error,
            "chain": _chain_summary(hs.chain_der),
            "legacy_protocols": {"tls1_0": tls10, "tls1_1": tls11},
        }
        result = ScannerResult(data=data)
        f = result.findings
        days = cert["days_until_expiry"]

        if days < 0:
            f.append(
                self.finding(
                    "expired",
                    "TLS certificate has expired",
                    Severity.CRITICAL,
                    evidence=f"Certificate expired on {cert['not_after']}.",
                    recommendation="Renew the certificate now and automate renewal (e.g. ACME / Let's Encrypt).",
                )
            )
        elif days <= 14:
            f.append(
                self.finding(
                    "expiring_soon",
                    "TLS certificate expires within 14 days",
                    Severity.HIGH,
                    evidence=f"Expires {cert['not_after']} (in {days} days).",
                    recommendation="Renew now and automate certificate renewal.",
                )
            )
        elif days <= 30:
            f.append(
                self.finding(
                    "expiring",
                    "TLS certificate expires within 30 days",
                    Severity.MEDIUM,
                    evidence=f"Expires {cert['not_after']} (in {days} days).",
                    recommendation="Confirm automatic renewal is working.",
                )
            )

        if not trusted and days >= 0:
            f.append(
                self.finding(
                    "untrusted",
                    "TLS certificate is not trusted",
                    Severity.HIGH,
                    evidence=verify_error or "Certificate chain did not validate.",
                    recommendation="Use a certificate from a public CA and serve the full intermediate chain.",
                )
            )
        if not host_ok:
            f.append(
                self.finding(
                    "hostname_mismatch",
                    "Certificate does not match the domain name",
                    Severity.HIGH,
                    evidence=f"{ctx.domain} is not in: {', '.join(names[:8])}",
                    recommendation="Issue a certificate that covers this hostname.",
                )
            )
        legacy = [v for v, ok in (("TLS 1.0", tls10), ("TLS 1.1", tls11)) if ok]
        if legacy:
            f.append(
                self.finding(
                    "legacy_tls",
                    f"Deprecated protocol accepted: {', '.join(legacy)}",
                    Severity.MEDIUM,
                    evidence=f"The server completed a handshake using {', '.join(legacy)}.",
                    recommendation="Disable TLS 1.0 and 1.1; allow only TLS 1.2 and 1.3 (RFC 8996).",
                    references=["https://www.rfc-editor.org/rfc/rfc8996"],
                )
            )
        if cert["key_type"] == "RSA" and cert["key_bits"] and cert["key_bits"] < 2048:
            f.append(
                self.finding(
                    "weak_key",
                    "Weak RSA key size",
                    Severity.MEDIUM,
                    evidence=f"RSA {cert['key_bits']} bits.",
                    recommendation="Use RSA 2048+ or an ECDSA P-256 key.",
                )
            )
        if cert["signature_hash"] in ("sha1", "md5"):
            f.append(
                self.finding(
                    "weak_signature",
                    "Certificate uses a weak signature algorithm",
                    Severity.MEDIUM,
                    evidence=f"Signature hash: {cert['signature_hash']}.",
                    recommendation="Reissue the certificate with SHA-256 or better.",
                )
            )
        return result
