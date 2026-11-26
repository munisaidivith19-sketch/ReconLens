"""Email security: SPF, DMARC and DKIM (common selectors), plus MTA-STS, TLS-RPT and BIMI.

Everything is DNS, except the MTA-STS policy file, which is fetched from
https://mta-sts.<domain>/.well-known/mta-sts.txt only when the _mta-sts record says one exists
(the same request every sending mail server makes).
"""

import asyncio
import re
import secrets

import httpx

from app.core.ssrf_guard import BlockedTargetError, ResponseTooLargeError
from app.models.finding import Severity
from app.scanners import base
from app.scanners.base import ScanContext, Scanner, ScannerResult, describe_error

DKIM_SELECTORS = (
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "k2",
    "s1",
    "s2",
    "mail",
    "dkim",
    "smtp",
    "mandrill",
    "everlytickey1",
    "mxvault",
    "zoho",
    "protonmail",
    "sendgrid",
    "amazonses",
    "fm1",
    "mailjet",
)


def is_dkim_key(record: str) -> bool:
    """A usable DKIM public key: has a non-empty p= tag (empty p= means revoked)."""
    pub = _tag(record, "p")
    return bool(pub) and ("v=dkim1" in record.lower() or "k=" in record.lower() or len(pub) > 40)


def _tag(record: str, tag: str) -> str | None:
    m = re.search(rf"(?:^|;)\s*{tag}\s*=\s*([^;]+)", record, re.IGNORECASE)
    return m.group(1).strip() if m else None


def parse_mta_sts_policy(text: str) -> dict:
    """Parse the key: value lines of an MTA-STS policy file (RFC 8461)."""
    policy: dict = {"version": None, "mode": None, "max_age": None, "mx": []}
    for raw in text.splitlines()[:50]:
        if ":" not in raw:
            continue
        key, value = (x.strip() for x in raw.split(":", 1))
        key = key.lower()
        if key == "version":
            policy["version"] = value
        elif key == "mode":
            policy["mode"] = value.lower()
        elif key == "max_age":
            policy["max_age"] = int(value) if value.isdigit() else None
        elif key == "mx" and len(policy["mx"]) < 10:
            policy["mx"].append(value)
    return policy


def analyze_spf(records: list[str]) -> dict:
    spf = [r for r in records if r.lower().startswith("v=spf1")]
    issues: list[str] = []
    if not spf:
        return {"record": None, "all_qualifier": None, "lookups": 0, "issues": ["No SPF record"]}
    if len(spf) > 1:
        issues.append("Multiple SPF records (this is a permanent error; receivers ignore SPF)")
    rec = spf[0]
    m = re.search(r"(?:^|\s)([+\-~?]?)all(?:\s|$)", rec, re.IGNORECASE)
    qualifier = (m.group(1) or "+") if m else None
    lookups = len(re.findall(r"\b(include:|a\b|a:|mx\b|mx:|ptr|exists:|redirect=)", rec, re.IGNORECASE))
    if qualifier is None and "redirect=" not in rec.lower():
        issues.append("No 'all' mechanism; unlisted senders are not rejected")
    elif qualifier == "+":
        issues.append("'+all' allows any server on the internet to send as this domain")
    elif qualifier == "?":
        issues.append("'?all' (neutral) gives no protection")
    if lookups > 10:
        issues.append(f"About {lookups} DNS-lookup mechanisms (limit is 10)")
    return {"record": rec[:500], "all_qualifier": qualifier, "lookups": lookups, "issues": issues}


def analyze_dmarc(records: list[str]) -> dict:
    dmarc = [r for r in records if r.lower().startswith("v=dmarc1")]
    if not dmarc:
        return {"record": None, "policy": None, "pct": None, "rua": [], "issues": ["No DMARC record"]}
    rec = dmarc[0]
    policy = (_tag(rec, "p") or "").lower() or None
    pct_raw = _tag(rec, "pct")
    pct = int(pct_raw) if pct_raw and pct_raw.isdigit() else 100
    rua = [u.strip() for u in (_tag(rec, "rua") or "").split(",") if u.strip()]
    issues = []
    if policy not in ("none", "quarantine", "reject"):
        issues.append("Missing or invalid policy (p=) tag")
    elif policy == "none":
        issues.append("Policy is p=none (monitoring only); spoofed mail is still delivered")
    if pct < 100 and policy in ("quarantine", "reject"):
        issues.append(f"Policy applies to only {pct}% of messages")
    if not rua:
        issues.append("No aggregate report address (rua); spoofing attempts go unnoticed")
    return {"record": rec[:500], "policy": policy, "pct": pct, "rua": rua[:5], "issues": issues}


class EmailSecurityScanner(Scanner):
    name = "email_security"
    label = "Email security (SPF, DMARC, DKIM)"
    category = "Email security"
    timeout = 30.0

    async def _txt(self, name: str) -> list[str]:
        try:
            return await base.dns_query(name, "TXT")
        except base.DnsLookupError:
            return []

    async def _mta_sts(self, ctx: ScanContext, domain: str) -> dict:
        record = next(
            (r for r in await self._txt(f"_mta-sts.{domain}") if r.lower().startswith("v=stsv1")), None
        )
        info: dict = {"record": record, "policy": None, "policy_error": None}
        if not record:
            return info
        url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
        try:
            resp = await ctx.client.get(
                url, headers={"Accept": "text/plain"}, max_bytes=64 * 1024, timeout=10.0
            )
        except (httpx.HTTPError, ResponseTooLargeError, BlockedTargetError, TimeoutError) as exc:
            info["policy_error"] = describe_error(exc)
            return info
        if resp.status_code != 200:
            info["policy_error"] = f"HTTP {resp.status_code}"
            return info
        policy = parse_mta_sts_policy(resp.text)
        if policy["version"] != "STSv1" or not policy["mode"]:
            info["policy_error"] = "policy file is not a valid STSv1 policy"
            return info
        info["policy"] = policy
        return info

    async def _hardening(self, ctx: ScanContext, domain: str) -> dict:
        mta_sts, tls_rpt, bimi = await asyncio.gather(
            self._mta_sts(ctx, domain),
            self._txt(f"_smtp._tls.{domain}"),
            self._txt(f"default._bimi.{domain}"),
        )
        tls_rpt_rec = next((r for r in tls_rpt if r.lower().startswith("v=tlsrptv1")), None)
        bimi_rec = next((r for r in bimi if r.lower().startswith("v=bimi1")), None)
        return {
            "mta_sts": mta_sts,
            "tls_rpt": {"record": tls_rpt_rec, "rua": _tag(tls_rpt_rec, "rua") if tls_rpt_rec else None},
            "bimi": {
                "record": bimi_rec,
                "logo": _tag(bimi_rec, "l") if bimi_rec else None,
                "certificate": _tag(bimi_rec, "a") if bimi_rec else None,
            },
        }

    async def run(self, ctx: ScanContext) -> ScannerResult:
        domain = ctx.domain
        try:
            mx = await base.dns_query(domain, "MX")
        except base.DnsLookupError:
            mx = []
        spf = analyze_spf(await self._txt(domain))

        # DMARC: the organizational domain's record applies to subdomains without their own.
        dmarc = analyze_dmarc(await self._txt(f"_dmarc.{domain}"))
        inherited_from = None
        labels = domain.split(".")
        if dmarc["record"] is None and len(labels) > 2:
            for i in range(1, len(labels) - 1):
                parent = ".".join(labels[i:])
                parent_dmarc = analyze_dmarc(await self._txt(f"_dmarc.{parent}"))
                if parent_dmarc["record"]:
                    sp = _tag(parent_dmarc["record"], "sp")
                    if sp:
                        parent_dmarc["policy"] = sp.lower()
                    dmarc, inherited_from = parent_dmarc, parent
                    break
        dmarc["inherited_from"] = inherited_from

        sem = asyncio.Semaphore(5)

        async def has_key(sel: str) -> bool:
            async with sem:
                recs = await self._txt(f"{sel}._domainkey.{domain}")
            return any(is_dkim_key(r) for r in recs)

        # A wildcard *._domainkey record would make every selector look valid.
        wildcard = await has_key(f"rl-{secrets.token_hex(6)}")
        found: list[str] = []
        if not wildcard:
            hits = await asyncio.gather(*(has_key(s) for s in DKIM_SELECTORS))
            found = [s for s, ok in zip(DKIM_SELECTORS, hits, strict=True) if ok]

        hardening = await self._hardening(ctx, domain) if mx else None

        policy = dmarc["policy"]
        enforcing = policy in ("quarantine", "reject") and (dmarc["pct"] or 100) == 100
        spf_strict = spf["all_qualifier"] in ("-", "~")
        if enforcing and spf["record"]:
            level, spoofable = "protected", False
            verdict = (
                f"Protected: DMARC p={policy} is enforced, so receivers quarantine or reject mail that "
                "fails SPF/DKIM alignment."
            )
        elif enforcing:
            level, spoofable = "partial", False
            verdict = f"Mostly protected: DMARC p={policy} is enforced, but there is no SPF record."
        elif policy == "none":
            level, spoofable = "spoofable", True
            verdict = (
                "Spoofable: DMARC is in monitoring mode (p=none), so mail forged as this domain is still "
                "delivered to inboxes."
            )
        else:
            level, spoofable = "spoofable", True
            verdict = (
                "Spoofable: there is no enforced DMARC policy"
                + ("" if spf_strict else " and SPF does not reject unlisted senders")
                + ", so attackers can send phishing email that appears to come from this domain."
            )

        data = {
            "spf": spf,
            "dmarc": dmarc,
            "dkim": {
                "selectors_found": found,
                "selectors_checked": list(DKIM_SELECTORS),
                "wildcard": wildcard,
            },
            "mx": sorted(mx)[:20],
            "hardening": hardening,
            "spoofable": spoofable,
            "verdict": verdict,
            "verdict_level": level,
        }
        result = ScannerResult(data=data)
        f = result.findings

        if spoofable:
            f.append(
                self.finding(
                    "spoofable",
                    "Domain can be spoofed in phishing emails",
                    Severity.HIGH,
                    evidence=verdict,
                    recommendation=(
                        "Publish SPF ending in -all (or ~all), sign mail with DKIM, then move DMARC from "
                        "p=none to p=quarantine and finally p=reject. Non-sending domains should publish "
                        "'v=spf1 -all' and 'v=DMARC1; p=reject'."
                    ),
                    references=["https://dmarc.org/overview/"],
                )
            )
        if spf["record"] is None:
            f.append(
                self.finding(
                    "no_spf",
                    "No SPF record",
                    Severity.MEDIUM,
                    evidence="No TXT record starting with v=spf1.",
                    recommendation="Publish an SPF record listing your legitimate mail senders, ending in -all.",
                )
            )
        elif spf["all_qualifier"] == "+":
            f.append(
                self.finding(
                    "spf_plus_all",
                    "SPF allows every server (+all)",
                    Severity.CRITICAL,
                    evidence=spf["record"],
                    recommendation="Replace +all with -all.",
                )
            )
        elif spf["issues"]:
            f.append(
                self.finding(
                    "spf_issues",
                    "SPF record has weaknesses",
                    Severity.LOW,
                    evidence="; ".join(spf["issues"]),
                    recommendation="Fix the listed SPF issues.",
                )
            )
        if dmarc["record"] is None:
            f.append(
                self.finding(
                    "no_dmarc",
                    "No DMARC record",
                    Severity.MEDIUM,
                    evidence=f"No TXT record at _dmarc.{domain}.",
                    recommendation="Publish 'v=DMARC1; p=quarantine; rua=mailto:dmarc@your-domain' and tighten later.",
                )
            )
        elif policy == "none":
            f.append(
                self.finding(
                    "dmarc_none",
                    "DMARC policy is p=none (monitoring only)",
                    Severity.MEDIUM,
                    evidence=dmarc["record"],
                    recommendation="Move to p=quarantine, then p=reject, once reports show legitimate mail passes.",
                )
            )
        if mx and not found and not wildcard:
            f.append(
                self.finding(
                    "no_dkim_found",
                    "No DKIM key found on common selectors",
                    Severity.INFO,
                    evidence=f"Checked {len(DKIM_SELECTORS)} common selectors.",
                    recommendation=(
                        "DKIM may use a custom selector. If not, enable DKIM signing with your mail provider."
                    ),
                )
            )
        if hardening:
            self._hardening_findings(result, hardening, domain)
        return result

    def _hardening_findings(self, result: ScannerResult, h: dict, domain: str) -> None:
        sts = h["mta_sts"]
        if not sts["record"]:
            result.findings.append(
                self.finding(
                    "no_mta_sts",
                    "No MTA-STS policy: inbound mail can be downgraded to plaintext",
                    Severity.LOW,
                    evidence=f"No v=STSv1 TXT record at _mta-sts.{domain}.",
                    recommendation=(
                        f"Publish an MTA-STS policy at https://mta-sts.{domain}/.well-known/mta-sts.txt and a "
                        f"_mta-sts.{domain} TXT record, start in mode: testing, then switch to mode: enforce."
                    ),
                    references=["https://www.rfc-editor.org/rfc/rfc8461"],
                )
            )
        elif sts["policy_error"]:
            result.findings.append(
                self.finding(
                    "mta_sts_broken",
                    "MTA-STS is announced but the policy file is unavailable",
                    Severity.LOW,
                    evidence=f"_mta-sts record: {sts['record']}. Policy: {sts['policy_error']}.",
                    recommendation=(
                        f"Serve a valid policy at https://mta-sts.{domain}/.well-known/mta-sts.txt over HTTPS with "
                        "a trusted certificate, or remove the TXT record."
                    ),
                    references=["https://www.rfc-editor.org/rfc/rfc8461#section-3.2"],
                )
            )
        elif sts["policy"] and sts["policy"]["mode"] != "enforce":
            result.findings.append(
                self.finding(
                    "mta_sts_testing",
                    f"MTA-STS is in {sts['policy']['mode']} mode",
                    Severity.INFO,
                    evidence=f"mode: {sts['policy']['mode']}",
                    recommendation="Once TLS reports show no failures, switch the policy to mode: enforce.",
                )
            )
        if not h["tls_rpt"]["record"]:
            result.findings.append(
                self.finding(
                    "no_tls_rpt",
                    "No TLS-RPT record for mail delivery reports",
                    Severity.INFO,
                    evidence=f"No v=TLSRPTv1 TXT record at _smtp._tls.{domain}.",
                    recommendation=(
                        f"Publish '_smtp._tls.{domain} TXT \"v=TLSRPTv1; rua=mailto:tls-reports@{domain}\"' to "
                        "receive reports of failed TLS connections to your mail servers."
                    ),
                    references=["https://www.rfc-editor.org/rfc/rfc8460"],
                )
            )
