"""Lookalike (typosquat) domains that are already registered: the phishing view of the domain.

Generates common misspellings of the registered domain (missing, doubled, swapped or neighbouring
keys, look-alike characters, hyphens, other TLDs and phishing-style words) and checks which of
them exist in public DNS. Only DNS lookups are made; the lookalike domains are never visited.
"""

from __future__ import annotations

import asyncio

from app.models.finding import Severity
from app.scanners import base
from app.scanners.base import ScanContext, Scanner, ScannerResult

MAX_CANDIDATES = 180
PARALLEL = 12
TIME_BUDGET = 30.0
MAX_REPORTED = 60

# Second-level labels used under country-code TLDs (example.co.uk, example.edu.in).
SECOND_LEVEL = {
    "co",
    "com",
    "net",
    "org",
    "ac",
    "edu",
    "gov",
    "gob",
    "or",
    "ne",
    "go",
    "nic",
    "res",
    "ltd",
    "plc",
}
ALT_TLDS = (
    "com",
    "net",
    "org",
    "co",
    "io",
    "info",
    "biz",
    "xyz",
    "online",
    "site",
    "app",
    "shop",
    "live",
    "in",
    "us",
)
PHISH_WORDS = (
    "login",
    "secure",
    "account",
    "support",
    "verify",
    "auth",
    "portal",
    "mail",
    "pay",
    "help",
    "app",
)
HOMOGLYPHS = {
    "o": ("0",),
    "0": ("o",),
    "l": ("1", "i"),
    "i": ("1", "l"),
    "1": ("l", "i"),
    "e": ("3",),
    "a": ("4",),
    "s": ("5",),
    "g": ("q",),
    "q": ("g",),
    "m": ("rn",),
    "w": ("vv",),
    "d": ("cl",),
}
MULTI_HOMOGLYPHS = {"rn": "m", "vv": "w", "cl": "d"}
KEYBOARD = {
    "q": "wa",
    "w": "qeas",
    "e": "wrsd",
    "r": "etdf",
    "t": "ryfg",
    "y": "tugh",
    "u": "yihj",
    "i": "uojk",
    "o": "ipkl",
    "p": "ol",
    "a": "qwsz",
    "s": "awedxz",
    "d": "serfcx",
    "f": "drtgvc",
    "g": "ftyhbv",
    "h": "gyujnb",
    "j": "huikmn",
    "k": "jiolm",
    "l": "kop",
    "z": "asx",
    "x": "zsdc",
    "c": "xdfv",
    "v": "cfgb",
    "b": "vghn",
    "n": "bhjm",
    "m": "njk",
}


def split_registrable(name: str) -> tuple[str, str]:
    """('example', 'co.uk') for example.co.uk; best effort without the public suffix list."""
    labels = name.lower().rstrip(".").split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in SECOND_LEVEL:
        return labels[-3], ".".join(labels[-2:])
    if len(labels) >= 2:
        return labels[-2], labels[-1]
    return labels[0], ""


def _valid(label: str) -> bool:
    return (
        1 <= len(label) <= 63
        and not label.startswith("-")
        and not label.endswith("-")
        and "--" not in label[2:4]
    )


def permutations(label: str, suffix: str) -> list[tuple[str, str]]:
    """(domain, technique) pairs, most phishing-relevant techniques first, without duplicates."""
    out: dict[str, str] = {}
    original = f"{label}.{suffix}"

    def add(lbl: str, technique: str, sfx: str = suffix) -> None:
        lbl = lbl.lower()
        if _valid(lbl) and all(c.isalnum() or c == "-" for c in lbl):
            dom = f"{lbl}.{sfx}"
            if dom != original and dom not in out:
                out[dom] = technique

    tld_root = suffix.split(".")[-1]
    for tld in ALT_TLDS:
        if tld != tld_root and tld != suffix:
            add(label, "other TLD", tld)
    for i, ch in enumerate(label):
        for alt in HOMOGLYPHS.get(ch, ()):
            add(label[:i] + alt + label[i + 1 :], "look-alike character")
    for multi, single in MULTI_HOMOGLYPHS.items():
        if multi in label:
            add(label.replace(multi, single, 1), "look-alike character")
    for word in PHISH_WORDS:
        add(f"{label}-{word}", "added word")
        add(f"{word}-{label}", "added word")
        add(f"{label}{word}", "added word")
    for i in range(len(label)):
        add(label[:i] + label[i + 1 :], "missing letter")
    for i in range(len(label) - 1):
        add(label[:i] + label[i + 1] + label[i] + label[i + 2 :], "swapped letters")
    for i, ch in enumerate(label):
        add(label[: i + 1] + ch + label[i + 1 :], "doubled letter")
    for i in range(1, len(label)):
        add(label[:i] + "-" + label[i:], "hyphen")
    for i, ch in enumerate(label):
        for alt in KEYBOARD.get(ch, ""):
            add(label[:i] + alt + label[i + 1 :], "keyboard typo")
    return list(out.items())


class LookalikesScanner(Scanner):
    name = "lookalikes"
    label = "Lookalike domains"
    category = "Brand protection"
    timeout = 45.0
    depends_on = ("whois_rdap",)

    async def run(self, ctx: ScanContext) -> ScannerResult:
        registrable = (ctx.results.get("whois_rdap") or {}).get("registrable_domain") or ctx.domain
        label, suffix = split_registrable(registrable)
        if not suffix or len(label) < 3:
            return ScannerResult(data={"base": registrable, "checked": 0, "registered": [], "generated": 0})
        candidates = permutations(label, suffix)
        generated = len(candidates)
        candidates = candidates[:MAX_CANDIDATES]

        limit = asyncio.Semaphore(PARALLEL)
        registered: list[dict] = []
        checked = 0

        async def q(name: str, rdtype: str) -> list[str]:
            try:
                return await base.dns_query(name, rdtype)
            except base.DnsLookupError:
                return []

        async def check(domain: str, technique: str) -> None:
            nonlocal checked
            async with limit:
                exists = await base.dns_name_exists(domain)
                checked += 1
                if not exists:
                    return
                ips, mx = await asyncio.gather(q(domain, "A"), q(domain, "MX"))
            registered.append(
                {
                    "domain": domain,
                    "technique": technique,
                    "ips": sorted(ips)[:4],
                    "mx": sorted(m.split()[-1].rstrip(".") for m in mx if m.split())[:3],
                }
            )

        tasks = [asyncio.create_task(check(d, t)) for d, t in candidates]
        timed_out = False
        if tasks:
            _done, pending = await asyncio.wait(tasks, timeout=TIME_BUDGET)
            for t in pending:
                t.cancel()
            timed_out = bool(pending)

        # Mail-capable ones first: those can send and receive phishing email.
        registered.sort(key=lambda r: (not r["mx"], not r["ips"], r["domain"]))
        data = {
            "base": f"{label}.{suffix}",
            "generated": generated,
            "checked": checked,
            "timed_out": timed_out,
            "registered": registered[:MAX_REPORTED],
            "registered_count": len(registered),
            "with_mail": sum(1 for r in registered if r["mx"]),
        }
        result = ScannerResult(data=data)
        if registered:
            mail = [r for r in registered if r["mx"]]
            result.findings.append(
                self.finding(
                    "registered",
                    f"{len(registered)} lookalike domain(s) are registered"
                    + (f", {len(mail)} with mail servers" if mail else ""),
                    Severity.LOW if mail else Severity.INFO,
                    evidence=", ".join(f"{r['domain']} ({r['technique']})" for r in registered[:10]),
                    recommendation=(
                        "Check who owns each domain. Lookalikes with MX records can send and receive phishing "
                        "email in your name. Register the most likely variants defensively, enforce DMARC so "
                        "your own domain cannot be spoofed, and report malicious ones to the registrar."
                    ),
                    references=["https://attack.mitre.org/techniques/T1583/001/"],
                )
            )
        return result
