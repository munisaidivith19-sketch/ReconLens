"""Groq-written report grounded only in the scan's structured findings, with a template fallback."""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from pydantic import ValidationError

from app.config import get_settings
from app.models.report import AiReport
from app.services.risk_score import risk_level

log = logging.getLogger(__name__)

MAX_FINDINGS_FOR_AI = 40
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

SYSTEM_PROMPT = """You are a senior application-security analyst writing a report for a bug bounty \
hunter or security team. The target was scanned with PASSIVE checks only, and the user confirmed \
they are authorized to test it.

Rules (follow strictly):
- Use ONLY the facts in the provided JSON. Never invent vulnerabilities, CVE IDs, versions, \
endpoints, technologies or scores.
- If data is missing or a check failed, say so in data_gaps instead of guessing.
- Abuse scenarios must stay high-level (what an attacker could achieve), with no exploit code, \
payloads or step-by-step attack instructions.
- Next steps must stay within an authorized scope: verification, manual review, and safe testing \
the program allows.
- Prioritize by real-world impact: actively exploited (KEV) CVEs, email spoofing, expired or \
untrusted certificates, missing HTTPS/HSTS/CSP, then the rest.

Reply with ONE JSON object and nothing else, using exactly these keys:
{
  "executive_summary": string (3-6 sentences),
  "risk_level": "info" | "low" | "medium" | "high" | "critical",
  "prioritized_findings": [ {"title": string, "severity": "info|low|medium|high|critical",
      "why_it_matters": string, "abuse_scenario": string, "remediation": string} ]  (max 10),
  "attack_paths": [ {"name": string, "steps": [string], "related_findings": [string]} ]  (max 4, \
built only from the actual findings; empty list if none make sense),
  "next_steps": [string]  (max 8, for a bug hunter, within scope),
  "data_gaps": [string]
}"""


def build_facts(domain: str, doc: dict[str, Any]) -> dict[str, Any]:
    """Compact, structured facts for the model (no raw HTML, no huge lists)."""
    results = doc.get("results") or {}
    findings = doc.get("findings") or []
    tech = (results.get("tech_stack") or {}).get("technologies", [])
    cve = results.get("cve_lookup") or {}
    email = results.get("email_security") or {}
    tls = results.get("tls_check") or {}
    headers = results.get("security_headers") or {}
    subs = results.get("subdomains") or {}
    vt = results.get("virustotal") or {}
    failed = [
        f"{s['label']}: {s.get('error') or 'failed'}"
        for s in doc.get("stages", [])
        if s.get("status") == "failed"
    ]
    return {
        "domain": domain,
        "risk_score": doc.get("risk_score"),
        "top_score_factors": doc.get("score_factors", []),
        "findings": [
            {
                "id": f["id"],
                "title": f["title"],
                "severity": f["severity"],
                "evidence": (f.get("evidence") or "")[:300],
                "recommendation": (f.get("recommendation") or "")[:200],
            }
            for f in findings[:MAX_FINDINGS_FOR_AI]
        ],
        "technologies": [{"name": t["name"], "version": t["version"]} for t in tech[:25]],
        "cves": [
            {
                "id": c["id"],
                "tech": f"{c['technology']} {c['version']}",
                "cvss": c.get("cvss"),
                "kev": c.get("kev"),
                "epss": c.get("epss"),
            }
            for c in (cve.get("cves") or [])[:15]
        ],
        "email": {"spoofable": email.get("spoofable"), "verdict": email.get("verdict")} if email else None,
        "tls": {
            k: tls.get(k) for k in ("protocol", "issuer", "days_until_expiry", "trusted", "hostname_match")
        }
        if tls.get("available")
        else None,
        "waf_cdn": headers.get("waf_cdn"),
        "subdomain_count": subs.get("count"),
        "reputation": vt.get("stats") if vt.get("status") == "ok" else vt.get("message"),
        "failed_checks": failed,
        "skipped": [s["technology"] + ": " + s["reason"] for s in (cve.get("skipped") or [])[:10]],
    }


def _grounded(report: AiReport, facts_json: str) -> bool:
    """Reject reports that mention CVE IDs which are not in the facts."""
    known = {c.upper() for c in _CVE_RE.findall(facts_json)}
    mentioned = {c.upper() for c in _CVE_RE.findall(report.model_dump_json())}
    return mentioned <= known


async def _call_groq(facts_json: str) -> AiReport | None:
    from groq import AsyncGroq

    settings = get_settings()
    client = AsyncGroq(api_key=settings.GROQ_API_KEY, timeout=45.0, max_retries=1)
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": "Scan facts (JSON):\n" + facts_json},
    ]
    for attempt in range(2):  # first try + one retry on invalid output
        completion = await client.chat.completions.create(
            model=settings.GROQ_MODEL,
            messages=messages,
            response_format={"type": "json_object"},
            temperature=0.2,
            max_completion_tokens=3500,
        )
        content = completion.choices[0].message.content or ""
        try:
            report = AiReport.model_validate_json(content)
            if not _grounded(report, facts_json):
                raise ValueError("report mentions CVEs that are not in the scan facts")
            report.generated_by = f"groq:{settings.GROQ_MODEL}"
            return report
        except (ValidationError, ValueError) as exc:
            log.info("AI report attempt %d invalid: %s", attempt + 1, type(exc).__name__)
            messages.append({"role": "assistant", "content": content[:4000]})
            messages.append(
                {
                    "role": "user",
                    "content": "That reply was invalid (" + str(exc)[:300] + "). Reply again with one valid "
                    "JSON object using exactly the required keys and only facts from the input.",
                }
            )
    return None


# ------------------------------------------------------------------ template fallback

_WHY = {
    "Email security": "Attackers can send convincing phishing email that appears to come from this domain.",
    "TLS": "Visitors' connections may be intercepted or show browser warnings that erode trust.",
    "HTTP security": "Missing browser protections make attacks such as XSS, clickjacking or downgrade easier.",
    "Vulnerabilities": "Publicly known vulnerabilities give attackers a ready-made way in.",
    "Domain registration": "Losing control of the domain hands an attacker every service that uses it.",
    "Attack surface": "Every exposed host or endpoint is another place an attacker can probe.",
    "Information disclosure": "Leaked details help attackers map and target the system faster.",
    "Reputation": "Security vendors already associate the domain with malicious activity.",
    "Technology": "Exposed versions let attackers match known vulnerabilities instantly.",
    "DNS": "DNS weaknesses can enable certificate mis-issuance or service disruption.",
}
_ABUSE = {
    "Email security": "An attacker sends phishing email spoofing the domain to customers or staff.",
    "TLS": "An attacker on the network path could attempt to downgrade or intercept traffic.",
    "HTTP security": "An attacker could chain a content-injection bug with the missing protections to target users.",
    "Vulnerabilities": "An attacker matches the exposed version to public exploits and targets the component.",
    "Domain registration": "An attacker could re-register or hijack the domain if it lapses or is transferred.",
    "Attack surface": "An attacker enumerates these hosts or endpoints looking for weak authentication or old software.",
    "Information disclosure": "An attacker uses the disclosed paths or details to focus their reconnaissance.",
    "Reputation": "Users and mail providers may already block or distrust the domain.",
    "Technology": "An attacker looks up advisories for the exposed versions.",
    "DNS": "An attacker could abuse weak DNS configuration to obtain certificates or disrupt service.",
}


def template_report(domain: str, doc: dict[str, Any]) -> AiReport:
    findings = [f for f in (doc.get("findings") or []) if f.get("severity") != "info"]
    score = doc.get("risk_score") or 0
    level = risk_level(score)
    counts: dict[str, int] = {}
    for f in doc.get("findings") or []:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    count_text = ", ".join(f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low") if counts.get(s))
    top = [f["title"] for f in findings[:3]]
    summary = (
        f"Passive analysis of {domain} produced a risk score of {score}/100 ({level}). "
        + (f"Findings by severity: {count_text}. " if count_text else "No significant issues were found. ")
        + (f"The most important issues are: {'; '.join(top)}. " if top else "")
        + "This report was generated from a template because the AI writer was unavailable; "
        "every statement comes directly from the scan findings."
    )

    prioritized = [
        {
            "title": f["title"][:300],
            "severity": f["severity"],
            "why_it_matters": _WHY.get(f.get("category", ""), "This weakens the domain's security posture."),
            "abuse_scenario": _ABUSE.get(
                f.get("category", ""), "An attacker could use this during reconnaissance."
            ),
            "remediation": (f.get("recommendation") or "Review and remediate.")[:1500],
        }
        for f in findings[:10]
    ]

    ids = {f["id"] for f in doc.get("findings") or []}
    titles = {f["id"]: f["title"] for f in doc.get("findings") or []}
    paths = []
    if "email_security.spoofable" in ids:
        paths.append(
            {
                "name": "Phishing via spoofed email",
                "steps": [
                    "No enforced DMARC policy is published for the domain",
                    "Forged mail claiming to be from the domain reaches inboxes",
                    "Recipients trust the sender and act on the message",
                ],
                "related_findings": [titles["email_security.spoofable"]],
            }
        )
    kev = [f for f in doc.get("findings") or [] if "(known exploited)" in f.get("title", "")]
    if kev:
        paths.append(
            {
                "name": "Exploitation of a known-exploited vulnerability",
                "steps": [
                    "The component version is visible to anyone",
                    "The version is affected by a CVE listed in CISA KEV",
                    "Public exploitation activity makes this a likely first target",
                ],
                "related_findings": [f["title"] for f in kev[:3]],
            }
        )
    header_ids = {"security_headers.missing_csp", "security_headers.missing_clickjacking"} & ids
    if header_ids:
        paths.append(
            {
                "name": "Client-side attacks against users",
                "steps": [
                    "Browser protections (CSP / frame restrictions) are missing",
                    "Any injection bug or framing of the site has fewer barriers",
                    "Users' sessions or actions could be targeted",
                ],
                "related_findings": [titles[i] for i in sorted(header_ids)],
            }
        )

    gaps = [
        f"{s['label']} did not complete: {s.get('error') or 'failed'}"
        for s in doc.get("stages", [])
        if s.get("status") == "failed"
    ]
    vt = (doc.get("results") or {}).get("virustotal") or {}
    if vt.get("status") == "skipped":
        gaps.append(vt.get("message", "Reputation check skipped"))
    subs = (doc.get("results") or {}).get("subdomains") or {}
    if subs and not subs.get("available", True):
        gaps.append(subs.get("message", "Subdomain source unavailable"))

    next_steps = [
        "Confirm each finding manually before reporting it; passive data can be stale or wrong.",
        "Check the program's scope and rules before any active testing.",
    ]
    if kev:
        next_steps.append(
            "Verify the exact version of components with KEV-listed CVEs and report if confirmed."
        )
    if (doc.get("results") or {}).get("endpoints", {}).get("wayback", {}).get("interesting"):
        next_steps.append("Review archived endpoints manually (only if in scope) for access-control issues.")
    if subs.get("interesting"):
        next_steps.append(
            "Review non-production subdomains for exposed admin panels or default credentials (in scope only)."
        )

    return AiReport(
        executive_summary=summary[:3000],
        risk_level=level,
        prioritized_findings=prioritized,
        attack_paths=paths[:4],
        next_steps=next_steps[:8],
        data_gaps=gaps[:12],
        generated_by="template",
    )


async def generate_report(domain: str, doc: dict[str, Any]) -> AiReport:
    settings = get_settings()
    if settings.GROQ_API_KEY:
        facts_json = json.dumps(build_facts(domain, doc), separators=(",", ":"), default=str)
        try:
            report = await _call_groq(facts_json)
            if report is not None:
                return report
        except Exception as exc:  # noqa: BLE001 - any API failure falls back to the template
            log.warning("Groq report failed: %s", type(exc).__name__)
    return template_report(domain, doc)


async def ai_report_stage(db: Any, scan_id: Any, state: dict[str, Any]) -> dict[str, Any]:
    doc = await db.scans.find_one({"_id": scan_id}) or {}
    doc = {**doc, **{k: state[k] for k in ("findings", "risk_score", "score_factors") if k in state}}
    report = await generate_report(state["domain"], doc)
    return {"ai_report": report.model_dump(mode="json")}
