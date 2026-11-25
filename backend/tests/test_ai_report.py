import json

import httpx
import pytest
import respx

from app.config import get_settings
from app.services import ai_report
from app.services.ai_report import build_facts, generate_report, template_report

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

DOC = {
    "risk_score": 62,
    "score_factors": [
        {"label": "Domain can be spoofed in phishing emails", "points": 20, "severity": "high"}
    ],
    "stages": [
        {"name": "subdomains", "label": "Subdomains", "status": "failed", "error": "timed out"},
        {"name": "dns_records", "label": "DNS", "status": "done", "error": None},
    ],
    "findings": [
        {
            "id": "email_security.spoofable",
            "title": "Domain can be spoofed in phishing emails",
            "severity": "high",
            "category": "Email security",
            "evidence": "No DMARC",
            "recommendation": "Publish DMARC p=reject",
        },
        {
            "id": "cve_lookup.cve.CVE-2023-44487",
            "title": "CVE-2023-44487 in Nginx 1.18.0 (known exploited)",
            "severity": "critical",
            "category": "Vulnerabilities",
            "evidence": "CVSS 7.5",
            "recommendation": "Upgrade",
        },
        {
            "id": "security_headers.missing_csp",
            "title": "Content-Security-Policy header missing",
            "severity": "medium",
            "category": "HTTP security",
            "evidence": "",
            "recommendation": "Add CSP",
        },
        {"id": "dns_records.no_ipv6", "title": "No IPv6", "severity": "info", "category": "DNS"},
    ],
    "results": {
        "cve_lookup": {
            "cves": [
                {
                    "id": "CVE-2023-44487",
                    "technology": "Nginx",
                    "version": "1.18.0",
                    "cvss": 7.5,
                    "kev": True,
                    "epss": 0.9,
                }
            ]
        },
        "virustotal": {"status": "skipped", "message": "reputation check skipped: rate limit"},
    },
}

VALID = {
    "executive_summary": "example.com is spoofable and runs an nginx version affected by CVE-2023-44487.",
    "risk_level": "high",
    "prioritized_findings": [
        {
            "title": "Email spoofing",
            "severity": "high",
            "why_it_matters": "Phishing.",
            "abuse_scenario": "Forged mail from the domain.",
            "remediation": "Enforce DMARC.",
        }
    ],
    "attack_paths": [
        {"name": "Phishing", "steps": ["Spoof", "Deliver"], "related_findings": ["Email spoofing"]}
    ],
    "next_steps": ["Verify DMARC"],
    "data_gaps": ["Subdomains timed out"],
}


def groq_response(content: str) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "id": "chatcmpl-1",
            "object": "chat.completion",
            "created": 0,
            "model": "openai/gpt-oss-120b",
            "choices": [
                {"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": content}}
            ],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        },
    )


@pytest.fixture
def groq_key(monkeypatch):
    monkeypatch.setattr(get_settings(), "GROQ_API_KEY", "gsk_test")
    monkeypatch.setattr(get_settings(), "GROQ_MODEL", "openai/gpt-oss-120b")


async def test_no_key_uses_template():
    report = await generate_report("example.com", DOC)
    assert report.generated_by == "template"
    assert report.risk_level == "high"
    assert report.prioritized_findings[0].title == "Domain can be spoofed in phishing emails"
    assert any("Subdomains" in g for g in report.data_gaps)
    assert any("rate limit" in g for g in report.data_gaps)
    names = {p.name for p in report.attack_paths}
    assert "Phishing via spoofed email" in names
    assert "Exploitation of a known-exploited vulnerability" in names


@respx.mock
async def test_valid_groq_report(groq_key):
    route = respx.post(GROQ_URL).mock(return_value=groq_response(json.dumps(VALID)))
    report = await generate_report("example.com", DOC)
    assert report.generated_by == "groq:openai/gpt-oss-120b"
    assert report.executive_summary.startswith("example.com")
    body = json.loads(route.calls.last.request.content)
    assert body["response_format"] == {"type": "json_object"}
    assert body["messages"][0]["role"] == "system"
    assert "Never invent" in body["messages"][0]["content"]
    facts = body["messages"][1]["content"]
    assert "CVE-2023-44487" in facts
    assert "<html" not in facts


@respx.mock
async def test_retry_once_on_invalid_output(groq_key):
    route = respx.post(GROQ_URL).mock(
        side_effect=[groq_response("not json"), groq_response(json.dumps(VALID))]
    )
    report = await generate_report("example.com", DOC)
    assert route.call_count == 2
    assert report.generated_by.startswith("groq:")


@respx.mock
async def test_falls_back_after_two_invalid(groq_key):
    route = respx.post(GROQ_URL).mock(return_value=groq_response('{"executive_summary": "x"}'))
    report = await generate_report("example.com", DOC)
    assert route.call_count == 2
    assert report.generated_by == "template"


@respx.mock
async def test_hallucinated_cve_rejected(groq_key):
    bad = {**VALID, "executive_summary": "Also vulnerable to CVE-2099-12345."}
    respx.post(GROQ_URL).mock(return_value=groq_response(json.dumps(bad)))
    report = await generate_report("example.com", DOC)
    assert report.generated_by == "template"


@respx.mock
async def test_api_error_falls_back(groq_key):
    respx.post(GROQ_URL).mock(return_value=httpx.Response(500, json={"error": {"message": "down"}}))
    report = await generate_report("example.com", DOC)
    assert report.generated_by == "template"


def test_facts_are_compact():
    facts = build_facts("example.com", DOC)
    assert facts["failed_checks"] == ["Subdomains: timed out"]
    assert facts["cves"][0]["kev"] is True
    assert len(json.dumps(facts)) < 5000


def test_template_never_mentions_unknown_cves():
    report = template_report("example.com", DOC)
    text = report.model_dump_json()
    assert set(ai_report._CVE_RE.findall(text)) <= {"CVE-2023-44487"}
