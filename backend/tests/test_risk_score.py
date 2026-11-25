from app.services.risk_score import calculate, risk_level


def f(fid, severity, title=None):
    return {"id": fid, "severity": severity, "title": title or fid}


def test_no_findings_scores_zero():
    assert calculate([]) == (0, [])
    assert calculate([f("x", "info")]) == (0, [])


def test_score_increases_with_severity():
    low, _ = calculate([f("a", "low")])
    med, _ = calculate([f("a", "medium")])
    high, _ = calculate([f("a", "high")])
    crit, _ = calculate([f("a", "critical")])
    assert 0 < low < med < high < crit <= 100


def test_score_saturates_at_100():
    score, _ = calculate([f(f"x{i}", "critical") for i in range(50)])
    assert score == 100


def test_heavy_factors_weigh_more():
    plain, _ = calculate([f("headers.other", "medium")])
    hsts, _ = calculate([f("security_headers.missing_hsts", "medium")])
    assert hsts > plain
    spoof, _ = calculate([f("email_security.spoofable", "high")])
    other_high, _ = calculate([f("something.high", "high")])
    assert spoof > other_high


def test_kev_cves_weigh_heavily():
    kev, factors = calculate(
        [f("cve_lookup.cve.CVE-2023-44487", "critical", "CVE-2023-44487 in Nginx (known exploited)")]
    )
    normal, _ = calculate([f("cve_lookup.cve.CVE-2021-1", "critical", "CVE-2021-1 in Nginx")])
    assert kev > normal
    assert factors[0]["label"].endswith("(known exploited)")


def test_top_factors_sorted_and_bounded():
    findings = [f(f"x{i}", s) for i, s in enumerate(["low", "critical", "medium", "high"] * 3)]
    score, factors = calculate(findings)
    assert len(factors) == 6
    assert factors[0]["severity"] == "critical"
    assert [x["points"] for x in factors] == sorted([x["points"] for x in factors], reverse=True)
    assert sum(x["points"] for x in factors) <= score + 0.5


def test_risk_level_bands():
    assert risk_level(0) == "info"
    assert risk_level(10) == "low"
    assert risk_level(30) == "medium"
    assert risk_level(50) == "high"
    assert risk_level(85) == "critical"
