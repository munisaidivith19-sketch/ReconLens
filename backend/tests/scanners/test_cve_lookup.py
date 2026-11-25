from datetime import UTC, datetime, timedelta

import httpx
import pytest
import respx

from app.scanners import cve_lookup
from app.scanners.cve_lookup import CveLookupScanner, build_cpe, severity_for
from app.services import threat_intel

NVD_IP = "104.16.1.1"
CISA_IP = "104.16.1.2"
EPSS_IP = "104.16.1.3"


def nvd_item(cid, score, sev):
    return {
        "cve": {
            "id": cid,
            "vulnStatus": "Analyzed",
            "published": "2021-06-01T00:00:00.000",
            "descriptions": [{"lang": "en", "value": f"Description of {cid}"}],
            "metrics": {
                "cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": score, "baseSeverity": sev}}]
            },
        }
    }


@pytest.fixture(autouse=True)
def _reset(public_dns):
    public_dns["services.nvd.nist.gov"] = [NVD_IP]
    public_dns["www.cisa.gov"] = [CISA_IP]
    public_dns["api.first.org"] = [EPSS_IP]
    threat_intel.reset_memory()
    cve_lookup.nvd_limiter_anon.reset()
    cve_lookup.nvd_limiter_keyed.reset()


def tech(name, version, cpe):
    return {"name": name, "version": version, "cpe": cpe, "categories": [], "confidence": 100}


def test_build_cpe():
    assert build_cpe("cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", "1.18.0") == "cpe:2.3:a:f5:nginx:1.18.0"
    assert build_cpe("cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", "1.18 beta; drop") is None


def test_kev_raises_severity():
    assert severity_for("MEDIUM", 6.1, kev=False) == "medium"
    assert severity_for("MEDIUM", 6.1, kev=True) == "high"
    assert severity_for("CRITICAL", 9.8, kev=True) == "critical"
    assert severity_for(None, 7.5, kev=False) == "high"


async def test_unknown_version_reports_no_cves(ctx):
    ctx.results["tech_stack"] = {
        "technologies": [tech("Nginx", "unknown", "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*")]
    }
    with respx.mock(assert_all_called=False) as mock:
        nvd = mock.get(url__startswith=f"https://{NVD_IP}/")
        res = await CveLookupScanner().run(ctx)
    assert not nvd.called
    assert res.data["cves"] == []
    assert res.data["skipped"][0]["reason"] == "version not exposed, CVE matching not possible"
    assert [f.id for f in res.findings] == ["cve_lookup.version_unknown"]
    assert res.findings[0].severity == "info"


@respx.mock
async def test_versioned_tech_enriched_with_kev_and_epss(ctx, fake_db):
    ctx.results["tech_stack"] = {
        "technologies": [tech("Nginx", "1.18.0", "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*")]
    }
    nvd = respx.get(url__startswith=f"https://{NVD_IP}/rest/json/cves/2.0").mock(
        return_value=httpx.Response(
            200,
            json={
                "vulnerabilities": [
                    nvd_item("CVE-2021-23017", 7.7, "HIGH"),
                    nvd_item("CVE-2020-0001", 5.3, "MEDIUM"),
                    nvd_item("CVE-2019-0002", 3.1, "LOW"),
                ]
            },
        )
    )
    respx.get(f"https://{CISA_IP}/sites/default/files/feeds/known_exploited_vulnerabilities.json").mock(
        return_value=httpx.Response(
            200,
            json={
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2020-0001",
                        "dateAdded": "2022-01-10",
                        "knownRansomwareCampaignUse": "Known",
                    }
                ]
            },
        )
    )
    respx.get(url__startswith=f"https://{EPSS_IP}/data/v1/epss").mock(
        return_value=httpx.Response(
            200, json={"data": [{"cve": "CVE-2021-23017", "epss": "0.6512", "percentile": "0.98"}]}
        )
    )
    res = await CveLookupScanner().run(ctx)

    assert nvd.calls.last.request.url.params["virtualMatchString"] == "cpe:2.3:a:f5:nginx:1.18.0"
    cves = {c["id"]: c for c in res.data["cves"]}
    assert cves["CVE-2020-0001"]["kev"] is True
    assert cves["CVE-2020-0001"]["severity"] == "high"  # MEDIUM raised by KEV
    assert cves["CVE-2020-0001"]["ransomware"] is True
    assert cves["CVE-2021-23017"]["epss"] == pytest.approx(0.6512)
    assert res.data["cves"][0]["id"] == "CVE-2020-0001"  # KEV sorted first
    assert res.data["kev_count"] == 1

    ids = {f.id for f in res.findings}
    assert "cve_lookup.cve.CVE-2020-0001" in ids
    assert "cve_lookup.cve.CVE-2021-23017" in ids
    assert "cve_lookup.cves.Nginx_1.18.0" in ids  # remaining low CVE grouped

    # KEV stored for reuse and NVD response cached
    assert (await fake_db.threat_intel.find_one({"_id": "kev"}))["count"] == 1
    assert await fake_db.api_cache.find_one({"key": "nvd:cpe:2.3:a:f5:nginx:1.18.0"})


@respx.mock
async def test_nvd_cache_used(ctx, fake_db):
    await fake_db.api_cache.insert_one(
        {"key": "nvd:cpe:2.3:a:php:php:7.4.3", "value": [], "created_at": datetime.now(UTC)}
    )
    ctx.results["tech_stack"] = {"technologies": [tech("PHP", "7.4.3", "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*")]}
    nvd = respx.get(url__startswith=f"https://{NVD_IP}/")
    res = await CveLookupScanner().run(ctx)
    assert not nvd.called
    assert res.data["checked"] == [{"technology": "PHP", "version": "7.4.3", "status": "ok", "count": 0}]


@respx.mock
async def test_nvd_failure_does_not_crash(ctx):
    ctx.results["tech_stack"] = {"technologies": [tech("PHP", "7.4.3", "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*")]}
    respx.get(url__startswith=f"https://{NVD_IP}/").mock(return_value=httpx.Response(503))
    res = await CveLookupScanner().run(ctx)
    assert res.data["checked"][0]["status"] == "NVD unavailable"


@respx.mock
async def test_stale_kev_used_when_download_fails(ctx, fake_db):
    await fake_db.threat_intel.insert_one(
        {
            "_id": "kev",
            "entries": [{"id": "CVE-1", "d": "2020-01-01", "r": False}],
            "fetched_at": datetime.now(UTC) - timedelta(days=3),
        }
    )
    respx.get(url__startswith=f"https://{CISA_IP}/").mock(return_value=httpx.Response(500))
    catalog = await threat_intel.get_kev_catalog(fake_db, ctx.client)
    assert "CVE-1" in catalog
