"""CISA KEV catalog (refreshed at most daily, stored in MongoDB) and FIRST EPSS scores."""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime, timedelta
from typing import Any

from app.core.cache import api_cache_get, api_cache_set
from app.core.ssrf_guard import SafeHttpClient

log = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_MAX_AGE = timedelta(hours=24)
KEV_MAX_BYTES = 12 * 1024 * 1024
EPSS_BATCH = 50

# Process-level copy so each scan doesn't hit MongoDB for the full catalog.
_kev_memory: tuple[float, dict[str, dict[str, Any]]] | None = None


def reset_memory() -> None:
    global _kev_memory
    _kev_memory = None


def parse_kev(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    catalog: dict[str, dict[str, Any]] = {}
    for v in doc.get("vulnerabilities", []) or []:
        cve = v.get("cveID")
        if isinstance(cve, str) and cve.startswith("CVE-"):
            catalog[cve] = {
                "date_added": v.get("dateAdded"),
                "ransomware": str(v.get("knownRansomwareCampaignUse", "")).lower() == "known",
            }
    return catalog


async def get_kev_catalog(db: Any, client: SafeHttpClient) -> dict[str, dict[str, Any]]:
    """Return {cve_id: {date_added, ransomware}}; download at most once per day."""
    global _kev_memory
    if _kev_memory and time.monotonic() - _kev_memory[0] < KEV_MAX_AGE.total_seconds():
        return _kev_memory[1]

    stored = await db.threat_intel.find_one({"_id": "kev"})
    fresh = False
    if stored:
        fetched = stored.get("fetched_at")
        if isinstance(fetched, datetime):
            if fetched.tzinfo is None:
                fetched = fetched.replace(tzinfo=UTC)
            fresh = datetime.now(UTC) - fetched < KEV_MAX_AGE
    if stored and fresh:
        catalog = {
            e["id"]: {"date_added": e.get("d"), "ransomware": e.get("r", False)} for e in stored["entries"]
        }
        _kev_memory = (time.monotonic(), catalog)
        return catalog

    try:
        resp = await client.get(KEV_URL, max_bytes=KEV_MAX_BYTES, headers={"Accept": "application/json"})
        if resp.status_code != 200:
            raise RuntimeError(f"KEV feed HTTP {resp.status_code}")
        catalog = parse_kev(resp.json())
        if not catalog:
            raise RuntimeError("KEV feed was empty")
        entries = [{"id": k, "d": v["date_added"], "r": v["ransomware"]} for k, v in catalog.items()]
        await db.threat_intel.update_one(
            {"_id": "kev"},
            {"$set": {"entries": entries, "fetched_at": datetime.now(UTC), "count": len(entries)}},
            upsert=True,
        )
    except Exception as exc:
        log.warning("KEV refresh failed: %s", type(exc).__name__)
        if stored:
            catalog = {
                e["id"]: {"date_added": e.get("d"), "ransomware": e.get("r", False)}
                for e in stored["entries"]
            }
        else:
            raise
    _kev_memory = (time.monotonic(), catalog)
    return catalog


async def get_epss(db: Any, client: SafeHttpClient, cve_ids: list[str]) -> dict[str, dict[str, float]]:
    """Return {cve_id: {"epss": float, "percentile": float}} using a 24h cache."""
    out: dict[str, dict[str, float]] = {}
    missing: list[str] = []
    for cve in dict.fromkeys(cve_ids):
        cached = await api_cache_get(db, f"epss:{cve}")
        if cached is not None:
            if cached:
                out[cve] = cached
        else:
            missing.append(cve)

    for i in range(0, len(missing), EPSS_BATCH):
        batch = missing[i : i + EPSS_BATCH]
        resp = await client.get(EPSS_URL, params={"cve": ",".join(batch)}, max_bytes=1024 * 1024)
        if resp.status_code != 200:
            log.info("EPSS HTTP %s", resp.status_code)
            continue
        got: dict[str, dict[str, float]] = {}
        for row in resp.json().get("data", []) or []:
            try:
                got[row["cve"]] = {"epss": float(row["epss"]), "percentile": float(row["percentile"])}
            except (KeyError, TypeError, ValueError):
                continue
        for cve in batch:
            # Cache misses too ({}), so unknown CVEs aren't re-queried for 24h.
            await api_cache_set(db, f"epss:{cve}", got.get(cve, {}))
        out.update(got)
    return out
