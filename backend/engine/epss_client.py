"""
EPSS (Exploit Prediction Scoring System) Integration
Fetches real-world exploit probability scores from FIRST.org's free API.
Only applies to CVE-identified vulnerabilities (from Trivy SCA).
"""
import httpx
from typing import Optional
import logging

logger = logging.getLogger(__name__)

EPSS_API_URL = "https://api.first.org/data/v1/epss"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

_cisa_kev_cache: Optional[set] = None

def get_cisa_kev_catalog() -> set[str]:
    """
    Fetches the CISA Known Exploited Vulnerabilities catalog.
    Caches the result in memory for the duration of execution.
    """
    global _cisa_kev_cache
    if _cisa_kev_cache is not None:
        return _cisa_kev_cache

    try:
        logger.info("Fetching CISA KEV Catalog...")
        response = httpx.get(CISA_KEV_URL, timeout=5.0)
        response.raise_for_status()
        data = response.json()
        vulns = data.get("vulnerabilities", [])
        _cisa_kev_cache = {v["cveID"].upper() for v in vulns if "cveID" in v}
        logger.info(f"CISA KEV Catalog loaded: {len(_cisa_kev_cache)} CVEs")
        return _cisa_kev_cache
    except Exception as e:
        logger.warning(f"Failed to fetch CISA KEV Catalog: {e}")
        return set()

def is_cisa_kev(cve_id: str) -> bool:
    """Checks if a CVE ID is in the CISA KEV catalog"""
    if not cve_id or not cve_id.upper().startswith("CVE-"):
        return False
    catalog = get_cisa_kev_catalog()
    return cve_id.upper() in catalog

def get_epss_score(cve_id: str) -> Optional[float]:
    """
    Given a CVE ID (e.g. 'CVE-2023-44487'), fetches the EPSS probability
    score from FIRST.org. Returns None if unavailable.

    EPSS (Exploit Prediction Scoring System) is a data-driven effort to
    estimate the probability that a CVE will be exploited in the wild
    within the next 30 days.
    """
    if not cve_id or not cve_id.upper().startswith("CVE-"):
        return None

    try:
        params = {"cve": cve_id.upper()}
        response = httpx.get(EPSS_API_URL, params=params, timeout=4.0)
        response.raise_for_status()
        data = response.json()

        results = data.get("data", [])
        if results:
            score = float(results[0].get("epss", 0))
            logger.info(f"EPSS score for {cve_id}: {score:.4f}")
            return score

    except httpx.TimeoutException:
        logger.warning(f"EPSS API timed out for {cve_id}")
    except Exception as e:
        logger.warning(f"EPSS lookup failed for {cve_id}: {e}")

    return None


def get_epss_scores_bulk(cve_ids: list[str]) -> dict[str, float]:
    """
    Bulk-fetch EPSS scores for multiple CVEs in a single API call.
    Returns a dict mapping CVE ID -> EPSS score. Missing ones are omitted.
    """
    valid_cves = [c.upper() for c in cve_ids if c and c.upper().startswith("CVE-")]
    if not valid_cves:
        return {}

    try:
        params = {"cve": ",".join(valid_cves)}
        response = httpx.get(EPSS_API_URL, params=params, timeout=6.0)
        response.raise_for_status()
        data = response.json()

        result = {}
        for item in data.get("data", []):
            cve = item.get("cve", "").upper()
            score = item.get("epss")
            if cve and score is not None:
                result[cve] = float(score)

        logger.info(f"EPSS bulk lookup: {len(result)}/{len(valid_cves)} CVEs found")
        return result

    except Exception as e:
        logger.warning(f"EPSS bulk lookup failed: {e}")
        return {}
