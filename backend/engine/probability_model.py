import json
import logging
from typing import Dict, Optional
from engine.epss_client import get_epss_score

logger = logging.getLogger(__name__)

def load_probabilities() -> Dict:
    with open("knowledge_base/exploit_probability.json") as f:
        return json.load(f)

def get_probability(
    bug_type: str,
    exposure: str,
    probabilities: Dict,
    cve_id: Optional[str] = None,
    asset: Optional[dict] = None,
    controls_efficacy: Optional[float] = None # Added for FAIR-CAM
) -> tuple[float, str]:
    """
    Returns (probability: float, source: str).
    """
    # Attempt EPSS lookup for CVE-identified vulnerabilities
    if cve_id and cve_id.upper().startswith("CVE-"):
        from engine.epss_client import get_epss_score, is_cisa_kev
        epss_score = get_epss_score(cve_id)
        is_kev = is_cisa_kev(cve_id)
        
        if epss_score is not None:
            final_score = min(epss_score, 0.95)
            if is_kev:
                final_score = min(0.98, final_score * 1.5) # Amplify exploitability
            logger.info(f"Using EPSS score {final_score:.4f} (KEV={is_kev}) for {cve_id}")
            return final_score, f"epss_kev:{cve_id}" if is_kev else f"epss:{cve_id}"

    # Fallback to FAIR Bayesian Network instead of static rate
    try:
        from engine.fair_bn import get_bn_probability
        bn_p = get_bn_probability(exposure, bug_type, asset, controls_efficacy=controls_efficacy)
        if bn_p > 0:
            return min(bn_p, 0.95), "fair_bn"
    except Exception as e:
        logger.warning(f"BN Inference fallback failed: {e}")

    # Ultimate Fallback: knowledge-base base rates
    base_rate = probabilities.get(bug_type, probabilities.get("UNKNOWN", {})).get(
        exposure.upper(), 0.05
    )
    return base_rate, "knowledge_base"
