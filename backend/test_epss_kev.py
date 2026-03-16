import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from engine.epss_client import is_cisa_kev, get_cisa_kev_catalog
from engine.probability_model import get_probability

def test_epss_kev():
    print("Testing CISA KEV + EPSS integration...")
    
    # 1. Test KEV catalog fetch
    catalog = get_cisa_kev_catalog()
    print(f"Loaded {len(catalog)} KEV CVEs.")
    assert len(catalog) > 0, "KEV Catalog should not be empty"

    # 2. Test known KEV (Log4Shell)
    log4shell = "CVE-2021-44228"
    is_log4_kev = is_cisa_kev(log4shell)
    print(f"{log4shell} in KEV? {is_log4_kev}")
    assert is_log4_kev == True, "Log4Shell MUST be in KEV"

    # 3. Test probability amplification fallback lookup structure
    # mock probabilities config
    probs = {"UNKNOWN": {"PUBLIC": 0.05, "INTERNAL": 0.02, "PRIVATE": 0.01}}
    
    score, source = get_probability(
        bug_type="UNKNOWN",
        exposure="public",
        probabilities=probs,
        cve_id=log4shell
    )
    print(f"\nProbability score for {log4shell}: {score:.4f} via {source}")
    assert "epss_kev" in source or "epss" in source
    
    print("\n✅ CISA KEV Amplification logic verified successfully!")

if __name__ == "__main__":
    try:
        test_epss_kev()
    except Exception as e:
        print(f"\n❌ Test Failed: {e}")
        sys.exit(1)
