import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from engine.impact_model import compute_total_impact
from models.company import CompanyContext

def test_impact():
    print("Testing FAIR-MAM Impact Model integration...")
    
    company = CompanyContext(
        company_name="TestCorp",
        industry="finance",
        annual_revenue=10000000.0,
        monthly_revenue=800000.0,
        active_users=10000,
        arpu=20.0,
        engineer_hourly_cost=80.0,
        deployment_exposure="public",
        infrastructure_type="cloud",
        sensitive_data_types=["PII", "financial"],
        regulatory_frameworks=["GDPR", "PCI_DSS"],
        estimated_records_stored=50000,
        company_size="mid_size"
    )
    
    breakdown, total, params = compute_total_impact(company, "SQL_INJECTION")
    
    print("\nImpact Breakdown:")
    for k, v in breakdown.dict().items():
        print(f"  {k}: ${v:,.2f}")
        
    print(f"\nTotal Likely Impact: ${total:,.2f}")
    
    print("\nGranular Params (min/max checks):")
    print(f"  Incident Response (min): ${params['incident_response']['min']:,.2f}")
    print(f"  Incident Response (max): ${params['incident_response']['max']:,.2f}")
    
    assert params['incident_response']['min'] > 0
    assert total > 0
    print("\n✅ Impact Model Logic verified successfully!")

if __name__ == "__main__":
    try:
        test_impact()
    except Exception as e:
        print(f"\n❌ Test Failed: {e}")
        sys.exit(1)
