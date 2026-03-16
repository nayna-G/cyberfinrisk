import json
from models.company import CompanyContext, AssetContext
from models.risk_result import ImpactBreakdown, GeminiAnalysis
from typing import Optional

def compute_total_impact(company: CompanyContext, bug_type: str, gemini_result: Optional[GeminiAnalysis] = None, asset: Optional[AssetContext] = None):
    with open("knowledge_base/breach_costs.json")     as f: bc  = json.load(f)
    with open("knowledge_base/regulatory_models.json") as f: rm  = json.load(f)
    with open("knowledge_base/downtime_estimates.json") as f: de  = json.load(f)
    with open("knowledge_base/bug_taxonomy.json")     as f: tax = json.load(f)

    bug_info = tax.get(bug_type, {})
    impact_params = {}

    def get_range(val_or_obj):
        """Helper to get min, likely, max from number or dict"""
        if isinstance(val_or_obj, dict):
            return val_or_obj.get("min", val_or_obj.get("likely", 0.0)), val_or_obj.get("likely", 0.0), val_or_obj.get("max", val_or_obj.get("likely", 0.0))
        return float(val_or_obj), float(val_or_obj), float(val_or_obj)

    # 1. Data breach cost
    if bug_info.get("data_exfiltration", False):
        cpr_obj = bc["cost_per_record_by_industry"].get(
            company.industry.lower(), bc["cost_per_record_by_industry"]["default"])
        cpr_min, cpr_likely, cpr_max = get_range(cpr_obj)
        
        scope_multiplier = 0.20 # baseline
        if gemini_result:
            if gemini_result.data_scope == "full_database":
                scope_multiplier = 1.0
            elif gemini_result.data_scope == "single_user_record":
                 scope_multiplier = 0.0001
            elif gemini_result.data_scope == "none":
                 scope_multiplier = 0.0
                 
        if company.system_role in ["framework", "infrastructure"] and not gemini_result:
             scope_multiplier = 0.05

        records = int(company.estimated_records_stored * scope_multiplier)
        data_breach = records * cpr_likely
        impact_params["data_breach"] = {
            "min": records * cpr_min,
            "likely": records * cpr_likely,
            "max": records * cpr_max
        }
    else:
        data_breach = 0.0
        impact_params["data_breach"] = {"min": 0, "likely": 0, "max": 0}

    # 2. Incident response
    incident_obj = bc["incident_response_cost"].get(company.company_size, 100000)
    inc_min, inc_likely, inc_max = get_range(incident_obj)
    data_breach = data_breach # Keep for breakdown
    impact_params["incident_response"] = {
        "min": inc_min,
        "likely": inc_likely,
        "max": inc_max
    }

    # 3. Downtime
    hours_obj = de["downtime_hours_by_bug_type"].get(bug_type, 2)
    h_min, h_likely, h_max = get_range(hours_obj)
    
    cph_obj = company.estimated_downtime_cost_per_hour or bc["downtime_cost_per_hour"].get(company.company_size, 12000)
    if asset and "value_per_hour" in asset.description.lower():
         cph_obj = asset.estimated_value_usd / 24 if "day" in asset.description.lower() else company.estimated_downtime_cost_per_hour or bc["downtime_cost_per_hour"].get(company.company_size, 12000)
         
    cph_min, cph_likely, cph_max = get_range(cph_obj)
    
    downtime = h_likely * cph_likely
    impact_params["downtime"] = {
        "min": h_min * cph_min,
        "likely": h_likely * cph_likely,
        "max": h_max * cph_max
    }

    # 4. Regulatory fines
    reg_min = reg_likely = reg_max = 0.0
    fw  = [r.upper() for r in company.regulatory_frameworks]
    dt  = [d.upper() for d in (asset.sensitive_data_types if asset else company.sensitive_data_types)]
    
    if "GDPR" in fw or "PII" in dt:
        fine = min(company.annual_revenue * rm["GDPR"]["fine_percentage_of_arr"], rm["GDPR"]["max_fine_usd"])
        reg_min += fine; reg_likely += fine; reg_max += fine  # GDPR is fixed logic usually
        
    if "PCI_DSS" in fw or "FINANCIAL" in dt:
        pci_obj = rm["PCI_DSS"]["avg_fine"]
        p_min, p_likely, p_max = get_range(pci_obj)
        reg_min += p_min; reg_likely += p_likely; reg_max += p_max
        
    if "HIPAA" in fw or "HEALTH" in dt:
        fine = rm["HIPAA"]["max_annual"]
        reg_min += fine; reg_likely += fine; reg_max += fine

    reg = reg_likely
    impact_params["regulatory"] = {
        "min": reg_min,
        "likely": reg_likely,
        "max": reg_max
    }

    # 5. Churn / reputation
    if any(d in dt for d in ["FINANCIAL", "HEALTH"]):
         cr_obj = bc["churn_rate_after_breach"]["high_sensitivity"]
    elif "PII" in dt:
         cr_obj = bc["churn_rate_after_breach"]["medium_sensitivity"]
    else:
         cr_obj = bc["churn_rate_after_breach"]["low_sensitivity"]
         
    cr_min, cr_likely, cr_max = get_range(cr_obj)
    reputation = company.active_users * cr_likely * company.arpu * 12
    impact_params["reputation"] = {
        "min": company.active_users * cr_min * company.arpu * 12,
        "likely": company.active_users * cr_likely * company.arpu * 12,
        "max": company.active_users * cr_max * company.arpu * 12
    }

    breakdown = ImpactBreakdown(
        data_breach_cost=round(impact_params["data_breach"]["likely"], 2),
        incident_response_cost=round(impact_params["incident_response"]["likely"], 2),
        downtime_cost=round(impact_params["downtime"]["likely"], 2),
        regulatory_penalty=round(impact_params["regulatory"]["likely"], 2),
        reputation_damage=round(impact_params["reputation"]["likely"], 2)
    )
    
    total = sum(impact_params[k]["likely"] for k in impact_params)
    
    # 7. Environment & Exposure Adjustment
    if asset:
        # Discount factor
        discount = 1.0
        if asset.environment.lower() in ("dev", "test"):
            discount = 0.01
            breakdown.data_breach_cost *= 0.01
            breakdown.regulatory_penalty = 0  # No fines for dev data breach usually
            breakdown.reputation_damage = 0
            breakdown.incident_response_cost *= 0.1
            
            # Apply discounts to impact_params too
            for k in impact_params:
                impact_params[k]["min"] *= 0.01
                impact_params[k]["likely"] *= 0.01
                impact_params[k]["max"] *= 0.01
            # Special manual overrides applied to breakdown
            impact_params["regulatory"] = {"min": 0, "likely": 0, "max": 0}
            impact_params["reputation"] = {"min": 0, "likely": 0, "max": 0}
            impact_params["incident_response"] = {k: v * 0.1 for k, v in impact_params["incident_response"].items()}
            
        elif asset.environment.lower() == "staging":
             discount = 0.1
             for k in breakdown.dict().keys():
                 setattr(breakdown, k, getattr(breakdown, k) * 0.1)
             for k in impact_params:
                 for pk in impact_params[k]:
                     impact_params[k][pk] *= 0.1

        total = sum(impact_params[k]["likely"] for k in impact_params)

    return breakdown, round(total, 2), impact_params
