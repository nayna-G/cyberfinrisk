from pydantic import BaseModel
from typing import List, Optional

class AssetContext(BaseModel):
    name: str
    description: str = ""
    paths: List[str]                     # Substrings to match file paths
    business_function: str
    estimated_value_usd: float           # Financial value to the business
    sensitive_data_types: List[str]      # e.g., ["PII", "credentials"]
    exposure: str                        # "internet-facing", "internal", "none"
    environment: str                     # "prod", "staging", "dev", "test"
    controls_efficacy: Optional[float] = None # range 0.0 - 1.0 (EPSS-esque)

class CompanyContext(BaseModel):
    company_name: str
    industry: str
    annual_revenue: float
    monthly_revenue: float
    active_users: Optional[int] = 0
    # Support for variations in the user's test list
    active_customers: Optional[int] = None
    active_stores: Optional[int] = None
    developers_using_platform: Optional[int] = None
    
    arpu: float
    engineer_hourly_cost: float
    deployment_exposure: str             # "public", "internal", "private"
    infrastructure_type: str             # "cloud", "on_prem", "hybrid"
    sensitive_data_types: List[str]      # ["PII", "financial", "health", "credentials"]
    regulatory_frameworks: List[str]     # ["GDPR", "PCI_DSS", "HIPAA", "CCPA"]
    estimated_records_stored: int
    estimated_downtime_cost_per_hour: Optional[float] = None
    company_size: str = "mid_size"
    system_role: str = "saas_product"    # "saas_product", "infrastructure", "framework", "internal_tool", "microservice"
    stack_description: Optional[str] = None
    product_description: Optional[str] = None
    assets: Optional[List[AssetContext]] = None

    def get_total_users(self) -> int:
        return self.active_users or self.active_customers or self.active_stores or self.developers_using_platform or 0
