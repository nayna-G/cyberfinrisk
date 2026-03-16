from pydantic import BaseModel
from typing import Optional, List

class ImpactBreakdown(BaseModel):
    data_breach_cost: float
    incident_response_cost: float
    downtime_cost: float
    regulatory_penalty: float
    reputation_damage: float

class GeminiAnalysis(BaseModel):
    is_exploitable: bool
    exploitability_confidence: str       # "high", "medium", "low"
    exploitability_reasoning: str        # plain English explanation
    business_context: str                # what this endpoint/code actually does
    authentication_required: str = "unknown" # e.g. "public_unauthenticated", "admin_only"
    data_scope: str = "unknown"          # e.g. "full_database", "system_files"
    adjusted_probability: float          # Gemini-adjusted probability (vs table default)
    false_positive_likelihood: str       # "high", "medium", "low"
    recommended_fix: str                 # actual fix code or instructions
    fix_complexity: str                  # "simple", "moderate", "complex"

class AttackChain(BaseModel):
    chain_id: str
    vulnerability_ids: List[str]
    chain_description: str               # plain English attack path
    combined_severity: str               # "critical", "high", "medium"
    combined_expected_loss: float
    chain_steps: List[str]               # step-by-step attack narrative

class RiskResult(BaseModel):
    vulnerability_id: str
    bug_type: str
    file: str
    line: int
    severity: str
    exposure: str
    probability_of_exploit: float        # table-based baseline
    gemini_analysis: Optional[GeminiAnalysis] = None
    effective_probability: float         # final probability after Gemini adjustment
    impact_breakdown: ImpactBreakdown
    total_impact: float
    expected_loss: float
    expected_loss_10th: Optional[float] = None
    expected_loss_90th: Optional[float] = None
    fix_effort_hours: float
    fix_cost_usd: float
    priority_score: float
    roi_of_fixing: float
    business_brief: str
    attack_chains: Optional[List[str]] = None   # chain IDs this vuln belongs to
