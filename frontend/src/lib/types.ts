// Shared types for VFIE frontend

export interface CompanyContext {
    company_name: string;
    industry: string;
    annual_revenue: number;
    monthly_revenue: number;
    active_users: number;
    arpu: number;
    engineer_hourly_cost: number;
    deployment_exposure: string;
    infrastructure_type: string;
    system_role: string;
    sensitive_data_types: string[];
    regulatory_frameworks: string[];
    estimated_records_stored: number;
    company_size: string;
    estimated_downtime_cost_per_hour: number | null;
    stack_description: string | null;
    product_description: string | null;
}

export interface GeminiAnalysis {
    business_context: string;
    is_exploitable: boolean;
    exploitability_confidence: string;
    exploitability_reasoning: string;
    recommended_fix: string;
    false_positive_likelihood: string;
    fix_complexity?: string;
    authentication_required?: string;
    data_scope?: string;
}

export interface VulnerabilityResult {
    vulnerability_id: string;
    bug_type: string;
    file: string;
    line: number;
    severity: string;
    exposure: string;
    expected_loss: number;
    expected_loss_10th?: number;
    expected_loss_90th?: number;
    total_impact: number;
    fix_cost_usd: number;
    fix_effort_hours: number;
    roi_of_fixing: number;
    effective_probability: number;
    probability_source?: string;
    business_brief: string;
    gemini_analysis: GeminiAnalysis | null;
    attack_chains: string[];
    impact_breakdown?: Record<string, number>;
}

export interface AttackChain {
    chain_id: string;
    chain_description: string;
    combined_severity: string;
    chain_steps: string[];
    combined_expected_loss: number;
    vulnerability_ids: string[];
}

export interface ScanResults {
    results: VulnerabilityResult[];
    attack_chains: AttackChain[];
    executive_summary: string;
    total_expected_loss: number;
    total_fix_cost: number;
    vulnerability_count: number;
    filtered_count: number;
    gemini_enabled: boolean;
}

export interface Project {
    id: string;
    repo_url: string;
    branch: string;
    org_id: string;
    group_id: string;
    created_by: string;
    created_at: string;
    last_scanned_at: string | null;
    status: string;
    vulnerability_count: number;
    total_expected_loss: number;
    total_fix_cost: number;
    gemini_enabled: boolean;
}

export interface ProjectDetail extends Project {
    company: Record<string, any>;
    scan_results: VulnerabilityResult[];
    attack_chains: AttackChain[];
    executive_summary: string;
    filtered_count: number;
}

export interface ScanFormData {
    repo_url: string;
    branch: string;
    gemini_api_key: string | null;
}

export interface ManualInput {
    raw: string; // JSON string of VulnInput[]
}

export interface VulnInput {
    id: string;
    raw_rule_id: string;
    file: string;
    line: number;
    message: string;
    severity: string;
    exposure: string;
}
