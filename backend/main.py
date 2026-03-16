import json, os, shutil, uuid
from datetime import datetime, timezone
from dotenv import load_dotenv
load_dotenv()
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from contextlib import asynccontextmanager
from logging_config import setup_logging

# Initialize structured logging
logger = setup_logging()

from models.company import CompanyContext
from models.risk_result import RiskResult, AttackChain
from engine.scanner import clone_repo, run_semgrep, parse_semgrep_findings, run_trivy, parse_trivy_findings, _rmtree_windows_safe
from engine.classifier import classify_bug, get_fix_effort, load_taxonomy
from engine.probability_model import load_probabilities, get_probability
from engine.impact_model import compute_total_impact
from engine.criticality import get_asset_criticality
from engine.expected_loss import (compute_expected_loss, compute_priority_score,
                                   compute_fix_cost, compute_roi)
from engine.ranker import rank_vulnerabilities
from engine.gemini_analyzer import init_gemini, analyze_vulnerability
from engine.attack_chain import find_attack_chains
from engine.business_brief import generate_business_brief, generate_executive_summary
from prometheus_fastapi_instrumentator import Instrumentator
from utils.email_utils import send_invite_email

from models.db import (
    Base, 
    pg_engine, 
    get_pg_db, 
    get_mongo_db,
    connect_to_mongo, 
    close_mongo_connection,
    User,
    PersonalAccessToken,
    Organization,
    OrganizationMember,
    Group,
    GroupMember,
    OrgInvite,
    Notification
)
from models.org_schemas import (
    OrganizationCreate, OrganizationUpdate, OrganizationResponse,
    GroupCreate, GroupUpdate, GroupResponse,
    OrgInviteCreate, OrgInviteResponse,
    MemberResponse,
    NotificationResponse
)
from models.project_schemas import ProjectCreate, ProjectSummary, ProjectDetail

# Manage Startup and Shutdown events
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Ensure DB tables exist
    Base.metadata.create_all(bind=pg_engine)
    # Connect to Mongo
    await connect_to_mongo()
    yield
    # Shutdown
    await close_mongo_connection()

app = FastAPI(
    title="Vulnerability Business Impact Engine", 
    version="3.0.0",
    lifespan=lifespan
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:3001",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:3001",
        "*",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["*"],
    expose_headers=["*"],
)

# Instrument the app for Prometheus
Instrumentator().instrument(app).expose(app)

# Serve frontend
app.mount("/static", StaticFiles(directory="frontend"), name="static")

@app.get("/")
async def serve_ui():
    return FileResponse("frontend/index.html")


class ManualScanRequest(BaseModel):
    vulnerabilities: List[dict]
    company: CompanyContext
    gemini_api_key: Optional[str] = None

class ScanRequest(BaseModel):
    repo_url: str
    branch: str = "main"
    company: CompanyContext
    gemini_api_key: Optional[str] = None

class AnalysisResponse(BaseModel):
    results: List[RiskResult]
    attack_chains: List[AttackChain]
    executive_summary: str
    total_expected_loss: float
    total_fix_cost: float
    vulnerability_count: int
    filtered_count: int
    gemini_enabled: bool


def run_risk_engine(
    findings: list,
    company: CompanyContext,
    gemini_api_key: Optional[str] = None
) -> tuple:
    if gemini_api_key:
        init_gemini(gemini_api_key)

    taxonomy      = load_taxonomy()
    probabilities = load_probabilities()
    results       = []
    filtered_count = 0

    for f in findings:
        bug_type    = classify_bug(f.get("raw_rule_id", ""), f.get("message", ""))
        fix_effort  = get_fix_effort(bug_type, taxonomy)
        # Map file to an asset if defined
        asset = None
        if company.assets:
            for ac in company.assets:
                for path in ac.paths:
                    if path in f["file"]:
                        asset = ac
                        break
                if asset: break

        # Environment & Exposure override based on asset
        exposure = asset.exposure.upper() if asset else f.get("exposure", company.deployment_exposure.upper())

        # Pass CVE ID for EPSS lookup (EPSS only applies to real CVEs from Trivy)
        cve_id = f.get("cve_id") or f.get("raw_rule_id", "")
        baseline_p, prob_source = get_probability(bug_type, exposure, probabilities, cve_id=cve_id)

        # --- Gemini analysis ---
        gemini_result = None
        effective_p   = baseline_p
        if gemini_api_key and f.get("code_context"):
            gemini_result = analyze_vulnerability(
                bug_type=bug_type,
                file=f["file"],
                line=f["line"],
                code_context=f.get("code_context", ""),
                message=f.get("message", ""),
                exposure=exposure,
                company=company,
                baseline_probability=baseline_p,
                asset=asset
            )
            if gemini_result:
                effective_p = gemini_result.adjusted_probability
                # Skip confirmed false positives
                if gemini_result.false_positive_likelihood == "high" and \
                   not gemini_result.is_exploitable:
                    filtered_count += 1
                    continue  # Actually filter the finding out as per Phase 0 goals

        breakdown, total_impact, impact_params = compute_total_impact(company, bug_type, gemini_result, asset)

        # Apply file-path criticality multiplier to expected loss
        # This makes vulns in payment/auth code weigh more than the same bug in test code
        _, crit_multiplier, _ = get_asset_criticality(f["file"])

        from engine.monte_carlo import run_lec_simulation
        sim_stats = run_lec_simulation(effective_p, impact_params)
        expected_loss = sim_stats["mean"] * crit_multiplier
        expected_loss_10th = sim_stats["p10"] * crit_multiplier
        expected_loss_90th = sim_stats["p90"] * crit_multiplier

        priority_score = compute_priority_score(expected_loss, fix_effort)
        fix_cost       = compute_fix_cost(fix_effort, company.engineer_hourly_cost)
        roi            = compute_roi(expected_loss, fix_cost)

        result = RiskResult(
            vulnerability_id       = f["id"],
            bug_type               = bug_type,
            file                   = f["file"],
            line                   = f["line"],
            severity               = f.get("severity", "medium"),
            exposure               = exposure,
            probability_of_exploit = baseline_p,
            gemini_analysis        = gemini_result,
            effective_probability  = effective_p,
            impact_breakdown       = breakdown,
            total_impact           = total_impact,
            expected_loss          = expected_loss,
            expected_loss_10th     = expected_loss_10th,
            expected_loss_90th     = expected_loss_90th,
            fix_effort_hours       = fix_effort,
            fix_cost_usd           = fix_cost,
            priority_score         = priority_score,
            roi_of_fixing          = roi,
            business_brief         = ""
        )
        result.business_brief = generate_business_brief(result, company)
        results.append(result)

    ranked = rank_vulnerabilities(results)

    # --- Attack chain analysis ---
    chains = []
    if gemini_api_key and len(ranked) >= 2:
        chains = find_attack_chains(ranked, company)
        # Tag each result with its chains
        for chain in chains:
            for r in ranked:
                if r.vulnerability_id in chain.vulnerability_ids:
                    if r.attack_chains is None:
                        r.attack_chains = []
                    r.attack_chains.append(chain.chain_id)

    return ranked, chains, filtered_count


@app.post("/analyze-manual", response_model=AnalysisResponse)
async def analyze_manual(req: ManualScanRequest):
    results, chains, filtered = run_risk_engine(
        req.vulnerabilities, req.company, req.gemini_api_key
    )
    summary = generate_executive_summary(results, req.company, chains)
    return AnalysisResponse(
        results=results,
        attack_chains=chains,
        executive_summary=summary,
        total_expected_loss=sum(r.expected_loss for r in results),
        total_fix_cost=sum(r.fix_cost_usd for r in results),
        vulnerability_count=len(results),
        filtered_count=filtered,
        gemini_enabled=bool(req.gemini_api_key)
    )


@app.post("/scan-repo", response_model=AnalysisResponse)
async def scan_repo(req: ScanRequest):
    repo_path = None
    try:
        repo_path = clone_repo(req.repo_url, req.branch)
        
        # Run Semgrep
        semgrep_raw = run_semgrep(repo_path)
        semgrep_parsed = parse_semgrep_findings(semgrep_raw, req.company.deployment_exposure, repo_path)
        
        # Run Trivy
        trivy_raw = run_trivy(repo_path)
        trivy_parsed = parse_trivy_findings(trivy_raw, req.company.deployment_exposure, repo_path)
        
        # Merge Findings
        combined_parsed = semgrep_parsed + trivy_parsed
        
        results, chains, filtered = run_risk_engine(combined_parsed, req.company, req.gemini_api_key)
        os.makedirs("data", exist_ok=True)
        with open("data/risk_results.json", "w") as f:
            json.dump({"results": [r.dict() for r in results],
                       "chains":  [c.dict() for c in chains]}, f, indent=2)
        summary = generate_executive_summary(results, req.company, chains)
        return AnalysisResponse(
            results=results, attack_chains=chains, executive_summary=summary,
            total_expected_loss=sum(r.expected_loss for r in results),
            total_fix_cost=sum(r.fix_cost_usd for r in results),
            vulnerability_count=len(results),
            filtered_count=filtered,
            gemini_enabled=bool(req.gemini_api_key)
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if repo_path and os.path.exists(repo_path):
            shutil.rmtree(repo_path)


@app.get("/health")
async def health():
    return {"status": "ok", "version": "3.0.0"}

# ==========================================
# User Profile Endpoints
# ==========================================

class UserProfileUpdate(BaseModel):
    full_name: Optional[str] = None

class TokenCreate(BaseModel):
    name: str
    token: Optional[str] = None  # If not provided, we generate one

@app.get("/api/user/{uuid}")
async def get_user_profile(uuid: str, db: Session = Depends(get_pg_db)):
    user = db.query(User).filter(User.uuid == uuid).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    tokens = [{
        "id": t.id,
        "name": t.name,
        "token": t.token,
        "created_at": str(t.created_at)
    } for t in user.tokens]
    
    return {
        "uuid": user.uuid,
        "email": user.email,
        "full_name": user.full_name,
        "tokens": tokens
    }

@app.post("/api/user")
async def sync_user_profile(user_data: dict, db: Session = Depends(get_pg_db)):
    """Sync user on login (Firebase UUID)"""
    uuid = user_data.get("uuid")
    email = user_data.get("email")
    
    if not uuid or not email:
        raise HTTPException(status_code=400, detail="UUID and Email required")
        
    user = db.query(User).filter(User.uuid == uuid).first()
    if not user:
        user = User(
            uuid=uuid,
            email=email,
            full_name=user_data.get("full_name")
        )
        db.add(user)
        db.commit()
    else:
        # Update email if changed or other basic fields from Gmail
        user.email = email
        if user_data.get("full_name") and not user.full_name:
             user.full_name = user_data.get("full_name")
        db.commit()
        
    return {"status": "success", "user": {"uuid": user.uuid, "email": user.email}}

@app.patch("/api/user/{uuid}")
async def update_user_profile(uuid: str, update_data: UserProfileUpdate, db: Session = Depends(get_pg_db)):
    user = db.query(User).filter(User.uuid == uuid).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if update_data.full_name is not None:
        user.full_name = update_data.full_name
        
    db.commit()
    return {"status": "success"}

@app.post("/api/user/{uuid}/tokens")
async def create_token(uuid: str, req: TokenCreate, db: Session = Depends(get_pg_db)):
    import secrets
    user = db.query(User).filter(User.uuid == uuid).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    token_val = req.token if req.token else f"fin_pat_{secrets.token_hex(16)}"
    
    new_token = PersonalAccessToken(
        user_uuid=uuid,
        name=req.name,
        token=token_val
    )
    db.add(new_token)
    db.commit()
    return {"id": new_token.id, "name": new_token.name, "token": new_token.token}

@app.delete("/api/user/tokens/{token_id}")
async def delete_token(token_id: int, db: Session = Depends(get_pg_db)):
    token = db.query(PersonalAccessToken).filter(PersonalAccessToken.id == token_id).first()
    if not token:
        raise HTTPException(status_code=404, detail="Token not found")
    db.delete(token)
    db.commit()
    return {"status": "success"}

# ==========================================
# Organization Endpoints
# ==========================================

@app.get("/api/orgs", response_model=List[OrganizationResponse])
async def list_organizations(user_uuid: Optional[str] = None, db: Session = Depends(get_pg_db)):
    if user_uuid:
        # Get orgs where user is a member
        orgs = db.query(Organization).join(OrganizationMember).filter(OrganizationMember.user_uuid == user_uuid).all()
        return orgs
    return db.query(Organization).all()

@app.post("/api/orgs", response_model=OrganizationResponse)
async def create_organization(req: OrganizationCreate, db: Session = Depends(get_pg_db)):
    # Check if slug exists
    existing = db.query(Organization).filter(Organization.slug == req.slug).first()
    if existing:
        raise HTTPException(status_code=400, detail="Organization slug already taken")
    
    # Create org
    new_org = Organization(
        name=req.name,
        slug=req.slug,
        plan=req.plan,
        creator_uuid=req.creator_uuid
    )
    db.add(new_org)
    db.flush() # Get the ID
    
    # Add creator as admin member
    membership = OrganizationMember(
        org_id=new_org.id,
        user_uuid=req.creator_uuid,
        role="admin"
    )
    db.add(membership)
    db.commit()
    db.refresh(new_org)
    
    return new_org

@app.patch("/api/orgs/{org_id}", response_model=OrganizationResponse)
async def update_organization(org_id: str, req: OrganizationUpdate, db: Session = Depends(get_pg_db)):
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    if req.name is not None:
        org.name = req.name
    if req.plan is not None:
        org.plan = req.plan
    db.commit()
    db.refresh(org)
    return org

@app.delete("/api/orgs/{org_id}", status_code=204)
async def delete_organization(org_id: str, db: Session = Depends(get_pg_db)):
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    db.delete(org)
    db.commit()

# ==========================================
# Group Endpoints
# ==========================================

@app.get("/api/orgs/{org_id}/groups", response_model=List[GroupResponse])
async def list_groups(org_id: str, db: Session = Depends(get_pg_db)):
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    return org.groups

@app.post("/api/orgs/{org_id}/groups", response_model=GroupResponse)
async def create_group(org_id: str, req: GroupCreate, db: Session = Depends(get_pg_db)):
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    new_group = Group(
        name=req.name,
        description=req.description,
        org_id=org_id,
        creator_uuid=req.creator_uuid,
    )
    db.add(new_group)
    db.flush()

    # Add creator as admin of the group
    membership = GroupMember(
        group_id=new_group.id,
        user_uuid=req.creator_uuid,
        role="admin"
    )
    db.add(membership)
    db.commit()
    db.refresh(new_group)
    return new_group

@app.get("/api/groups/{group_id}", response_model=GroupResponse)
async def get_group(group_id: str, db: Session = Depends(get_pg_db)):
    group = db.query(Group).filter(Group.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    return group

@app.patch("/api/groups/{group_id}", response_model=GroupResponse)
async def update_group(group_id: str, req: GroupUpdate, db: Session = Depends(get_pg_db)):
    group = db.query(Group).filter(Group.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    if req.name is not None:
        group.name = req.name
    if req.description is not None:
        group.description = req.description
    if req.auto_scan is not None:
        group.auto_scan = req.auto_scan
    if req.enforce_policies is not None:
        group.enforce_policies = req.enforce_policies
    db.commit()
    db.refresh(group)
    return group

@app.delete("/api/groups/{group_id}", status_code=204)
async def delete_group(group_id: str, db: Session = Depends(get_pg_db)):
    group = db.query(Group).filter(Group.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    db.delete(group)
    db.commit()


# ── Members API ────────────────────────────────────────────────────────────

@app.get("/api/orgs/{org_id}/members", response_model=List[MemberResponse])
async def list_org_members(org_id: str, db: Session = Depends(get_pg_db)):
    members = db.query(
        OrganizationMember.id,
        OrganizationMember.org_id,
        OrganizationMember.user_uuid,
        OrganizationMember.role,
        OrganizationMember.joined_at,
        User.email,
        User.full_name
    ).join(User, OrganizationMember.user_uuid == User.uuid).filter(OrganizationMember.org_id == org_id).all()
    
    return [
        MemberResponse(
            id=m.id,
            org_id=m.org_id,
            user_uuid=m.user_uuid,
            role=m.role,
            joined_at=m.joined_at,
            email=m.email,
            full_name=m.full_name
        ) for m in members
    ]


# ── Invites API ────────────────────────────────────────────────────────────

@app.post("/api/orgs/{org_id}/invite", response_model=OrgInviteResponse)
async def invite_member(
    org_id: str, 
    req: OrgInviteCreate, 
    background_tasks: BackgroundTasks, 
    db: Session = Depends(get_pg_db)
):
    # 1. Create the invite with explicit token
    invite_token = str(uuid.uuid4())
    invite = OrgInvite(
        org_id=org_id,
        invited_email=req.invited_email,
        inviter_uuid=req.inviter_uuid,
        role=req.role,
        token=invite_token
    )
    db.add(invite)
    
    # 2. Fetch context for notification/email
    org = db.query(Organization).filter(Organization.id == org_id).first()
    inviter = db.query(User).filter(User.uuid == req.inviter_uuid).first()
    inviter_name = inviter.full_name if inviter else "A teammate"
    org_name = org.name if org else "an organization"

    # 3. Check if user exists to send in-app notification
    user = db.query(User).filter(User.email == req.invited_email).first()
    if user:
        notif = Notification(
            user_uuid=user.uuid,
            type="invite",
            title="Team Invitation",
            body=f"You have been invited to join {org_name}.",
            link=f"/dashboard/invites/{invite_token}"
        )
        db.add(notif)
    
    # 4. Dispatch Email in background
    background_tasks.add_task(
        send_invite_email,
        to_email=req.invited_email,
        org_name=org_name,
        invite_token=invite_token,
        inviter_name=inviter_name
    )
    
    db.commit()
    db.refresh(invite)
    return invite

@app.get("/api/invites/{token}")
async def get_invite_details(token: str, db: Session = Depends(get_pg_db)):
    invite = db.query(OrgInvite).filter(OrgInvite.token == token).first()
    if not invite:
        raise HTTPException(status_code=404, detail="Invitation not found")
    
    org = db.query(Organization).filter(Organization.id == invite.org_id).first()
    return {
        "org_name": org.name if org else "an organization",
        "invited_email": invite.invited_email,
        "status": invite.status,
        "role": invite.role
    }

@app.post("/api/invites/{token}/accept")
async def accept_invite(
    token: str, 
    user_uuid: str, 
    db: Session = Depends(get_pg_db)
):
    # 1. Verify invite
    invite = db.query(OrgInvite).filter(OrgInvite.token == token).first()
    if not invite:
        raise HTTPException(status_code=404, detail="Invalid invitation token")
    
    if invite.status == "accepted":
        # Check if this specific user is the one who accepted or is already a member
        org = db.query(Organization).filter(Organization.id == invite.org_id).first()
        return {"message": "You are already a member", "org_name": org.name if org else "the organization"}

    # 2. Add member
    # Check if already a member first (idempotency)
    existing = db.query(OrganizationMember).filter(
        OrganizationMember.org_id == invite.org_id, 
        OrganizationMember.user_uuid == user_uuid
    ).first()
    
    if not existing:
        member = OrganizationMember(
            org_id=invite.org_id,
            user_uuid=user_uuid,
            role=invite.role
        )
        db.add(member)
    
    # 3. Update invite status
    invite.status = "accepted"
    
    # 4. Notify new member
    org = db.query(Organization).filter(Organization.id == invite.org_id).first()
    notif = Notification(
        user_uuid=user_uuid,
        type="info",
        title="Welcome!",
        body=f"You are now a member of {org.name if org else 'the organization'}.",
        link="/dashboard"
    )
    db.add(notif)
    
    db.commit()
    return {"message": "Successfully joined organization", "org_name": org.name if org else "the organization"}


# ── Notifications API ───────────────────────────────────────────────────────


# ── Notifications API ───────────────────────────────────────────────────────

@app.get("/api/notifications/{user_uuid}", response_model=List[NotificationResponse])
async def list_notifications(user_uuid: str, db: Session = Depends(get_pg_db)):
    return db.query(Notification).filter(Notification.user_uuid == user_uuid).order_by(Notification.created_at.desc()).all()

@app.patch("/api/notifications/{id}/read", response_model=NotificationResponse)
async def mark_notification_read(id: str, db: Session = Depends(get_pg_db)):
    notif = db.query(Notification).filter(Notification.id == id).first()
    if not notif:
        raise HTTPException(status_code=404, detail="Notification not found")
    notif.is_read = True
    db.commit()
    db.refresh(notif)
    return notif

@app.delete("/api/notifications/{id}", status_code=204)
async def delete_notification(id: str, db: Session = Depends(get_pg_db)):
    notif = db.query(Notification).filter(Notification.id == id).first()
    if not notif:
        raise HTTPException(status_code=404, detail="Notification not found")
    db.delete(notif)
    db.commit()


# ==========================================
# Project Endpoints (MongoDB)
# ==========================================

def _check_org_membership(user_uuid: str, org_id: str, db: Session):
    """Verify user is a member of the org. Raises 403 if not."""
    member = db.query(OrganizationMember).filter(
        OrganizationMember.org_id == org_id,
        OrganizationMember.user_uuid == user_uuid
    ).first()
    if not member:
        raise HTTPException(status_code=403, detail="Not a member of this organization")


@app.post("/api/projects", response_model=ProjectDetail)
async def create_project(req: ProjectCreate, db: Session = Depends(get_pg_db)):
    """Run a scan and save the project + results to MongoDB."""
    # 1. Verify org membership
    _check_org_membership(req.created_by, req.org_id, db)

    mongo = get_mongo_db()
    if mongo is None:
        raise HTTPException(status_code=500, detail="MongoDB not connected")

    # 2. Run the scan
    repo_path = None
    repo_path = None
    try:
        repo_path = clone_repo(req.repo_url, req.branch)
        
        # Run Semgrep
        semgrep_raw = run_semgrep(repo_path)
        semgrep_parsed = parse_semgrep_findings(semgrep_raw, req.company.deployment_exposure, repo_path)
        
        # Run Trivy
        trivy_raw = run_trivy(repo_path)
        trivy_parsed = parse_trivy_findings(trivy_raw, req.company.deployment_exposure, repo_path)
        
        # Merge Findings
        combined_parsed = semgrep_parsed + trivy_parsed
        
        results, chains, filtered = run_risk_engine(combined_parsed, req.company, req.gemini_api_key)
        summary = generate_executive_summary(results, req.company, chains)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")
    finally:
        if repo_path and os.path.exists(repo_path):
            _rmtree_windows_safe(repo_path)

    # 3. Build the document
    now = datetime.now(timezone.utc).isoformat()
    doc = {
        "repo_url": req.repo_url,
        "branch": req.branch,
        "company": req.company.dict(),
        "org_id": req.org_id,
        "group_id": req.group_id,
        "created_by": req.created_by,
        "created_at": now,
        "last_scanned_at": now,
        "status": "completed",
        "scan_results": [r.dict() for r in results],
        "attack_chains": [c.dict() for c in chains],
        "executive_summary": summary,
        "total_expected_loss": sum(r.expected_loss for r in results),
        "total_fix_cost": sum(r.fix_cost_usd for r in results),
        "vulnerability_count": len(results),
        "filtered_count": filtered,
        "gemini_enabled": bool(req.gemini_api_key),
    }

    # 4. Insert into MongoDB
    result = await mongo["projects"].insert_one(doc)
    doc["id"] = str(result.inserted_id)

    return ProjectDetail(
        id=doc["id"],
        repo_url=doc["repo_url"],
        branch=doc["branch"],
        org_id=doc["org_id"],
        group_id=doc["group_id"],
        created_by=doc["created_by"],
        created_at=doc["created_at"],
        last_scanned_at=doc["last_scanned_at"],
        status=doc["status"],
        vulnerability_count=doc["vulnerability_count"],
        total_expected_loss=doc["total_expected_loss"],
        total_fix_cost=doc["total_fix_cost"],
        gemini_enabled=doc["gemini_enabled"],
        company=doc["company"],
        scan_results=doc["scan_results"],
        attack_chains=doc["attack_chains"],
        executive_summary=doc["executive_summary"],
        filtered_count=doc["filtered_count"],
    )


@app.get("/api/projects", response_model=List[ProjectSummary])
async def list_projects(
    org_id: str,
    group_id: Optional[str] = None,
    user_uuid: Optional[str] = None,
    db: Session = Depends(get_pg_db)
):
    """List projects for an org, optionally filtered by group."""
    if user_uuid:
        _check_org_membership(user_uuid, org_id, db)

    mongo = get_mongo_db()
    if mongo is None:
        raise HTTPException(status_code=500, detail="MongoDB not connected")

    query = {"org_id": org_id}
    if group_id:
        query["group_id"] = group_id

    cursor = mongo["projects"].find(
        query,
        {  # Projection: exclude heavy fields for list view
            "scan_results": 0,
            "attack_chains": 0,
            "company": 0,
            "executive_summary": 0,
        }
    ).sort("last_scanned_at", -1)

    projects = []
    async for doc in cursor:
        projects.append(ProjectSummary(
            id=str(doc["_id"]),
            repo_url=doc["repo_url"],
            branch=doc["branch"],
            org_id=doc["org_id"],
            group_id=doc["group_id"],
            created_by=doc.get("created_by", ""),
            created_at=doc.get("created_at", ""),
            last_scanned_at=doc.get("last_scanned_at"),
            status=doc.get("status", "completed"),
            vulnerability_count=doc.get("vulnerability_count", 0),
            total_expected_loss=doc.get("total_expected_loss", 0),
            total_fix_cost=doc.get("total_fix_cost", 0),
            gemini_enabled=doc.get("gemini_enabled", False),
        ))
    return projects


@app.get("/api/projects/{project_id}", response_model=ProjectDetail)
async def get_project(project_id: str):
    """Get a single project with full scan results."""
    from bson import ObjectId
    mongo = get_mongo_db()
    if mongo is None:
        raise HTTPException(status_code=500, detail="MongoDB not connected")

    try:
        doc = await mongo["projects"].find_one({"_id": ObjectId(project_id)})
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid project ID")

    if not doc:
        raise HTTPException(status_code=404, detail="Project not found")

    return ProjectDetail(
        id=str(doc["_id"]),
        repo_url=doc["repo_url"],
        branch=doc["branch"],
        org_id=doc["org_id"],
        group_id=doc["group_id"],
        created_by=doc.get("created_by", ""),
        created_at=doc.get("created_at", ""),
        last_scanned_at=doc.get("last_scanned_at"),
        status=doc.get("status", "completed"),
        vulnerability_count=doc.get("vulnerability_count", 0),
        total_expected_loss=doc.get("total_expected_loss", 0),
        total_fix_cost=doc.get("total_fix_cost", 0),
        gemini_enabled=doc.get("gemini_enabled", False),
        company=doc.get("company", {}),
        scan_results=doc.get("scan_results", []),
        attack_chains=doc.get("attack_chains", []),
        executive_summary=doc.get("executive_summary", ""),
        filtered_count=doc.get("filtered_count", 0),
    )


@app.delete("/api/projects/{project_id}", status_code=204)
async def delete_project(project_id: str):
    """Delete a project from MongoDB."""
    from bson import ObjectId
    mongo = get_mongo_db()
    if mongo is None:
        raise HTTPException(status_code=500, detail="MongoDB not connected")

    try:
        result = await mongo["projects"].delete_one({"_id": ObjectId(project_id)})
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid project ID")

    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Project not found")


@app.post("/api/projects/scan-all")
async def scan_all_projects(
    org_id: str,
    group_id: Optional[str] = None,
    user_uuid: Optional[str] = None,
    db: Session = Depends(get_pg_db)
):
    """Re-scan all projects for a given org/group."""
    if user_uuid:
        _check_org_membership(user_uuid, org_id, db)

    mongo = get_mongo_db()
    if mongo is None:
        raise HTTPException(status_code=500, detail="MongoDB not connected")

    query = {"org_id": org_id}
    if group_id:
        query["group_id"] = group_id

    cursor = mongo["projects"].find(query)
    results_summary = []
    errors = []

    async for doc in cursor:
        project_id = str(doc["_id"])
        repo_path = None
        try:
            company = CompanyContext(**doc["company"])
            gemini_key = None  # Don't use stored key for security
            repo_path = clone_repo(doc["repo_url"], doc["branch"])
            
            # Run Semgrep
            semgrep_raw = run_semgrep(repo_path)
            semgrep_parsed = parse_semgrep_findings(semgrep_raw, company.deployment_exposure, repo_path)
            
            # Run Trivy
            trivy_raw = run_trivy(repo_path)
            trivy_parsed = parse_trivy_findings(trivy_raw, company.deployment_exposure, repo_path)
            
            # Merge Findings
            combined_parsed = semgrep_parsed + trivy_parsed
            
            scan_results, chains, filtered = run_risk_engine(combined_parsed, company, gemini_key)
            summary = generate_executive_summary(scan_results, company, chains)

            now = datetime.now(timezone.utc).isoformat()
            from bson import ObjectId
            await mongo["projects"].update_one(
                {"_id": ObjectId(project_id)},
                {"$set": {
                    "scan_results": [r.dict() for r in scan_results],
                    "attack_chains": [c.dict() for c in chains],
                    "executive_summary": summary,
                    "total_expected_loss": sum(r.expected_loss for r in scan_results),
                    "total_fix_cost": sum(r.fix_cost_usd for r in scan_results),
                    "vulnerability_count": len(scan_results),
                    "filtered_count": filtered,
                    "gemini_enabled": False,
                    "last_scanned_at": now,
                    "status": "completed",
                }}
            )
            results_summary.append({"project_id": project_id, "status": "completed", "vulnerabilities": len(scan_results)})
        except Exception as e:
            errors.append({"project_id": project_id, "error": str(e)})
            # Mark as failed in DB
            try:
                from bson import ObjectId
                await mongo["projects"].update_one(
                    {"_id": ObjectId(project_id)},
                    {"$set": {"status": "failed", "last_scanned_at": datetime.now(timezone.utc).isoformat()}}
                )
            except Exception:
                pass
        finally:
            if repo_path and os.path.exists(repo_path):
                shutil.rmtree(repo_path)

    return {
        "scanned": len(results_summary),
        "failed": len(errors),
        "results": results_summary,
        "errors": errors,
    }
