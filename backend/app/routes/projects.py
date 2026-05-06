"""
Projects API — create projects, store scan runs, query history and trends.
"""
from __future__ import annotations
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.services.auth_service import get_current_user
from app.models.database_models import Project, ScanRun, Finding, User

router = APIRouter(prefix="/projects", tags=["Projects"])


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class ProjectCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None


class ProjectOut(BaseModel):
    id: str
    name: str
    description: Optional[str]
    created_at: datetime
    scan_count: int = 0

    model_config = {"from_attributes": True}


class ScanRunCreate(BaseModel):
    scanner: str
    findings: list[dict]   # normalised finding dicts from scanner_parsers
    decisions: list[dict]  # AgentDecision dicts (optional enrichment)


class ScanRunOut(BaseModel):
    id: str
    scanner: str
    total_findings: int
    error_count: int
    warning_count: int
    info_count: int
    auto_fix_count: int
    suggest_count: int
    suppress_count: int
    manual_review_count: int
    created_at: datetime

    model_config = {"from_attributes": True}


class TrendPoint(BaseModel):
    date: str          # ISO date string
    total: int
    error: int
    warning: int
    info: int
    auto_fix: int
    suggest: int


# ── helpers ───────────────────────────────────────────────────────────────────

def _get_project_or_404(project_id: str, user: User, db: Session) -> Project:
    p = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == user.id,
    ).first()
    if not p:
        raise HTTPException(status_code=404, detail="Project not found")
    return p


def _severity_counts(findings: list[dict]) -> dict:
    counts = {"ERROR": 0, "WARNING": 0, "INFO": 0, "UNKNOWN": 0}
    for f in findings:
        sev = f.get("severity", "UNKNOWN")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _action_counts(decisions: list[dict]) -> dict:
    counts = {"AUTO_FIX": 0, "SUGGEST": 0, "SUPPRESS": 0, "MANUAL_REVIEW": 0}
    for d in decisions:
        action = (d.get("action") or "MANUAL_REVIEW").upper()
        counts[action] = counts.get(action, 0) + 1
    return counts


# ── routes ────────────────────────────────────────────────────────────────────

@router.post("", response_model=ProjectOut, status_code=201)
def create_project(
    body: ProjectCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    existing = db.query(Project).filter(
        Project.user_id == user.id,
        Project.name == body.name,
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail="Project name already exists")

    project = Project(
        id=str(uuid.uuid4()),
        user_id=user.id,
        name=body.name,
        description=body.description,
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    return ProjectOut(
        id=project.id,
        name=project.name,
        description=project.description,
        created_at=project.created_at,
        scan_count=0,
    )


@router.get("", response_model=list[ProjectOut])
def list_projects(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    projects = db.query(Project).filter(Project.user_id == user.id).order_by(Project.created_at.desc()).all()
    return [
        ProjectOut(
            id=p.id,
            name=p.name,
            description=p.description,
            created_at=p.created_at,
            scan_count=len(p.scan_runs),
        )
        for p in projects
    ]


@router.delete("/{project_id}", status_code=204)
def delete_project(
    project_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    project = _get_project_or_404(project_id, user, db)
    db.delete(project)
    db.commit()


@router.post("/{project_id}/scans", response_model=ScanRunOut, status_code=201)
def record_scan(
    project_id: str,
    body: ScanRunCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Store a completed scan run and its findings for trend tracking."""
    _get_project_or_404(project_id, user, db)

    sev = _severity_counts(body.findings)
    act = _action_counts(body.decisions)

    run = ScanRun(
        id=str(uuid.uuid4()),
        project_id=project_id,
        scanner=body.scanner,
        total_findings=len(body.findings),
        error_count=sev["ERROR"],
        warning_count=sev["WARNING"],
        info_count=sev["INFO"],
        auto_fix_count=act["AUTO_FIX"],
        suggest_count=act["SUGGEST"],
        suppress_count=act["SUPPRESS"],
        manual_review_count=act["MANUAL_REVIEW"],
    )
    db.add(run)
    db.flush()  # get run.id before inserting findings

    # Build decision lookup by index for enrichment
    decision_map = {i: d for i, d in enumerate(body.decisions)}

    for i, f in enumerate(body.findings):
        dec = decision_map.get(i, {})
        action_raw = dec.get("action")
        action = action_raw.upper() if action_raw else None
        conf_raw = dec.get("confidence")
        conf = int(conf_raw * 100) if conf_raw is not None else None

        db.add(Finding(
            scan_run_id=run.id,
            rule_id=f.get("rule_id", "unknown"),
            path=f.get("path", "unknown"),
            start_line=f.get("start_line", 0),
            severity=f.get("severity", "UNKNOWN"),
            action=action,
            confidence=conf,
            scanner=f.get("scanner", body.scanner),
            message=f.get("message", ""),
            suggested_fix=dec.get("suggested_fix"),
        ))

    db.commit()
    db.refresh(run)
    return run


@router.get("/{project_id}/scans", response_model=list[ScanRunOut])
def list_scans(
    project_id: str,
    limit: int = 30,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _get_project_or_404(project_id, user, db)
    runs = (
        db.query(ScanRun)
        .filter(ScanRun.project_id == project_id)
        .order_by(ScanRun.created_at.desc())
        .limit(limit)
        .all()
    )
    return runs


@router.get("/{project_id}/trends", response_model=list[TrendPoint])
def get_trends(
    project_id: str,
    limit: int = 30,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Return per-scan severity and action counts for charting."""
    _get_project_or_404(project_id, user, db)
    runs = (
        db.query(ScanRun)
        .filter(ScanRun.project_id == project_id)
        .order_by(ScanRun.created_at.asc())
        .limit(limit)
        .all()
    )
    return [
        TrendPoint(
            date=r.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            total=r.total_findings,
            error=r.error_count,
            warning=r.warning_count,
            info=r.info_count,
            auto_fix=r.auto_fix_count,
            suggest=r.suggest_count,
        )
        for r in runs
    ]


@router.get("/{project_id}/scans/{run_id}/findings", response_model=list[dict])
def get_findings(
    project_id: str,
    run_id: str,
    severity: Optional[str] = None,
    action: Optional[str] = None,
    limit: int = 200,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Return individual findings for a scan run, with optional severity/action filters."""
    _get_project_or_404(project_id, user, db)
    run = db.query(ScanRun).filter(
        ScanRun.id == run_id,
        ScanRun.project_id == project_id,
    ).first()
    if not run:
        raise HTTPException(status_code=404, detail="Scan run not found")

    q = db.query(Finding).filter(Finding.scan_run_id == run_id)
    if severity:
        q = q.filter(Finding.severity == severity.upper())
    if action:
        q = q.filter(Finding.action == action.upper())

    return [
        {
            "id": f.id,
            "rule_id": f.rule_id,
            "path": f.path,
            "start_line": f.start_line,
            "severity": f.severity,
            "action": f.action,
            "confidence": f.confidence,
            "scanner": f.scanner,
            "message": f.message,
            "suggested_fix": f.suggested_fix,
        }
        for f in q.limit(limit).all()
    ]
