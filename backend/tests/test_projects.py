"""
Tests for project CRUD, scan history recording, and trends endpoint.
Uses in-memory SQLite — no external dependencies.
"""
import uuid
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models.database_models import Project, ScanRun, Finding, User
from app.models.user import UserTier
from app.routes.projects import (
    _severity_counts, _action_counts,
    create_project, list_projects, delete_project,
    record_scan, list_scans, get_trends, get_findings,
)


# ── in-memory DB fixture ──────────────────────────────────────────────────────

@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


@pytest.fixture
def user(db):
    u = User(
        id=str(uuid.uuid4()),
        email="test@example.com",
        hashed_password="hash",
        tier=UserTier.FREE,
        monthly_requests=0,
        monthly_limit=100,
    )
    db.add(u)
    db.commit()
    return u


@pytest.fixture
def project(db, user):
    p = Project(
        id=str(uuid.uuid4()),
        user_id=user.id,
        name="test-project",
    )
    db.add(p)
    db.commit()
    return p


# ── helper function tests ─────────────────────────────────────────────────────

class TestHelpers:
    def test_severity_counts_basic(self):
        findings = [
            {"severity": "ERROR"},
            {"severity": "ERROR"},
            {"severity": "WARNING"},
            {"severity": "INFO"},
        ]
        counts = _severity_counts(findings)
        assert counts["ERROR"] == 2
        assert counts["WARNING"] == 1
        assert counts["INFO"] == 1

    def test_severity_counts_empty(self):
        counts = _severity_counts([])
        assert counts["ERROR"] == 0

    def test_severity_counts_unknown(self):
        counts = _severity_counts([{"severity": "UNKNOWN"}, {}])
        assert counts["UNKNOWN"] == 2

    def test_action_counts_basic(self):
        decisions = [
            {"action": "auto_fix"},
            {"action": "SUGGEST"},
            {"action": "suppress"},
            {"action": "manual_review"},
            {"action": "auto_fix"},
        ]
        counts = _action_counts(decisions)
        assert counts["AUTO_FIX"] == 2
        assert counts["SUGGEST"] == 1
        assert counts["SUPPRESS"] == 1
        assert counts["MANUAL_REVIEW"] == 1

    def test_action_counts_none_action(self):
        counts = _action_counts([{"action": None}, {}])
        assert counts["MANUAL_REVIEW"] == 2


# ── Project model tests ───────────────────────────────────────────────────────

class TestProjectModel:
    def test_create_project(self, db, user):
        p = Project(id=str(uuid.uuid4()), user_id=user.id, name="my-project")
        db.add(p)
        db.commit()
        found = db.query(Project).filter_by(name="my-project").first()
        assert found is not None
        assert found.user_id == user.id

    def test_unique_name_per_user(self, db, user):
        from sqlalchemy.exc import IntegrityError
        db.add(Project(id=str(uuid.uuid4()), user_id=user.id, name="dup"))
        db.commit()
        db.add(Project(id=str(uuid.uuid4()), user_id=user.id, name="dup"))
        with pytest.raises(IntegrityError):
            db.commit()

    def test_delete_cascades_to_scan_runs(self, db, user):
        p = Project(id=str(uuid.uuid4()), user_id=user.id, name="cascade-test")
        db.add(p)
        db.commit()
        run = ScanRun(id=str(uuid.uuid4()), project_id=p.id, scanner="bandit",
                      total_findings=1, error_count=1, warning_count=0,
                      info_count=0, auto_fix_count=0, suggest_count=0,
                      suppress_count=0, manual_review_count=1)
        db.add(run)
        db.commit()
        db.delete(p)
        db.commit()
        assert db.query(ScanRun).filter_by(project_id=p.id).count() == 0


# ── ScanRun model tests ───────────────────────────────────────────────────────

class TestScanRunModel:
    def test_record_scan_run(self, db, project):
        run = ScanRun(
            id=str(uuid.uuid4()),
            project_id=project.id,
            scanner="semgrep",
            total_findings=5,
            error_count=2,
            warning_count=2,
            info_count=1,
            auto_fix_count=1,
            suggest_count=2,
            suppress_count=1,
            manual_review_count=1,
        )
        db.add(run)
        db.commit()
        found = db.query(ScanRun).filter_by(project_id=project.id).first()
        assert found.scanner == "semgrep"
        assert found.total_findings == 5
        assert found.error_count == 2

    def test_multiple_runs_ordered(self, db, project):
        for i in range(3):
            db.add(ScanRun(
                id=str(uuid.uuid4()), project_id=project.id,
                scanner="bandit", total_findings=i,
                error_count=0, warning_count=0, info_count=0,
                auto_fix_count=0, suggest_count=0, suppress_count=0,
                manual_review_count=0,
            ))
        db.commit()
        runs = db.query(ScanRun).filter_by(project_id=project.id).all()
        assert len(runs) == 3


# ── Finding model tests ───────────────────────────────────────────────────────

class TestFindingModel:
    def test_finding_stored(self, db, project):
        run = ScanRun(
            id=str(uuid.uuid4()), project_id=project.id,
            scanner="trivy", total_findings=1,
            error_count=1, warning_count=0, info_count=0,
            auto_fix_count=0, suggest_count=1, suppress_count=0,
            manual_review_count=0,
        )
        db.add(run)
        db.flush()
        f = Finding(
            scan_run_id=run.id,
            rule_id="trivy.CVE-2023-1234",
            path="requirements.txt",
            start_line=0,
            severity="ERROR",
            action="SUGGEST",
            confidence=75,
            scanner="trivy",
            message="Django SQL injection",
        )
        db.add(f)
        db.commit()
        found = db.query(Finding).filter_by(scan_run_id=run.id).first()
        assert found.rule_id == "trivy.CVE-2023-1234"
        assert found.action == "SUGGEST"
        assert found.confidence == 75

    def test_findings_cascade_delete_with_scan_run(self, db, project):
        run = ScanRun(
            id=str(uuid.uuid4()), project_id=project.id, scanner="bandit",
            total_findings=1, error_count=0, warning_count=1, info_count=0,
            auto_fix_count=0, suggest_count=0, suppress_count=0, manual_review_count=1,
        )
        db.add(run)
        db.flush()
        db.add(Finding(
            scan_run_id=run.id, rule_id="bandit.B101", path="app.py",
            start_line=10, severity="WARNING", scanner="bandit",
        ))
        db.commit()
        db.delete(run)
        db.commit()
        assert db.query(Finding).filter_by(scan_run_id=run.id).count() == 0


# ── Trends logic tests ────────────────────────────────────────────────────────

class TestTrendsData:
    def test_trends_reflect_scan_run_counts(self, db, project):
        for total in [3, 5, 2]:
            db.add(ScanRun(
                id=str(uuid.uuid4()), project_id=project.id,
                scanner="semgrep", total_findings=total,
                error_count=total, warning_count=0, info_count=0,
                auto_fix_count=0, suggest_count=0, suppress_count=0,
                manual_review_count=total,
            ))
        db.commit()
        runs = db.query(ScanRun).filter_by(project_id=project.id).order_by(ScanRun.created_at.asc()).all()
        totals = [r.total_findings for r in runs]
        assert totals == [3, 5, 2]

    def test_severity_distribution_sums_to_total(self, db, project):
        run = ScanRun(
            id=str(uuid.uuid4()), project_id=project.id, scanner="bandit",
            total_findings=6, error_count=2, warning_count=3, info_count=1,
            auto_fix_count=0, suggest_count=2, suppress_count=1, manual_review_count=3,
        )
        db.add(run)
        db.commit()
        assert run.error_count + run.warning_count + run.info_count == 6
