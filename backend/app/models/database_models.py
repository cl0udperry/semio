"""
SQLAlchemy database models for the Semio freemium system.
Includes proper relationships, constraints, and indexing for production use.
"""

from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, String, DateTime, Boolean, Text, 
    ForeignKey, Index, UniqueConstraint, CheckConstraint
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base
from app.models.user import UserTier


class User(Base):
    """
    User model with authentication and tier management.
    Includes proper indexing and constraints for performance.
    """
    __tablename__ = "users"

    # Primary key
    id = Column(String(36), primary_key=True, index=True)  # UUID
    
    # Authentication fields
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    
    # Tier and API key management
    tier = Column(String(20), nullable=False, default=UserTier.FREE)
    api_key = Column(String(64), unique=True, nullable=True, index=True)  # User's own API key
    
    # Usage tracking
    monthly_requests = Column(Integer, default=0, nullable=False)
    monthly_limit = Column(Integer, default=100, nullable=False)  # Based on tier
    
    # Account status
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    usage_logs = relationship("UsageLog", back_populates="user", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user", cascade="all, delete-orphan")
    
    # Constraints
    __table_args__ = (
        CheckConstraint("monthly_requests >= 0", name="check_monthly_requests_positive"),
        CheckConstraint("monthly_limit > 0", name="check_monthly_limit_positive"),
        Index("idx_users_email_tier", "email", "tier"),
        Index("idx_users_api_key_active", "api_key", "is_active"),
    )


class UsageLog(Base):
    """
    Usage tracking for rate limiting and analytics.
    Includes detailed request information for audit purposes.
    """
    __tablename__ = "usage_logs"

    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Foreign key to user
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Request details
    endpoint = Column(String(100), nullable=False)  # /api/scan, /api/review
    method = Column(String(10), nullable=False)  # POST, GET
    file_size = Column(Integer, nullable=True)  # Size of uploaded file in bytes
    processing_time_ms = Column(Integer, nullable=True)  # Processing time in milliseconds
    
    # Response details
    status_code = Column(Integer, nullable=False)
    vulnerabilities_found = Column(Integer, default=0, nullable=False)
    fixes_generated = Column(Integer, default=0, nullable=False)
    
    # Metadata
    ip_address = Column(String(45), nullable=True)  # IPv4 or IPv6
    user_agent = Column(Text, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    
    # Relationships
    user = relationship("User", back_populates="usage_logs")
    
    # Constraints
    __table_args__ = (
        CheckConstraint("processing_time_ms >= 0", name="check_processing_time_positive"),
        CheckConstraint("vulnerabilities_found >= 0", name="check_vulnerabilities_positive"),
        CheckConstraint("fixes_generated >= 0", name="check_fixes_positive"),
        Index("idx_usage_logs_user_date", "user_id", "created_at"),
        Index("idx_usage_logs_date", "created_at"),
    )


class AuditLog(Base):
    """
    Audit trail for security and compliance.
    Tracks important user actions and system events.
    """
    __tablename__ = "audit_logs"

    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Foreign key to user (nullable for system events)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    
    # Event details
    event_type = Column(String(50), nullable=False)  # login, tier_upgrade, api_key_generated, etc.
    event_data = Column(Text, nullable=True)  # JSON string with event details
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    
    # Relationships
    user = relationship("User", back_populates="audit_logs")
    
    # Constraints
    __table_args__ = (
        Index("idx_audit_logs_user_date", "user_id", "created_at"),
        Index("idx_audit_logs_event_type", "event_type", "created_at"),
    )


class MonthlyUsageReset(Base):
    """
    Tracks monthly usage reset events for billing and analytics.
    """
    __tablename__ = "monthly_usage_resets"

    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Reset details
    reset_month = Column(String(7), nullable=False)  # YYYY-MM format
    users_processed = Column(Integer, default=0, nullable=False)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    # Constraints
    __table_args__ = (
        UniqueConstraint("reset_month", name="uq_monthly_reset_month"),
        Index("idx_monthly_reset_date", "created_at"),
    )


class Project(Base):
    """
    A named project grouping scan runs for trend tracking.
    """
    __tablename__ = "projects"

    id = Column(String(36), primary_key=True, index=True)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    scan_runs = relationship("ScanRun", back_populates="project", cascade="all, delete-orphan", order_by="ScanRun.created_at.desc()")

    __table_args__ = (
        UniqueConstraint("user_id", "name", name="uq_project_user_name"),
        Index("idx_projects_user", "user_id", "created_at"),
    )


class ScanRun(Base):
    """
    One execution of a scanner against a project.
    Stores aggregate counts; individual findings in Finding table.
    """
    __tablename__ = "scan_runs"

    id = Column(String(36), primary_key=True, index=True)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    scanner = Column(String(50), nullable=False)          # semgrep | bandit | trivy | dependency-check
    total_findings = Column(Integer, default=0, nullable=False)
    error_count = Column(Integer, default=0, nullable=False)    # HIGH/CRITICAL
    warning_count = Column(Integer, default=0, nullable=False)  # MEDIUM
    info_count = Column(Integer, default=0, nullable=False)     # LOW/INFO
    auto_fix_count = Column(Integer, default=0, nullable=False)
    suggest_count = Column(Integer, default=0, nullable=False)
    suppress_count = Column(Integer, default=0, nullable=False)
    manual_review_count = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)

    project = relationship("Project", back_populates="scan_runs")
    findings = relationship("Finding", back_populates="scan_run", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_scan_runs_project_date", "project_id", "created_at"),
    )


class Finding(Base):
    """
    Individual normalised finding from a scan run.
    """
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_run_id = Column(String(36), ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    rule_id = Column(String(255), nullable=False)
    path = Column(Text, nullable=False)
    start_line = Column(Integer, default=0, nullable=False)
    severity = Column(String(20), nullable=False)          # ERROR | WARNING | INFO | UNKNOWN
    action = Column(String(20), nullable=True)             # AUTO_FIX | SUGGEST | SUPPRESS | MANUAL_REVIEW
    confidence = Column(Integer, nullable=True)            # 0–100
    scanner = Column(String(50), nullable=False)
    message = Column(Text, nullable=True)
    suggested_fix = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    scan_run = relationship("ScanRun", back_populates="findings")

    __table_args__ = (
        Index("idx_findings_scan_run", "scan_run_id"),
        Index("idx_findings_severity", "severity"),
        Index("idx_findings_rule", "rule_id"),
    )


class APIKey(Base):
    """
    Separate table for API key management (alternative approach).
    Provides better security and key rotation capabilities.
    """
    __tablename__ = "api_keys"

    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Foreign key to user
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # API key details
    key_hash = Column(String(255), unique=True, nullable=False, index=True)  # Hashed API key
    name = Column(String(100), nullable=True)  # Optional name for the key
    is_active = Column(Boolean, default=True, nullable=False)
    
    # Security
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    
    # Constraints
    __table_args__ = (
        Index("idx_api_keys_user_active", "user_id", "is_active"),
        Index("idx_api_keys_hash", "key_hash"),
    )

# API Keys table for CLI access
API_KEYS_TABLE = """
CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    key_name TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL,
    revoked_at DATETIME,
    is_active BOOLEAN DEFAULT 1,
    FOREIGN KEY (user_id) REFERENCES users (id)
);
"""
