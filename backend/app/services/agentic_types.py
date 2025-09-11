"""
Agentic AI Types - Shared types and enums for the agentic system
"""
from enum import Enum
from dataclasses import dataclass
from typing import Dict, Optional

class ActionType(Enum):
    """Types of actions the agentic AI can take"""
    SUPPRESS = "suppress"
    SUGGEST = "suggest"
    AUTO_FIX = "auto_fix"
    MANUAL_REVIEW = "manual_review"

@dataclass
class AgentDecision:
    """Represents a decision made by the agentic AI"""
    finding_id: str
    file_path: str
    line_number: int
    rule_id: str
    action: ActionType
    confidence: float
    fp_likelihood: float
    fix_confidence: float
    original_code: str
    suggested_fix: Optional[str]
    explanation: str
    metadata: Dict
