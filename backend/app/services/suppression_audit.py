"""
Suppression Audit Trail - Comprehensive tracking of all suppression decisions
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum
import hashlib

logger = logging.getLogger(__name__)

class SuppressionReason(Enum):
    """Enumeration of suppression reasons"""
    TEST_FILE = "test_file"
    MOCK_CODE = "mock_code"
    DEBUG_CODE = "debug_code"
    BENIGN_PATTERN = "benign_pattern"
    SAFE_CONTEXT = "safe_context"
    LLM_ANALYSIS = "llm_analysis"
    HIGH_CONFIDENCE_RULE = "high_confidence_rule"
    MANUAL_APPROVAL = "manual_approval"
    BUSINESS_LOGIC = "business_logic"
    SECURITY_CONTEXT = "security_context"

class ValidationMethod(Enum):
    """Enumeration of validation methods used"""
    RULE_BASED = "rule_based"
    LLM_ANALYSIS = "llm_analysis"
    PATTERN_MATCHING = "pattern_matching"
    CONTEXT_ANALYSIS = "context_analysis"
    MANUAL_REVIEW = "manual_review"
    HISTORICAL_DATA = "historical_data"

@dataclass
class SuppressionAuditRecord:
    """Comprehensive audit record for suppression decisions"""
    # Basic identification
    audit_id: str
    finding_id: str
    rule_id: str
    file_path: str
    line_number: int
    
    # Suppression details
    suppression_reason: SuppressionReason
    confidence_score: float
    suppression_threshold: float
    
    # Validation methods used
    validation_methods: List[ValidationMethod]
    validation_details: Dict[str, Any]
    
    # Context information
    original_severity: str
    original_message: str
    code_snippet: str
    file_context: Dict[str, Any]
    
    # Decision tracking
    decision_timestamp: datetime
    decision_made_by: str  # "system" or "user_id"
    
    # Audit trail
    audit_trail: List[Dict[str, Any]]
    
    # Risk assessment
    risk_level: str  # "low", "medium", "high"
    risk_factors: List[str]
    
    # Business impact
    business_impact: str  # "none", "low", "medium", "high"
    affected_components: List[str]
    
    # Optional fields with defaults (must come after required fields)
    decision_approved_by: Optional[str] = None
    approval_timestamp: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        data['suppression_reason'] = self.suppression_reason.value
        data['validation_methods'] = [m.value for m in self.validation_methods]
        data['decision_timestamp'] = self.decision_timestamp.isoformat()
        if self.approval_timestamp:
            data['approval_timestamp'] = self.approval_timestamp.isoformat()
        return data

class SuppressionAuditTrail:
    """
    Comprehensive audit trail system for suppression decisions
    """
    
    def __init__(self, storage_path: str = "suppression_audit.json"):
        self.storage_path = storage_path
        self.audit_records: List[SuppressionAuditRecord] = []
        self.load_audit_records()
    
    def create_suppression_record(self, 
                                finding: Dict, 
                                fp_score: float, 
                                suppression_threshold: float,
                                validation_methods: List[ValidationMethod],
                                validation_details: Dict[str, Any],
                                decision_made_by: str = "system") -> SuppressionAuditRecord:
        """Create a comprehensive suppression audit record"""
        
        # Generate unique audit ID
        audit_id = self._generate_audit_id(finding)
        
        # Determine suppression reason
        suppression_reason = self._determine_suppression_reason(finding, validation_details)
        
        # Assess risk level
        risk_level, risk_factors = self._assess_risk_level(finding, fp_score)
        
        # Assess business impact
        business_impact, affected_components = self._assess_business_impact(finding)
        
        # Create audit trail
        audit_trail = self._create_audit_trail(finding, validation_details)
        
        record = SuppressionAuditRecord(
            audit_id=audit_id,
            finding_id=f"{finding['rule_id']}:{finding['path']}:{finding['start_line']}",
            rule_id=finding['rule_id'],
            file_path=finding['path'],
            line_number=finding['start_line'],
            suppression_reason=suppression_reason,
            confidence_score=fp_score,
            suppression_threshold=suppression_threshold,
            validation_methods=validation_methods,
            validation_details=validation_details,
            original_severity=finding.get('severity', 'UNKNOWN'),
            original_message=finding.get('message', ''),
            code_snippet=finding.get('code', ''),
            file_context=self._extract_file_context(finding),
            decision_timestamp=datetime.now(),
            decision_made_by=decision_made_by,
            audit_trail=audit_trail,
            risk_level=risk_level,
            risk_factors=risk_factors,
            business_impact=business_impact,
            affected_components=affected_components
        )
        
        # Store the record
        self.audit_records.append(record)
        self.save_audit_records()
        
        logger.info(f"Created suppression audit record: {audit_id}")
        return record
    
    def approve_suppression(self, audit_id: str, approved_by: str) -> bool:
        """Approve a suppression decision"""
        for record in self.audit_records:
            if record.audit_id == audit_id:
                record.decision_approved_by = approved_by
                record.approval_timestamp = datetime.now()
                self.save_audit_records()
                logger.info(f"Suppression approved: {audit_id} by {approved_by}")
                return True
        return False
    
    def get_suppression_report(self, 
                             start_date: Optional[datetime] = None,
                             end_date: Optional[datetime] = None,
                             file_path: Optional[str] = None,
                             rule_id: Optional[str] = None) -> Dict[str, Any]:
        """Generate comprehensive suppression report"""
        
        filtered_records = self._filter_records(start_date, end_date, file_path, rule_id)
        
        # Calculate statistics
        total_suppressions = len(filtered_records)
        approved_suppressions = len([r for r in filtered_records if r.decision_approved_by])
        pending_approvals = total_suppressions - approved_suppressions
        
        # Risk distribution
        risk_distribution = {}
        for record in filtered_records:
            risk_distribution[record.risk_level] = risk_distribution.get(record.risk_level, 0) + 1
        
        # Reason distribution
        reason_distribution = {}
        for record in filtered_records:
            reason = record.suppression_reason.value
            reason_distribution[reason] = reason_distribution.get(reason, 0) + 1
        
        # Validation method distribution
        validation_distribution = {}
        for record in filtered_records:
            for method in record.validation_methods:
                method_name = method.value
                validation_distribution[method_name] = validation_distribution.get(method_name, 0) + 1
        
        return {
            'summary': {
                'total_suppressions': total_suppressions,
                'approved_suppressions': approved_suppressions,
                'pending_approvals': pending_approvals,
                'approval_rate': approved_suppressions / total_suppressions if total_suppressions > 0 else 0
            },
            'risk_distribution': risk_distribution,
            'reason_distribution': reason_distribution,
            'validation_distribution': validation_distribution,
            'detailed_records': [record.to_dict() for record in filtered_records],
            'report_generated': datetime.now().isoformat()
        }
    
    def _generate_audit_id(self, finding: Dict) -> str:
        """Generate unique audit ID"""
        content = f"{finding['rule_id']}:{finding['path']}:{finding['start_line']}:{datetime.now().isoformat()}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def _determine_suppression_reason(self, finding: Dict, validation_details: Dict[str, Any]) -> SuppressionReason:
        """Determine the primary reason for suppression"""
        
        # Check validation details for specific patterns
        if validation_details.get('test_file_detected'):
            return SuppressionReason.TEST_FILE
        elif validation_details.get('mock_code_detected'):
            return SuppressionReason.MOCK_CODE
        elif validation_details.get('debug_code_detected'):
            return SuppressionReason.DEBUG_CODE
        elif validation_details.get('llm_analysis_used'):
            return SuppressionReason.LLM_ANALYSIS
        elif validation_details.get('high_confidence_rule'):
            return SuppressionReason.HIGH_CONFIDENCE_RULE
        else:
            return SuppressionReason.SAFE_CONTEXT
    
    def _assess_risk_level(self, finding: Dict, fp_score: float) -> tuple[str, List[str]]:
        """Assess the risk level of suppressing this finding"""
        risk_factors = []
        
        # High severity findings are higher risk
        if finding.get('severity') == 'ERROR':
            risk_factors.append('high_severity')
        
        # Low confidence suppressions are higher risk
        if fp_score < 0.9:
            risk_factors.append('low_confidence')
        
        # Security-critical rules are higher risk
        security_critical_rules = ['sql-injection', 'xss', 'command-injection', 'path-traversal']
        if any(rule in finding.get('rule_id', '').lower() for rule in security_critical_rules):
            risk_factors.append('security_critical_rule')
        
        # Production code is higher risk
        if not self._is_test_or_dev_context(finding):
            risk_factors.append('production_code')
        
        # Determine risk level
        if len(risk_factors) >= 3:
            risk_level = 'high'
        elif len(risk_factors) >= 1:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        return risk_level, risk_factors
    
    def _assess_business_impact(self, finding: Dict) -> tuple[str, List[str]]:
        """Assess the business impact of suppressing this finding"""
        affected_components = []
        
        # Check if it's in core business logic
        file_path = finding.get('path', '')
        if any(component in file_path.lower() for component in ['auth', 'payment', 'user', 'admin']):
            affected_components.append('core_business_logic')
            business_impact = 'high'
        elif any(component in file_path.lower() for component in ['api', 'service', 'controller']):
            affected_components.append('api_layer')
            business_impact = 'medium'
        elif any(component in file_path.lower() for component in ['util', 'helper', 'common']):
            affected_components.append('utility_code')
            business_impact = 'low'
        else:
            affected_components.append('other')
            business_impact = 'low'
        
        return business_impact, affected_components
    
    def _create_audit_trail(self, finding: Dict, validation_details: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Create detailed audit trail of the suppression decision"""
        trail = []
        
        # Add validation steps
        for method, details in validation_details.items():
            trail.append({
                'timestamp': datetime.now().isoformat(),
                'step': f'validation_{method}',
                'details': details,
                'result': 'passed' if details.get('passed', False) else 'failed'
            })
        
        # Add decision step
        trail.append({
            'timestamp': datetime.now().isoformat(),
            'step': 'suppression_decision',
            'details': {
                'confidence_score': validation_details.get('confidence_score', 0),
                'suppression_threshold': validation_details.get('suppression_threshold', 0),
                'decision': 'suppress' if validation_details.get('confidence_score', 0) >= validation_details.get('suppression_threshold', 0) else 'review'
            },
            'result': 'suppressed'
        })
        
        return trail
    
    def _extract_file_context(self, finding: Dict) -> Dict[str, Any]:
        """Extract relevant file context"""
        return {
            'file_extension': finding.get('path', '').split('.')[-1] if '.' in finding.get('path', '') else '',
            'file_directory': '/'.join(finding.get('path', '').split('/')[:-1]),
            'file_name': finding.get('path', '').split('/')[-1],
            'line_context': {
                'start_line': finding.get('start_line', 0),
                'end_line': finding.get('end_line', 0)
            }
        }
    
    def _is_test_or_dev_context(self, finding: Dict) -> bool:
        """Check if finding is in test or development context"""
        file_path = finding.get('path', '').lower()
        test_indicators = ['test', 'mock', 'spec', 'fixture', 'debug']
        return any(indicator in file_path for indicator in test_indicators)
    
    def _filter_records(self, 
                       start_date: Optional[datetime] = None,
                       end_date: Optional[datetime] = None,
                       file_path: Optional[str] = None,
                       rule_id: Optional[str] = None) -> List[SuppressionAuditRecord]:
        """Filter audit records based on criteria"""
        filtered = self.audit_records
        
        if start_date:
            filtered = [r for r in filtered if r.decision_timestamp >= start_date]
        if end_date:
            filtered = [r for r in filtered if r.decision_timestamp <= end_date]
        if file_path:
            filtered = [r for r in filtered if file_path in r.file_path]
        if rule_id:
            filtered = [r for r in filtered if rule_id in r.rule_id]
        
        return filtered
    
    def load_audit_records(self):
        """Load audit records from storage"""
        try:
            with open(self.storage_path, 'r') as f:
                data = json.load(f)
                self.audit_records = [SuppressionAuditRecord(**record) for record in data]
        except FileNotFoundError:
            self.audit_records = []
        except Exception as e:
            logger.error(f"Error loading audit records: {e}")
            self.audit_records = []
    
    def save_audit_records(self):
        """Save audit records to storage"""
        try:
            with open(self.storage_path, 'w') as f:
                json.dump([record.to_dict() for record in self.audit_records], f, indent=2)
        except Exception as e:
            logger.error(f"Error saving audit records: {e}")
