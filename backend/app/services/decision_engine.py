"""
Decision Engine - Risk-aware decision making based on multiple analysis factors
"""

import logging
from typing import Dict, Tuple
from enum import Enum
from dataclasses import dataclass

from .agentic_types import ActionType

logger = logging.getLogger(__name__)

@dataclass
class DecisionFactors:
    """Factors that influence the decision-making process"""
    fp_score: float
    fix_confidence: float
    severity: str
    rule_id: str
    file_path: str
    line_number: int
    historical_similarity: float = 0.0
    suppression_flags: int = 0

class DecisionEngine:
    """
    Risk-aware decision engine that combines multiple factors to determine the best action
    """
    
    def __init__(self):
        # Severity weights for decision making
        self.severity_weights = {
            'ERROR': 1.0,
            'WARNING': 0.7,
            'INFO': 0.4,
            'UNKNOWN': 0.5
        }
        
        # Rule-specific confidence thresholds
        self.rule_thresholds = {
            'python.lang.correctness.useless-comparison': {
                'auto_fix': 0.8,
                'suppress': 0.7
            },
            'python.lang.security.audit.weak-crypto': {
                'auto_fix': 0.9,
                'suppress': 0.6
            },
            'python.lang.security.audit.insecure-deserialization': {
                'auto_fix': 0.95,
                'suppress': 0.5
            }
        }
        
        # Default thresholds
        self.default_thresholds = {
            'auto_fix': 0.9,
            'suppress': 0.8,
            'suggest': 0.6
        }
    
    def make_decision(self, decision_data: Dict, 
                     auto_fix_threshold: float = 0.9,
                     suppress_threshold: float = 0.8) -> Tuple[ActionType, float, str]:
        """
        Make a risk-aware decision based on multiple factors
        
        Args:
            decision_data: Dictionary containing decision factors
            auto_fix_threshold: Confidence threshold for automatic fixes
            suppress_threshold: Confidence threshold for suppression
            
        Returns:
            Tuple of (action, confidence, explanation)
        """
        try:
            # Extract decision factors
            factors = DecisionFactors(
                fp_score=decision_data.get('fp_score', 0.0),
                fix_confidence=decision_data.get('fix_confidence', 0.0),
                severity=decision_data.get('severity', 'UNKNOWN'),
                rule_id=decision_data.get('rule_id', ''),
                file_path=decision_data.get('file_path', ''),
                line_number=decision_data.get('line_number', 0)
            )
            
            # Get rule-specific thresholds
            thresholds = self._get_thresholds(factors.rule_id)
            
            # Calculate weighted confidence
            confidence = self._calculate_confidence(factors)
            
            # Determine action based on thresholds and factors
            action, explanation = self._determine_action(
                factors, confidence, thresholds, auto_fix_threshold, suppress_threshold
            )
            
            logger.debug(f"Decision for {factors.rule_id}: {action.value} "
                        f"(confidence={confidence:.2f}, fp_score={factors.fp_score:.2f})")
            
            return action, confidence, explanation
            
        except Exception as e:
            logger.error(f"Error in decision making: {e}")
            return ActionType.MANUAL_REVIEW, 0.0, f"Decision error: {e}"
    
    def _get_thresholds(self, rule_id: str) -> Dict[str, float]:
        """Get rule-specific thresholds or defaults"""
        return self.rule_thresholds.get(rule_id, self.default_thresholds)
    
    def _calculate_confidence(self, factors: DecisionFactors) -> float:
        """
        Calculate weighted confidence based on multiple factors
        
        Formula: (1 - fp_score) * fix_confidence * severity_weight
        """
        # Base confidence is inverse of false positive score
        base_confidence = 1.0 - factors.fp_score
        
        # Weight by fix confidence (if available)
        if factors.fix_confidence > 0:
            base_confidence *= factors.fix_confidence
        
        # Weight by severity
        severity_weight = self.severity_weights.get(factors.severity, 0.5)
        base_confidence *= severity_weight
        
        # Apply historical similarity if available
        if factors.historical_similarity > 0:
            base_confidence = (base_confidence * 0.7) + (factors.historical_similarity * 0.3)
        
        # Penalize for suppression flags
        if factors.suppression_flags > 0:
            base_confidence *= (0.9 ** factors.suppression_flags)
        
        return min(max(base_confidence, 0.0), 1.0)
    
    def _determine_action(self, factors: DecisionFactors, confidence: float,
                         thresholds: Dict[str, float],
                         auto_fix_threshold: float,
                         suppress_threshold: float) -> Tuple[ActionType, str]:
        """
        Determine the best action based on confidence and thresholds
        """
        # Check for suppression first (highest priority)
        if factors.fp_score >= suppress_threshold:
            return ActionType.SUPPRESS, (
                f"High false positive likelihood ({factors.fp_score:.2f}) "
                f"exceeds suppression threshold ({suppress_threshold:.2f})"
            )
        
        # Check for auto-fix (requires high confidence and low false positive)
        if (confidence >= auto_fix_threshold and 
            factors.fp_score < 0.3 and 
            factors.fix_confidence >= 0.8):
            return ActionType.AUTO_FIX, (
                f"High confidence fix ({confidence:.2f}) with low false positive "
                f"likelihood ({factors.fp_score:.2f})"
            )
        
        # Check for suggestion (moderate confidence)
        if confidence >= thresholds.get('suggest', 0.6):
            return ActionType.SUGGEST, (
                f"Moderate confidence ({confidence:.2f}) - recommend manual review "
                f"with suggested fix"
            )
        
        # Default to manual review
        return ActionType.MANUAL_REVIEW, (
            f"Low confidence ({confidence:.2f}) - requires manual review. "
            f"False positive likelihood: {factors.fp_score:.2f}"
        )
    
    def update_thresholds(self, rule_id: str, new_thresholds: Dict[str, float]):
        """Update thresholds for a specific rule"""
        if rule_id not in self.rule_thresholds:
            self.rule_thresholds[rule_id] = {}
        
        self.rule_thresholds[rule_id].update(new_thresholds)
        logger.info(f"Updated thresholds for {rule_id}: {new_thresholds}")
    
    def get_decision_stats(self) -> Dict:
        """Get statistics about decision performance"""
        return {
            'total_decisions': 0,
            'action_distribution': {
                'suppress': 0,
                'suggest': 0,
                'auto_fix': 0,
                'manual_review': 0
            },
            'average_confidence': 0.0,
            'rule_performance': {}
        }
