"""
Semio Agentic AI Core - Orchestrates intelligent vulnerability analysis and decision-making
"""

import json
import logging
from typing import Dict, List, Optional, Tuple
import ast
import re

from .semgrep_parser import parse_semgrep_json, extract_context_for_fix
from .llm_recommender import generate_fixes
from .false_positive_filter import FalsePositiveFilter
from .fix_validator import FixValidator
from .decision_engine import DecisionEngine
from .memory_store import MemoryStore
from .agentic_types import ActionType, AgentDecision

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SemioAgenticCore:
    """
    Core agentic AI system that orchestrates intelligent vulnerability analysis
    """
    
    def __init__(self):
        self.fp_filter = FalsePositiveFilter()
        self.fix_validator = FixValidator()
        self.decision_engine = DecisionEngine()
        self.memory_store = MemoryStore()
        
    def process_semgrep_findings(self, semgrep_json: Dict, 
                                auto_fix_threshold: float = 0.9,
                                suppress_threshold: float = 0.8) -> List[AgentDecision]:
        """
        Main entry point for processing Semgrep findings through the agentic pipeline
        
        Args:
            semgrep_json: Raw Semgrep JSON output
            auto_fix_threshold: Confidence threshold for automatic fixes
            suppress_threshold: Confidence threshold for suppression
            
        Returns:
            List of agent decisions with recommended actions
        """
        logger.info("Starting agentic processing of Semgrep findings")
        
        # Step 1: Parse and extract context
        findings = parse_semgrep_json(semgrep_json, include_code_context=True)
        logger.info(f"Parsed {len(findings)} findings from Semgrep output")
        
        decisions = []
        
        for finding in findings:
            try:
                decision = self._process_single_finding(
                    finding, auto_fix_threshold, suppress_threshold
                )
                decisions.append(decision)
                
                # Store decision in memory for future learning
                self.memory_store.store_decision(decision)
                
            except Exception as e:
                logger.error(f"Error processing finding {finding.get('rule_id', 'unknown')}: {e}")
                # Create a fallback decision
                decision = self._create_fallback_decision(finding, str(e))
                decisions.append(decision)
        
        logger.info(f"Completed agentic processing. Generated {len(decisions)} decisions")
        return decisions
    
    def _process_single_finding(self, finding: Dict, 
                               auto_fix_threshold: float,
                               suppress_threshold: float) -> AgentDecision:
        """
        Process a single finding through the complete agentic pipeline
        """
        finding_id = f"{finding['rule_id']}:{finding['path']}:{finding['start_line']}"
        
        # Step 2: False Positive Analysis
        fp_score = self.fp_filter.analyze_finding(finding)
        logger.debug(f"False positive score for {finding_id}: {fp_score}")
        
        # Step 3: Generate Fix (if not likely false positive)
        fix_confidence = 0.0
        suggested_fix = None
        
        if fp_score < suppress_threshold:
            # Generate fix using existing LLM recommender (same as old endpoints)
            try:
                fixes = generate_fixes([finding], tier="FREE")  # Use FREE tier for demo
                if fixes and len(fixes) > 0:
                    fix_data = fixes[0]
                    suggested_fix = fix_data.get('suggested_fix')
                    fix_confidence = fix_data.get('confidence_score', 0.0)
                    
                    # Step 4: Validate the fix
                    if suggested_fix:
                        validation_result = self.fix_validator.validate_fix(
                            finding, suggested_fix
                        )
                        # Adjust confidence based on validation
                        if not validation_result.is_valid:
                            fix_confidence *= 0.7  # Reduce confidence for invalid fixes
                            logger.warning(f"Fix validation failed for {finding_id}: {validation_result.errors}")
            except Exception as e:
                logger.error(f"Error generating fix for {finding_id}: {e}")
                suggested_fix = None
                fix_confidence = 0.0
        
        # Step 5: Risk-aware decision making
        decision_data = {
            'fp_score': fp_score,
            'fix_confidence': fix_confidence,
            'severity': finding.get('severity', 'UNKNOWN'),
            'rule_id': finding['rule_id'],
            'file_path': finding['path'],
            'line_number': finding['start_line']
        }
        
        action, confidence, explanation = self.decision_engine.make_decision(
            decision_data, auto_fix_threshold, suppress_threshold
        )
        
        # Step 6: Create structured decision
        decision = AgentDecision(
            finding_id=finding_id,
            file_path=finding['path'],
            line_number=finding['start_line'],
            rule_id=finding['rule_id'],
            action=action,
            confidence=confidence,
            fp_likelihood=fp_score,
            fix_confidence=fix_confidence,
            original_code=finding.get('code', ''),
            suggested_fix=suggested_fix,
            explanation=explanation,
            metadata={
                'severity': finding.get('severity'),
                'description': finding.get('description', ''),
                'cwe': finding.get('cwe', []),
                'owasp': finding.get('owasp', [])
            }
        )
        
        return decision
    
    def _create_fallback_decision(self, finding: Dict, error: str) -> AgentDecision:
        """Create a fallback decision when processing fails"""
        finding_id = f"{finding['rule_id']}:{finding['path']}:{finding['start_line']}"
        
        return AgentDecision(
            finding_id=finding_id,
            file_path=finding['path'],
            line_number=finding['start_line'],
            rule_id=finding['rule_id'],
            action=ActionType.MANUAL_REVIEW,
            confidence=0.0,
            fp_likelihood=0.5,  # Neutral
            fix_confidence=0.0,
            original_code=finding.get('code', ''),
            suggested_fix=None,
            explanation=f"Processing error: {error}. Manual review required.",
            metadata={'error': error}
        )
    
    def get_agent_stats(self) -> Dict:
        """Get statistics about agent performance and decisions"""
        return self.memory_store.get_statistics()
    
    def export_decisions(self, decisions: List[AgentDecision], format: str = 'json') -> str:
        """
        Export agent decisions in various formats
        
        Args:
            decisions: List of agent decisions
            format: Output format ('json', 'markdown', 'html')
            
        Returns:
            Formatted string representation
        """
        if format == 'json':
            return json.dumps([self._decision_to_dict(d) for d in decisions], indent=2)
        elif format == 'markdown':
            return self._export_markdown(decisions)
        elif format == 'html':
            return self._export_html(decisions)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _decision_to_dict(self, decision: AgentDecision) -> Dict:
        """Convert AgentDecision to dictionary for JSON serialization"""
        return {
            'finding_id': decision.finding_id,
            'file_path': decision.file_path,
            'line_number': decision.line_number,
            'rule_id': decision.rule_id,
            'action': decision.action.value,
            'confidence': decision.confidence,
            'fp_likelihood': decision.fp_likelihood,
            'fix_confidence': decision.fix_confidence,
            'original_code': decision.original_code,
            'suggested_fix': decision.suggested_fix,
            'explanation': decision.explanation,
            'metadata': decision.metadata
        }
    
    def _export_markdown(self, decisions: List[AgentDecision]) -> str:
        """Export decisions as markdown report"""
        lines = ["# Semio Agentic Analysis Report\n"]
        
        # Summary
        action_counts = {}
        for d in decisions:
            action_counts[d.action.value] = action_counts.get(d.action.value, 0) + 1
        
        lines.append("## Summary\n")
        for action, count in action_counts.items():
            lines.append(f"- **{action.title()}**: {count} findings\n")
        
        # Detailed findings
        lines.append("\n## Detailed Findings\n")
        for decision in decisions:
            lines.append(f"### {decision.rule_id}\n")
            lines.append(f"- **File**: {decision.file_path}:{decision.line_number}\n")
            lines.append(f"- **Action**: {decision.action.value.title()}\n")
            lines.append(f"- **Confidence**: {decision.confidence:.2f}\n")
            lines.append(f"- **False Positive Likelihood**: {decision.fp_likelihood:.2f}\n")
            if decision.suggested_fix:
                lines.append(f"- **Suggested Fix**:\n```\n{decision.suggested_fix}\n```\n")
            lines.append(f"- **Explanation**: {decision.explanation}\n\n")
        
        return "\n".join(lines)
    
    def _export_html(self, decisions: List[AgentDecision]) -> str:
        """Export decisions as HTML report"""
        # This would generate a more sophisticated HTML report
        # For now, return a simple HTML structure
        html = """
        <html>
        <head>
            <title>Semio Agentic Analysis Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .finding { border: 1px solid #ddd; margin: 10px 0; padding: 15px; }
                .action-suppress { background-color: #fff3cd; }
                .action-suggest { background-color: #d1ecf1; }
                .action-auto_fix { background-color: #d4edda; }
            </style>
        </head>
        <body>
            <h1>Semio Agentic Analysis Report</h1>
        """
        
        for decision in decisions:
            action_class = f"action-{decision.action.value}"
            html += f"""
            <div class="finding {action_class}">
                <h3>{decision.rule_id}</h3>
                <p><strong>File:</strong> {decision.file_path}:{decision.line_number}</p>
                <p><strong>Action:</strong> {decision.action.value.title()}</p>
                <p><strong>Confidence:</strong> {decision.confidence:.2f}</p>
                <p><strong>Explanation:</strong> {decision.explanation}</p>
            </div>
            """
        
        html += "</body></html>"
        return html
