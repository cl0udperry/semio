"""
False Positive Filter - Combines rule-based and LLM-based analysis to identify likely false positives
"""

import re
import os
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import logging

from .llm_recommender import get_llm_client
from ..models.user import UserTier

logger = logging.getLogger(__name__)

@dataclass
class FPFilterResult:
    """Result from false positive analysis"""
    is_false_positive: bool
    confidence: float
    reasoning: str
    rule_matches: List[str]
    llm_analysis: Optional[str] = None

class FalsePositiveFilter:
    """
    Hybrid false positive filter combining rule-based and LLM-based analysis
    """
    
    def __init__(self):
        # Rule-based patterns for common false positives
        self.fp_patterns = {
            'test_files': [
                r'test_.*\.py$',
                r'.*_test\.py$',
                r'tests?/.*',
                r'.*test/.*',
                r'.*spec\.py$',
                r'.*mock.*\.py$',
                r'.*fixture.*\.py$'
            ],
            'mock_patterns': [
                r'mock\.',
                r'patch\(',
                r'MagicMock',
                r'Mock\(',
                r'@mock\.',
                r'@patch\(',
                r'unittest\.mock'
            ],
            'benign_patterns': [
                r'# TODO:',
                r'# FIXME:',
                r'# nosec',
                r'# noqa',
                r'# pylint:',
                r'# type: ignore',
                r'# fmt: off',
                r'# noinspection'
            ],
            'safe_functions': [
                r'logging\.',
                r'print\(',
                r'debug\(',
                r'logger\.',
                r'console\.log',
                r'console\.warn',
                r'console\.error'
            ]
        }
        
        # High-confidence false positive rules
        self.high_confidence_rules = {
            'python.lang.correctness.useless-comparison': {
                'patterns': [r'assert.*==.*', r'assert.*!=.*', r'if.*==.*:.*pass'],
                'confidence': 0.9
            },
            'python.lang.security.audit.weak-crypto': {
                'patterns': [r'hashlib\.md5', r'hashlib\.sha1'],
                'context': 'test',
                'confidence': 0.8
            },
            'python.lang.security.audit.insecure-deserialization': {
                'patterns': [r'pickle\.loads', r'yaml\.load\('],
                'context': 'test',
                'confidence': 0.8
            }
        }
    
    def analyze_finding(self, finding: Dict) -> tuple[float, Dict[str, Any]]:
        """
        Analyze a finding to determine false positive likelihood with detailed validation
        
        Args:
            finding: Semgrep finding dictionary
            
        Returns:
            Tuple of (score, validation_details) where score is between 0.0 and 1.0
        """
        try:
            validation_details = {}
            
            # Step 1: Rule-based analysis
            rule_score, rule_matches = self._rule_based_analysis(finding)
            validation_details['rule_based_analysis'] = {
                'score': rule_score,
                'matches': rule_matches,
                'passed': rule_score > 0.5
            }
            
            # Step 2: LLM-based analysis (if rule score is ambiguous)
            llm_score = 0.0
            llm_analysis = None
            
            if 0.3 <= rule_score <= 0.7:  # Ambiguous cases
                llm_score, llm_analysis = self._llm_based_analysis(finding)
                validation_details['llm_analysis'] = {
                    'score': llm_score,
                    'analysis': llm_analysis,
                    'used': True,
                    'passed': llm_score > 0.5
                }
            else:
                validation_details['llm_analysis'] = {
                    'score': 0.0,
                    'analysis': None,
                    'used': False,
                    'passed': False
                }
            
            # Step 3: Combine scores
            if llm_analysis:
                # Weighted combination: 70% rule-based, 30% LLM
                final_score = (rule_score * 0.7) + (llm_score * 0.3)
                validation_details['llm_analysis_used'] = True
            else:
                final_score = rule_score
                validation_details['llm_analysis_used'] = False
            
            # Add final validation details
            validation_details['final_score'] = final_score
            validation_details['confidence_score'] = final_score
            validation_details['suppression_threshold'] = 0.95  # Conservative threshold
            
            # Add context-specific flags
            validation_details['test_file_detected'] = self._is_test_context(finding.get('code', ''), finding.get('message', ''))
            validation_details['mock_code_detected'] = any('mock' in match.lower() for match in rule_matches)
            validation_details['debug_code_detected'] = self._is_debug_context(finding.get('code', ''), finding.get('message', ''))
            validation_details['high_confidence_rule'] = finding.get('rule_id', '') in self.high_confidence_rules
            
            logger.debug(f"FP analysis for {finding.get('rule_id', 'unknown')}: "
                        f"rule_score={rule_score:.2f}, llm_score={llm_score:.2f}, "
                        f"final_score={final_score:.2f}")
            
            return final_score, validation_details
            
        except Exception as e:
            logger.error(f"Error in false positive analysis: {e}")
            return 0.5, {'error': str(e), 'final_score': 0.5}  # Neutral score on error
    
    def _rule_based_analysis(self, finding: Dict) -> Tuple[float, List[str]]:
        """
        Perform rule-based false positive analysis
        
        Returns:
            Tuple of (score, list of matching rules)
        """
        file_path = finding.get('path', '')
        rule_id = finding.get('rule_id', '')
        code = finding.get('code', '')
        message = finding.get('message', '')
        
        matches = []
        score = 0.0
        
        # Check file path patterns
        for pattern_type, patterns in self.fp_patterns.items():
            for pattern in patterns:
                if re.search(pattern, file_path, re.IGNORECASE):
                    matches.append(f"{pattern_type}: {pattern}")
                    if pattern_type == 'test_files':
                        score += 0.4
                    elif pattern_type == 'mock_patterns':
                        score += 0.3
                    elif pattern_type == 'benign_patterns':
                        score += 0.2
                    elif pattern_type == 'safe_functions':
                        score += 0.1
        
        # Check high-confidence rules
        if rule_id in self.high_confidence_rules:
            rule_config = self.high_confidence_rules[rule_id]
            for pattern in rule_config['patterns']:
                if re.search(pattern, code, re.IGNORECASE):
                    matches.append(f"high_confidence_rule: {pattern}")
                    score = max(score, rule_config['confidence'])
        
        # Check for test context in code
        if self._is_test_context(code, message):
            matches.append("test_context")
            score += 0.3
        
        # Check for debug/development patterns
        if self._is_debug_context(code, message):
            matches.append("debug_context")
            score += 0.2
        
        # Cap the score at 1.0
        score = min(score, 1.0)
        
        return score, matches
    
    def _llm_based_analysis(self, finding: Dict) -> Tuple[float, Optional[str]]:
        """
        Perform LLM-based false positive analysis
        
        Returns:
            Tuple of (score, analysis text)
        """
        try:
            # Get LLM client (using shared client for now)
            llm_client = get_llm_client(UserTier.FREE)
            if not llm_client:
                return 0.5, "LLM not available"
            
            # Build prompt for false positive analysis
            prompt = self._build_fp_analysis_prompt(finding)
            
            messages = [
                {
                    "role": "system",
                    "content": "You are a security expert specializing in identifying false positives in static analysis results. Analyze the given finding and determine if it's likely a false positive."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ]
            
            response = llm_client.chat.completions.create(
                model="gemini-2.0-flash",
                messages=messages
            )
            
            analysis = response.choices[0].message.content
            
            # Extract confidence score from response
            score = self._extract_confidence_from_llm_response(analysis)
            
            return score, analysis
            
        except Exception as e:
            logger.error(f"Error in LLM-based FP analysis: {e}")
            return 0.5, f"LLM analysis failed: {e}"
    
    def _build_fp_analysis_prompt(self, finding: Dict) -> str:
        """Build prompt for LLM false positive analysis"""
        return f"""
Analyze this Semgrep finding to determine if it's likely a false positive:

**Finding Details:**
- Rule ID: {finding.get('rule_id', 'unknown')}
- File: {finding.get('path', 'unknown')}
- Line: {finding.get('start_line', 'unknown')}
- Severity: {finding.get('severity', 'unknown')}
- Message: {finding.get('message', 'unknown')}

**Code Context:**
```python
{finding.get('code', 'No code available')}
```

**Additional Context:**
- Description: {finding.get('description', 'No description')}
- CWE: {finding.get('cwe', [])}
- OWASP: {finding.get('owasp', [])}

**Analysis Instructions:**
1. Consider if this is test code, mock code, or development code
2. Check if the vulnerability is intentional (e.g., testing edge cases)
3. Look for patterns that indicate this is not production code
4. Consider if the finding is in a safe context (logging, debugging, etc.)

**Response Format:**
Provide a JSON response with:
{{
    "is_false_positive": true/false,
    "confidence": 0.0-1.0,
    "reasoning": "explanation of your decision",
    "key_indicators": ["list", "of", "key", "indicators"]
}}

Return ONLY the JSON response, no additional text.
"""
    
    def _extract_confidence_from_llm_response(self, response: str) -> float:
        """Extract confidence score from LLM response"""
        try:
            import json
            # Clean the response
            cleaned = response.strip()
            if cleaned.startswith('```json'):
                cleaned = cleaned[7:]
            if cleaned.endswith('```'):
                cleaned = cleaned[:-3]
            
            data = json.loads(cleaned)
            return data.get('confidence', 0.5)
            
        except Exception as e:
            logger.warning(f"Failed to parse LLM response: {e}")
            # Fallback: look for confidence in text
            if 'false positive' in response.lower():
                return 0.7
            elif 'true positive' in response.lower():
                return 0.3
            else:
                return 0.5
    
    def _is_test_context(self, code: str, message: str) -> bool:
        """Check if code appears to be in a test context"""
        test_indicators = [
            'test_',
            'assert',
            'unittest',
            'pytest',
            'mock',
            'patch',
            'fixture',
            'setup',
            'teardown'
        ]
        
        code_lower = code.lower()
        message_lower = message.lower()
        
        for indicator in test_indicators:
            if indicator in code_lower or indicator in message_lower:
                return True
        
        return False
    
    def _is_debug_context(self, code: str, message: str) -> bool:
        """Check if code appears to be debug/development code"""
        debug_indicators = [
            'debug',
            'print(',
            'console.log',
            'logging.',
            'logger.',
            'TODO:',
            'FIXME:',
            'HACK:',
            'XXX:'
        ]
        
        code_lower = code.lower()
        message_lower = message.lower()
        
        for indicator in debug_indicators:
            if indicator in code_lower or indicator in message_lower:
                return True
        
        return False
    
    def get_filter_stats(self) -> Dict:
        """Get statistics about filter performance"""
        return {
            'total_analyses': 0,  # Would be tracked in production
            'rule_based_matches': {},
            'llm_analyses': 0,
            'average_confidence': 0.0
        }
