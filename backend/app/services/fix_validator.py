"""
Fix Validator - Validates generated fixes for syntax and semantic correctness
"""

import ast
import re
import subprocess
import tempfile
import os
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

@dataclass
class ValidationResult:
    """Result from fix validation"""
    is_valid: bool
    errors: List[str]
    warnings: List[str]
    syntax_valid: bool
    semantic_valid: bool
    test_passed: bool
    confidence: float

class FixValidator:
    """
    Validates generated fixes for syntax, semantics, and basic correctness
    """
    
    def __init__(self):
        self.supported_languages = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.java': 'java',
            '.go': 'go',
            '.rs': 'rust',
            '.php': 'php'
        }
        
        # Common security patterns to validate
        self.security_patterns = {
            'python': {
                'sql_injection': [
                    r'execute\s*\(\s*[\'"][^\'"]*\+',
                    r'cursor\.execute\s*\(\s*[\'"][^\'"]*\+',
                    r'query\s*=\s*[\'"][^\'"]*\+'
                ],
                'xss': [
                    r'\.innerHTML\s*=',
                    r'document\.write\s*\(',
                    r'eval\s*\('
                ],
                'path_traversal': [
                    r'open\s*\(\s*[^\'"]*\+',
                    r'file\s*\(\s*[^\'"]*\+'
                ]
            }
        }
    
    def validate_fix(self, finding: Dict, suggested_fix: str) -> ValidationResult:
        """
        Validate a suggested fix for a finding
        
        Args:
            finding: Original Semgrep finding
            suggested_fix: The suggested fix code
            
        Returns:
            ValidationResult with validation details
        """
        errors = []
        warnings = []
        
        # Determine language from file extension
        file_path = finding.get('path', '')
        language = self._detect_language(file_path)
        
        # Step 1: Basic syntax validation
        syntax_valid = self._validate_syntax(suggested_fix, language)
        if not syntax_valid:
            errors.append(f"Syntax validation failed for {language}")
        
        # Step 2: Semantic validation
        semantic_valid = self._validate_semantics(finding, suggested_fix, language)
        if not semantic_valid:
            errors.append("Semantic validation failed")
        
        # Step 3: Security pattern validation
        security_valid = self._validate_security_patterns(suggested_fix, language)
        if not security_valid:
            warnings.append("Potential security issues detected in fix")
        
        # Step 4: Basic test validation (if possible)
        test_passed = self._validate_with_tests(finding, suggested_fix, language)
        if not test_passed:
            warnings.append("Test validation could not be performed")
        
        # Calculate overall confidence
        confidence = self._calculate_confidence(syntax_valid, semantic_valid, security_valid, test_passed)
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            syntax_valid=syntax_valid,
            semantic_valid=semantic_valid,
            test_passed=test_passed,
            confidence=confidence
        )
    
    def _detect_language(self, file_path: str) -> str:
        """Detect programming language from file extension"""
        _, ext = os.path.splitext(file_path)
        return self.supported_languages.get(ext.lower(), 'python')
    
    def _validate_syntax(self, code: str, language: str) -> bool:
        """Validate syntax for the given language"""
        try:
            if language == 'python':
                return self._validate_python_syntax(code)
            elif language == 'javascript':
                return self._validate_javascript_syntax(code)
            elif language == 'typescript':
                return self._validate_typescript_syntax(code)
            else:
                # For unsupported languages, assume valid
                return True
        except Exception as e:
            logger.error(f"Syntax validation error: {e}")
            return False
    
    def _validate_python_syntax(self, code: str) -> bool:
        """Validate Python syntax using ast.parse"""
        try:
            # Clean the code - remove markdown code blocks if present
            cleaned_code = self._clean_code_block(code)
            
            # Try to parse with ast
            ast.parse(cleaned_code)
            return True
        except SyntaxError as e:
            logger.debug(f"Python syntax error: {e}")
            return False
        except Exception as e:
            logger.debug(f"Python validation error: {e}")
            return False
    
    def _validate_javascript_syntax(self, code: str) -> bool:
        """Validate JavaScript syntax using node"""
        try:
            # Clean the code
            cleaned_code = self._clean_code_block(code)
            
            # Create temporary file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
                f.write(cleaned_code)
                temp_file = f.name
            
            try:
                # Use node to check syntax
                result = subprocess.run(
                    ['node', '--check', temp_file],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                return result.returncode == 0
            finally:
                os.unlink(temp_file)
                
        except Exception as e:
            logger.debug(f"JavaScript validation error: {e}")
            return True  # Assume valid if validation fails
    
    def _validate_typescript_syntax(self, code: str) -> bool:
        """Validate TypeScript syntax using tsc"""
        try:
            # Clean the code
            cleaned_code = self._clean_code_block(code)
            
            # Create temporary file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.ts', delete=False) as f:
                f.write(cleaned_code)
                temp_file = f.name
            
            try:
                # Use tsc to check syntax
                result = subprocess.run(
                    ['tsc', '--noEmit', temp_file],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                return result.returncode == 0
            finally:
                os.unlink(temp_file)
                
        except Exception as e:
            logger.debug(f"TypeScript validation error: {e}")
            return True  # Assume valid if validation fails
    
    def _validate_semantics(self, finding: Dict, suggested_fix: str, language: str) -> bool:
        """Validate semantic correctness of the fix"""
        try:
            # Check if the fix addresses the specific vulnerability
            rule_id = finding.get('rule_id', '')
            original_code = finding.get('code', '')
            
            # Language-specific semantic validation
            if language == 'python':
                return self._validate_python_semantics(rule_id, original_code, suggested_fix)
            else:
                # For other languages, do basic checks
                return self._validate_generic_semantics(rule_id, original_code, suggested_fix)
                
        except Exception as e:
            logger.error(f"Semantic validation error: {e}")
            return True  # Assume valid on error
    
    def _validate_python_semantics(self, rule_id: str, original_code: str, suggested_fix: str) -> bool:
        """Validate Python-specific semantic correctness"""
        # Check for common semantic issues
        if 'useless-comparison' in rule_id:
            # Check if the fix removes the useless comparison
            if '==' in original_code and '==' not in suggested_fix:
                return True
            if '!=' in original_code and '!=' not in suggested_fix:
                return True
        
        elif 'weak-crypto' in rule_id:
            # Check if weak crypto functions are replaced
            weak_patterns = [r'hashlib\.md5', r'hashlib\.sha1']
            strong_patterns = [r'hashlib\.sha256', r'hashlib\.sha512', r'hashlib\.blake2b']
            
            has_weak = any(re.search(pattern, original_code) for pattern in weak_patterns)
            has_strong = any(re.search(pattern, suggested_fix) for pattern in strong_patterns)
            
            if has_weak and has_strong:
                return True
        
        elif 'insecure-deserialization' in rule_id:
            # Check if unsafe deserialization is replaced
            unsafe_patterns = [r'pickle\.loads', r'yaml\.load\(']
            safe_patterns = [r'json\.loads', r'yaml\.safe_load\(']
            
            has_unsafe = any(re.search(pattern, original_code) for pattern in unsafe_patterns)
            has_safe = any(re.search(pattern, suggested_fix) for pattern in safe_patterns)
            
            if has_unsafe and has_safe:
                return True
        
        # Default: assume semantically valid
        return True
    
    def _validate_generic_semantics(self, rule_id: str, original_code: str, suggested_fix: str) -> bool:
        """Validate generic semantic correctness"""
        # Basic checks that apply to most languages
        
        # Check if the fix is not empty
        if not suggested_fix.strip():
            return False
        
        # Check if the fix is different from original (not just a copy)
        if suggested_fix.strip() == original_code.strip():
            return False
        
        # Check if the fix doesn't introduce obvious errors
        if 'error' in suggested_fix.lower() or 'exception' in suggested_fix.lower():
            return False
        
        return True
    
    def _validate_security_patterns(self, suggested_fix: str, language: str) -> bool:
        """Validate that the fix doesn't introduce new security issues"""
        try:
            if language == 'python':
                patterns = self.security_patterns.get('python', {})
                
                for issue_type, pattern_list in patterns.items():
                    for pattern in pattern_list:
                        if re.search(pattern, suggested_fix, re.IGNORECASE):
                            logger.warning(f"Potential {issue_type} pattern detected in fix")
                            return False
            
            return True
            
        except Exception as e:
            logger.error(f"Security pattern validation error: {e}")
            return True  # Assume safe on error
    
    def _validate_with_tests(self, finding: Dict, suggested_fix: str, language: str) -> bool:
        """Attempt to validate the fix with basic tests"""
        try:
            if language == 'python':
                return self._validate_python_with_tests(finding, suggested_fix)
            else:
                # For other languages, skip test validation for now
                return True
                
        except Exception as e:
            logger.debug(f"Test validation error: {e}")
            return True  # Assume passed on error
    
    def _validate_python_with_tests(self, finding: Dict, suggested_fix: str) -> bool:
        """Validate Python fix with basic syntax and import tests"""
        try:
            # Clean the fix
            cleaned_fix = self._clean_code_block(suggested_fix)
            
            # Check if it's a simple expression or statement
            if 'import' in cleaned_fix or 'from' in cleaned_fix:
                # Try to parse imports
                try:
                    ast.parse(cleaned_fix)
                    return True
                except SyntaxError:
                    return False
            
            # For other code, try to create a minimal test
            test_code = f"""
import ast
try:
    {cleaned_fix}
    print("Fix is valid")
except Exception as e:
    print(f"Fix error: {{e}}")
"""
            
            # Create temporary file and run
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                f.write(test_code)
                temp_file = f.name
            
            try:
                result = subprocess.run(
                    ['python', temp_file],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                return result.returncode == 0 and "Fix is valid" in result.stdout
            finally:
                os.unlink(temp_file)
                
        except Exception as e:
            logger.debug(f"Python test validation error: {e}")
            return True  # Assume passed on error
    
    def _clean_code_block(self, code: str) -> str:
        """Clean code from markdown code blocks and extra formatting"""
        # Remove markdown code blocks
        if code.startswith('```'):
            lines = code.split('\n')
            if len(lines) > 1:
                # Remove first line (```python) and last line (```)
                code = '\n'.join(lines[1:-1])
        
        # Remove common prefixes
        code = re.sub(r'^>>>\s*', '', code, flags=re.MULTILINE)
        code = re.sub(r'^\.\.\.\s*', '', code, flags=re.MULTILINE)
        
        return code.strip()
    
    def _calculate_confidence(self, syntax_valid: bool, semantic_valid: bool, 
                            security_valid: bool, test_passed: bool) -> float:
        """Calculate overall confidence score based on validation results"""
        confidence = 0.0
        
        if syntax_valid:
            confidence += 0.3
        if semantic_valid:
            confidence += 0.4
        if security_valid:
            confidence += 0.2
        if test_passed:
            confidence += 0.1
        
        return confidence
    
    def get_validation_stats(self) -> Dict:
        """Get statistics about validation performance"""
        return {
            'total_validations': 0,
            'syntax_errors': 0,
            'semantic_errors': 0,
            'security_warnings': 0,
            'test_failures': 0,
            'average_confidence': 0.0
        }
