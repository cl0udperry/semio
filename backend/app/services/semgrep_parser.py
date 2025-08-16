import os
import re
from typing import Dict, List, Optional

def parse_semgrep_json(data, include_code_context: bool = True):
    """
    Parse semgrep JSON results and extract structured vulnerability data.
    Enhanced to provide more context for LLM fix generation.
    
    Args:
        data: Semgrep JSON output
        include_code_context: Whether to attempt to extract code context
    """
    results = []
    for finding in data.get("results", []):
        # Extract basic vulnerability info
        vuln_data = {
            "rule_id": finding.get("check_id"),
            "path": finding.get("path"),
            "start_line": finding["start"]["line"],
            "end_line": finding.get("end", {}).get("line", finding["start"]["line"]),
            "code": None,  # Will be populated below
            "message": finding["extra"].get("message", ""),
            "severity": finding.get("extra", {}).get("metadata", {}).get("severity", "UNKNOWN"),
            "metadata": finding.get("extra", {}).get("metadata", {})
        }
        
        # Extract code using multiple strategies
        if include_code_context:
            vuln_data["code"] = extract_code_from_finding(finding)
        
        # Extract additional context for better LLM prompts
        if "extra" in finding:
            extra = finding["extra"]
            vuln_data.update({
                "description": extra.get("description", ""),
                "references": extra.get("references", []),
                "cwe": extra.get("cwe", []),
                "owasp": extra.get("owasp", [])
            })
        
        results.append(vuln_data)
    
    return results

def extract_code_from_finding(finding: Dict) -> Optional[str]:
    """
    Extract code from a Semgrep finding using multiple strategies.
    
    Priority order:
    1. Lines from extra.lines (if available)
    2. Source from extra.source (if available)
    3. Parse tree extraction (if available)
    4. Manual file reading fallback
    """
    extra = finding.get("extra", {})
    
    # Strategy 1: Try to get lines directly
    if extra.get("lines"):
        return extra["lines"]
    
    # Strategy 2: Try to get source
    if extra.get("source"):
        return extra["source"]
    
    # Strategy 3: Extract from parse tree if available
    parse_tree_code = extract_from_parse_tree(finding)
    if parse_tree_code:
        return parse_tree_code
    
    # Strategy 4: Manual file reading fallback
    file_path = finding.get("path")
    start_line = finding["start"]["line"]
    end_line = finding.get("end", {}).get("line", start_line)
    
    if file_path and os.path.exists(file_path):
        return read_code_from_file(file_path, start_line, end_line)
    
    return None

def extract_from_parse_tree(finding: Dict) -> Optional[str]:
    """
    Extract code from Semgrep's parse tree if available.
    This works when --include-parse-tree flag is used.
    """
    try:
        # Check if parse tree is available
        if "extra" in finding and "parse_tree" in finding["extra"]:
            parse_tree = finding["extra"]["parse_tree"]
            
            # Extract the actual code from parse tree
            # This is a simplified extraction - you might need to enhance this
            if isinstance(parse_tree, dict) and "text" in parse_tree:
                return parse_tree["text"]
            
            # Try to extract from other parse tree fields
            if isinstance(parse_tree, str):
                return parse_tree
                
    except Exception as e:
        print(f"Warning: Failed to extract from parse tree: {e}")
    
    return None

def read_code_from_file(file_path: str, start_line: int, end_line: int, context_lines: int = 3) -> Optional[str]:
    """
    Read code from file as a fallback when Semgrep doesn't provide code.
    
    Args:
        file_path: Path to the source file
        start_line: Starting line number
        end_line: Ending line number
        context_lines: Number of lines to include before and after
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        # Calculate line ranges with context
        file_start = max(1, start_line - context_lines)
        file_end = min(len(lines), end_line + context_lines)
        
        # Extract the relevant lines
        relevant_lines = lines[file_start - 1:file_end]
        
        # Add line numbers for clarity
        numbered_lines = []
        for i, line in enumerate(relevant_lines, file_start):
            prefix = ">>> " if start_line <= i <= end_line else "    "
            numbered_lines.append(f"{prefix}{i:4d}: {line.rstrip()}")
        
        return "".join(numbered_lines)
        
    except Exception as e:
        print(f"Warning: Failed to read code from file {file_path}: {e}")
        return None

def extract_context_for_fix(vuln_data):
    """
    Extract additional context that might be useful for generating fixes.
    """
    return {
        "vulnerability_type": vuln_data["rule_id"],
        "file_path": vuln_data["path"],
        "line_number": vuln_data["start_line"],
        "vulnerable_code": vuln_data["code"] or "Code not available",
        "severity": vuln_data["severity"],
        "description": vuln_data.get("description", ""),
        "cwe_ids": vuln_data.get("cwe", []),
        "owasp_categories": vuln_data.get("owasp", [])
    }

def validate_semgrep_output(data: Dict) -> Dict[str, any]:
    """
    Validate Semgrep output and provide recommendations for better results.
    """
    results = data.get("results", [])
    validation = {
        "total_findings": len(results),
        "findings_with_code": 0,
        "findings_without_code": 0,
        "recommendations": []
    }
    
    for finding in results:
        code = extract_code_from_finding(finding)
        if code:
            validation["findings_with_code"] += 1
        else:
            validation["findings_without_code"] += 1
    
    # Generate recommendations
    if validation["findings_without_code"] > 0:
        validation["recommendations"].append(
            "Use '--include-parse-tree' flag for better code extraction"
        )
        validation["recommendations"].append(
            "Use '--max-lines-per-finding 20' to include more context"
        )
        validation["recommendations"].append(
            "Ensure source files are accessible for fallback code reading"
        )
    
    return validation