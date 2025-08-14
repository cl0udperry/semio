def parse_semgrep_json(data):
    """
    Parse semgrep JSON results and extract structured vulnerability data.
    Enhanced to provide more context for LLM fix generation.
    """
    results = []
    for finding in data.get("results", []):
        # Extract basic vulnerability info
        vuln_data = {
            "rule_id": finding.get("check_id"),
            "path": finding.get("path"),
            "start_line": finding["start"]["line"],
            "end_line": finding.get("end", {}).get("line", finding["start"]["line"]),
            "code": finding["extra"].get("lines"),
            "message": finding["extra"].get("message", ""),
            "severity": finding.get("extra", {}).get("severity", "UNKNOWN"),
            "metadata": finding.get("extra", {})
        }
        
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

def extract_context_for_fix(vuln_data):
    """
    Extract additional context that might be useful for generating fixes.
    """
    return {
        "vulnerability_type": vuln_data["rule_id"],
        "file_path": vuln_data["path"],
        "line_number": vuln_data["start_line"],
        "vulnerable_code": vuln_data["code"],
        "severity": vuln_data["severity"],
        "description": vuln_data.get("description", ""),
        "cwe_ids": vuln_data.get("cwe", []),
        "owasp_categories": vuln_data.get("owasp", [])
    }