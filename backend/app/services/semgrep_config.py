"""
Semgrep Configuration Helper for Semio Integration
"""

def get_optimal_semgrep_command(
    target_path: str = ".",
    rules: str = "auto",
    output_file: str = "semgrep-results.json",
    include_parse_tree: bool = True,
    max_lines_per_finding: int = 20,
    additional_flags: list = None
) -> str:
    """
    Generate optimal Semgrep command for Semio integration.
    
    Args:
        target_path: Path to scan
        rules: Rules to use (auto, p/security-audit, etc.)
        output_file: Output JSON file
        include_parse_tree: Whether to include parse tree for better code extraction
        max_lines_per_finding: Maximum lines per finding for context
        additional_flags: Additional Semgrep flags
    
    Returns:
        Formatted Semgrep command
    """
    base_cmd = f"semgrep --json --output {output_file}"
    
    if include_parse_tree:
        base_cmd += " --include-parse-tree"
    
    if max_lines_per_finding:
        base_cmd += f" --max-lines-per-finding {max_lines_per_finding}"
    
    base_cmd += f" --config {rules}"
    
    if additional_flags:
        base_cmd += " " + " ".join(additional_flags)
    
    base_cmd += f" {target_path}"
    
    return base_cmd

def get_semgrep_recommendations(validation_result: dict) -> list:
    """
    Generate specific recommendations based on validation results.
    """
    recommendations = []
    
    if validation_result.get("findings_without_code", 0) > 0:
        recommendations.append({
            "type": "warning",
            "message": "Some findings lack code context",
            "solution": "Use --include-parse-tree flag for better code extraction",
            "command": "semgrep --json --include-parse-tree --max-lines-per-finding 20 --config auto ."
        })
    
    if validation_result.get("total_findings", 0) == 0:
        recommendations.append({
            "type": "info",
            "message": "No vulnerabilities found",
            "solution": "Try different rule sets or scan different directories",
            "command": "semgrep --json --config p/security-audit ."
        })
    
    return recommendations

def validate_semgrep_installation() -> dict:
    """
    Validate Semgrep installation and version.
    """
    import subprocess
    import sys
    
    result = {
        "installed": False,
        "version": None,
        "recommendation": None
    }
    
    try:
        # Check if semgrep is available
        process = subprocess.run(
            ["semgrep", "--version"], 
            capture_output=True, 
            text=True, 
            timeout=10
        )
        
        if process.returncode == 0:
            result["installed"] = True
            result["version"] = process.stdout.strip()
            
            # Check version compatibility
            if "1.0" in result["version"] or "0.9" in result["version"]:
                result["recommendation"] = "Consider upgrading to Semgrep 1.0+ for better features"
        else:
            result["recommendation"] = "Semgrep command failed. Check installation."
            
    except FileNotFoundError:
        result["recommendation"] = "Semgrep not found. Install with: pip install semgrep"
    except subprocess.TimeoutExpired:
        result["recommendation"] = "Semgrep command timed out. Check installation."
    except Exception as e:
        result["recommendation"] = f"Error checking Semgrep: {str(e)}"
    
    return result

def create_semgrep_config_file(config_path: str = ".semgrep.yml") -> str:
    """
    Create a sample Semgrep configuration file optimized for Semio.
    """
    config_content = """# Semgrep configuration optimized for Semio integration
rules:
  # Security rules
  - id: semgrep-security-audit
    pattern: p/security-audit
  
  # Additional security rules
  - id: semgrep-best-practices
    pattern: p/best-practices
  
  # Language-specific rules
  - id: python-security
    pattern: p/python
    languages: [python]
  
  - id: javascript-security
    pattern: p/javascript
    languages: [javascript, typescript]

# Output configuration
output:
  format: json
  include-parse-tree: true
  max-lines-per-finding: 20

# Scan configuration
scan:
  exclude:
    - "**/node_modules/**"
    - "**/venv/**"
    - "**/.git/**"
    - "**/dist/**"
    - "**/build/**"
"""
    
    try:
        with open(config_path, 'w') as f:
            f.write(config_content)
        return f"Configuration file created: {config_path}"
    except Exception as e:
        return f"Failed to create config file: {str(e)}"
