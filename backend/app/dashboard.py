"""
sem.io Gradio Dashboard
A web interface for sem.io security analysis
"""

import os
import json
import tempfile
import requests
from pathlib import Path
from typing import Dict, Any, Optional
import gradio as gr
from datetime import datetime

# Configuration
DEFAULT_API_URL = "http://localhost:8000"  # Fallback for local development
API_URL = os.getenv("SEMIO_API_URL", DEFAULT_API_URL)

def get_api_url() -> str:
    """Get API URL from environment or use default."""
    # For AWS deployment, try to get the instance URL
    api_url = os.getenv("SEMIO_API_URL")
    if api_url:
        return api_url
    
    # If no environment variable, try to construct from AWS instance metadata
    try:
        import requests
        # Try to get instance metadata (only works on AWS)
        response = requests.get("http://169.254.169.254/latest/meta-data/public-hostname", timeout=1)
        if response.status_code == 200:
            hostname = response.text.strip()
            return f"http://{hostname}:8000"
    except:
        pass
    
    # Fallback to localhost for local development
    return DEFAULT_API_URL

def analyze_semgrep_file(file) -> Dict[str, Any]:
    """Analyze Semgrep JSON file using Semio API."""
    if file is None:
        return {"error": "Please upload a Semgrep JSON file"}
    
    try:
        # Debug: Print file info
        print(f"File object: {file}")
        print(f"File type: {type(file)}")
        
        # Handle different file input types from Gradio
        if isinstance(file, list) and len(file) > 0:
            # Gradio returns a list of file paths
            file_path = file[0]
        elif isinstance(file, str):
            # Direct file path
            file_path = file
        elif hasattr(file, 'name'):
            # File object with name attribute
            file_path = file.name
        elif hasattr(file, 'file'):
            # Gradio file object with file attribute
            file_path = file.file.name
        else:
            file_path = str(file)
        
        print(f"Using file path: {file_path}")
        
        # Check if file exists
        if not os.path.exists(file_path):
            return {"error": f"File not found: {file_path}"}
        
        with open(file_path, 'r') as f:
            semgrep_data = json.load(f)
        
        # Debug: Print what we're about to send
        print(f"API URL: {get_api_url()}")
        print(f"Data type: {type(semgrep_data)}")
        print(f"Data keys: {list(semgrep_data.keys()) if isinstance(semgrep_data, dict) else 'Not a dict'}")
        print(f"Data preview: {str(semgrep_data)[:200]}...")
        
        # Make API request with UI headers
        headers = {
            "Content-Type": "application/json",
            "X-sem.io-UI": "gradio-dashboard",
            "User-Agent": "sem.io-Gradio-Dashboard/1.0"
        }
        
        print("Making request to public endpoint...")
        response = requests.post(
            f"{get_api_url()}/api/review-public",
            json=semgrep_data,
            headers=headers,
            timeout=300  # 5 minutes timeout
        )
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 429:
            return {"error": "Rate limit exceeded. Please try again later."}
        elif response.status_code == 403:
            return {"error": "Access denied. This endpoint can only be accessed through the Semio dashboard."}
        else:
            return {"error": f"API Error: {response.status_code} - {response.text}"}
            
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"Error details: {error_details}")
        return {"error": f"Error: {str(e)}\n\nDebug info: {error_details}"}

def generate_report(data: Dict[str, Any], format_type: str) -> str:
    """Generate report in specified format."""
    if "error" in data:
        return f"Error: {data['error']}"
    
    try:
        # Generate report locally using the ReportGenerator
        from app.services.report_generator import ReportGenerator
        report_gen = ReportGenerator()
        return report_gen.generate_report(data, format_type)
            
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"Report generation error: {error_details}")
        return f"Error generating {format_type} report: {str(e)}"

def create_sample_data() -> str:
    """Create sample Semgrep JSON data for testing."""
    sample_data = {
        "version": "1.131.0",
        "results": [
            {
                "check_id": "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
                "path": "test-files/test.py",
                "start": {
                    "line": 11,
                    "col": 47,
                    "offset": 336
                },
                "end": {
                    "line": 11,
                    "col": 51,
                    "offset": 340
                },
                "extra": {
                    "message": "Found 'subprocess' function 'call' with 'shell=True'. This is dangerous because this call will spawn the command using a shell process. Doing so propagates current shell settings and variables, which makes it much easier for a malicious actor to execute commands. Use 'shell=False' instead.",
                    "lines": "subprocess.call(f\"ls {user_input}\", shell=True)  # Command injection",
                    "fix": "False",
                    "metadata": {
                        "source-rule-url": "https://bandit.readthedocs.io/en/latest/plugins/b602_subprocess_popen_with_shell_equals_true.html",
                        "owasp": [
                            "A01:2017 - Injection",
                            "A03:2021 - Injection"
                        ],
                        "cwe": [
                            "CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')"
                        ],
                        "category": "security",
                        "technology": [
                            "python"
                        ],
                        "likelihood": "HIGH",
                        "impact": "LOW",
                        "confidence": "MEDIUM",
                        "vulnerability_class": [
                            "Command Injection"
                        ]
                    },
                    "severity": "ERROR",
                    "fingerprint": "sample-fingerprint-1"
                },
                "start_line": 11,
                "end_line": 11,
                "source_code": {
                    "file_path": "test-files/test.py",
                    "start_line": 11,
                    "end_line": 11,
                    "vulnerable_lines": [
                        "    6: ",
                        "    7: def vulnerable_function(user_input):",
                        "    8:     # SQL Injection vulnerability",
                        "    9:     query = f\"SELECT * FROM users WHERE id = {user_input}\"",
                        "   10:     os.system(f\"echo {user_input}\")  # Command injection",
                        "   11:     subprocess.call(f\"ls {user_input}\", shell=True)  # Command injection",
                        "   12:     subprocess.Popen(f\"cat {user_input}\", shell=True)  # Command injection",
                        "   13:     return query"
                    ],
                    "context_lines": 5
                }
            },
            {
                "check_id": "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
                "path": "test-files/test.py",
                "start": {
                    "line": 12,
                    "col": 49,
                    "offset": 411
                },
                "end": {
                    "line": 12,
                    "col": 53,
                    "offset": 415
                },
                "extra": {
                    "message": "Found 'subprocess' function 'Popen' with 'shell=True'. This is dangerous because this call will spawn the command using a shell process. Doing so propagates current shell settings and variables, which makes it much easier for a malicious actor to execute commands. Use 'shell=False' instead.",
                    "lines": "subprocess.Popen(f\"cat {user_input}\", shell=True)  # Command injection",
                    "fix": "False",
                    "metadata": {
                        "source-rule-url": "https://bandit.readthedocs.io/en/latest/plugins/b602_subprocess_popen_with_shell_equals_true.html",
                        "owasp": [
                            "A01:2017 - Injection",
                            "A03:2021 - Injection"
                        ],
                        "cwe": [
                            "CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')"
                        ],
                        "category": "security",
                        "technology": [
                            "python"
                        ],
                        "likelihood": "HIGH",
                        "impact": "LOW",
                        "confidence": "MEDIUM",
                        "vulnerability_class": [
                            "Command Injection"
                        ]
                    },
                    "severity": "ERROR",
                    "fingerprint": "sample-fingerprint-2"
                },
                "start_line": 12,
                "end_line": 12,
                "source_code": {
                    "file_path": "test-files/test.py",
                    "start_line": 12,
                    "end_line": 12,
                    "vulnerable_lines": [
                        "    7: def vulnerable_function(user_input):",
                        "    8:     # SQL Injection vulnerability",
                        "    9:     query = f\"SELECT * FROM users WHERE id = {user_input}\"",
                        "   10:     os.system(f\"echo {user_input}\")  # Command injection",
                        "   11:     subprocess.call(f\"ls {user_input}\", shell=True)  # Command injection",
                        "   12:     subprocess.Popen(f\"cat {user_input}\", shell=True)  # Command injection",
                        "   13:     return query"
                    ],
                    "context_lines": 5
                }
            },
            {
                "check_id": "python.lang.security.audit.sql-injection.sql-injection",
                "path": "test-files/test.py",
                "start": {
                    "line": 9,
                    "col": 15,
                    "offset": 280
                },
                "end": {
                    "line": 9,
                    "col": 45,
                    "offset": 310
                },
                "extra": {
                    "message": "Possible SQL injection. Use parameterized queries instead of string formatting.",
                    "lines": "query = f\"SELECT * FROM users WHERE id = {user_input}\"",
                    "fix": "False",
                    "metadata": {
                        "category": "security",
                        "technology": [
                            "python"
                        ],
                        "likelihood": "HIGH",
                        "impact": "HIGH",
                        "confidence": "MEDIUM",
                        "vulnerability_class": [
                            "SQL Injection"
                        ]
                    },
                    "severity": "WARNING",
                    "fingerprint": "sample-fingerprint-3"
                },
                "start_line": 9,
                "end_line": 9,
                "source_code": {
                    "file_path": "test-files/test.py",
                    "start_line": 9,
                    "end_line": 9,
                    "vulnerable_lines": [
                        "    7: def vulnerable_function(user_input):",
                        "    8:     # SQL Injection vulnerability",
                        "    9:     query = f\"SELECT * FROM users WHERE id = {user_input}\"",
                        "   10:     os.system(f\"echo {user_input}\")  # Command injection",
                        "   11:     subprocess.call(f\"ls {user_input}\", shell=True)"
                    ],
                    "context_lines": 5
                }
            }
        ],
        "errors": [],
        "paths": {
            "scanned": [
                "test-files/test.py"
            ]
        },
        "time": {
            "rules": [],
            "rules_parse_time": 0.29289722442626953,
            "profiling_times": {
                "config_time": 1.4812743663787842,
                "core_time": 0.7768964767456055,
                "ignores_time": 0.0004923343658447266,
                "total_time": 2.259347915649414
            },
            "parsing_time": {
                "total_time": 0.009083032608032227,
                "per_file_time": {
                    "mean": 0.009083032608032227,
                    "std_dev": 0.0
                }
            },
            "scanning_time": {
                "total_time": 0.026292085647583008,
                "per_file_time": {
                    "mean": 0.013146042823791504,
                    "std_dev": 0.00015485658367708766
                }
            },
            "matching_time": {
                "total_time": 0.004363059997558594,
                "per_file_and_rule_time": {
                    "mean": 0.0008726119995117188,
                    "std_dev": 2.299781453984906e-06
                }
            },
            "tainting_time": {
                "total_time": 0.0007297992706298828,
                "per_def_and_rule_time": {
                    "mean": 0.00024326642354329428,
                    "std_dev": 5.105347453435468e-09
                }
            },
            "targets": [],
            "total_bytes": 0,
            "max_memory_bytes": 265479552
        },
        "engine_requested": "OSS",
        "skipped_rules": []
    }
    
    # Create temporary file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(sample_data, f, indent=2)
        return f.name

def format_results(data: Dict[str, Any]) -> str:
    """Format results for display."""
    if "error" in data:
        return f"**Error:** {data['error']}"
    
    # Create summary
    summary = f"""
# sem.io Security Analysis Results

**Upload ID:** {data.get('upload_id', 'N/A')}  
**Timestamp:** {data.get('timestamp', 'N/A')}

## Summary

- **Total Vulnerabilities:** {data.get('total_vulnerabilities', 0)}
- **Error Severity (High/Critical):** {data.get('error_severity_count', 0)}
- **Warning Severity (Medium):** {data.get('warning_severity_count', 0)}
- **Info Severity (Low):** {data.get('info_severity_count', 0)}
- **Unknown Severity:** {data.get('unknown_severity_count', 0)}
- **Errors:** {len(data.get('errors', []))}

## Severity Distribution
"""
    
    severity_dist = data.get('summary', {}).get('severity_distribution', {})
    for severity, count in severity_dist.items():
        summary += f"- **{severity}:** {count}\n"
    
    summary += "\n## Fix Types\n"
    fix_types = data.get('summary', {}).get('fix_types', {})
    for fix_type, count in fix_types.items():
        summary += f"- **{fix_type}:** {count}\n"
    
    # Add code context information
    code_stats = data.get('summary', {}).get('code_context_stats', {})
    if code_stats:
        summary += f"\n## Code Context Analysis\n"
        summary += f"- **Findings with Code:** {code_stats.get('findings_with_code', 0)}\n"
        summary += f"- **Findings without Code:** {code_stats.get('findings_without_code', 0)}\n"
    
    # Add Semgrep recommendations
    recommendations = data.get('summary', {}).get('semgrep_recommendations', [])
    if recommendations:
        summary += f"\n## Semgrep Recommendations\n"
        for rec in recommendations:
            summary += f"- {rec}\n"
    
    # Add findings and fixes
    findings = data.get('findings', [])
    fixes = data.get('fixes', [])
    
    if findings and fixes:
        summary += "\n## Vulnerabilities and Fixes\n\n"
        for i, (finding, fix) in enumerate(zip(findings, fixes), 1):
            confidence = f"{fix.get('confidence_score', 0) * 100:.1f}%"
            summary += f"""
### {i}. {finding.get('rule_id', 'Unknown Rule')}

**File:** `{finding.get('path', 'N/A')}`  
**Line:** {finding.get('start_line', 'N/A')}  
**Severity:** {finding.get('severity', 'N/A')}  
**Confidence:** {confidence}

**Vulnerable Code:**
```python
{finding.get('code', 'No code snippet available from Semgrep report')}
```

**Suggested Fix:**
```python
{fix.get('suggested_fix', 'N/A')}
```

**Explanation:** {fix.get('explanation', 'N/A')}

---
"""
    
    # Add errors if any
    errors = data.get('errors', [])
    if errors:
        summary += "\n## Errors\n\n"
        for error in errors:
            summary += f"- **{error.get('finding_id', 'Unknown')}** ({error.get('file', 'Unknown')}): {error.get('error', 'Unknown error')}\n"
    
    return summary

def create_dashboard():
    """Create the Gradio dashboard interface."""
    
    with gr.Blocks(
        title="sem.io - AI-Powered Security Intelligence",
        theme=gr.themes.Soft(),
        css="""
        .gradio-container {
            max-width: 1400px !important;
            background: #f8fafc;
            padding: 2rem;
        }
        .hero-section {
            background: linear-gradient(135deg, #1a202c 0%, #2d3748 100%);
            color: white;
            padding: 3rem 2rem;
            border-radius: 16px;
            margin-bottom: 2rem;
            text-align: center;
            box-shadow: 0 15px 40px rgba(0,0,0,0.2);
            border: 1px solid #4a5568;
        }
        .hero-title {
            font-size: 3rem;
            font-weight: 900;
            margin-bottom: 1.5rem;
            color: #ffffff;
            text-shadow: 0 2px 4px rgba(0,0,0,0.3);
            letter-spacing: -0.02em;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
        }
        .hero-subtitle {
            font-size: 1.4rem;
            margin-bottom: 2.5rem;
            color: #e2e8f0;
            line-height: 1.7;
            font-weight: 500;
            text-shadow: 0 1px 2px rgba(0,0,0,0.2);
        }
        .features-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 1.5rem;
            margin: 2.5rem 0;
        }
        .feature-card {
            background: rgba(255,255,255,0.15);
            padding: 2rem;
            border-radius: 16px;
            backdrop-filter: blur(15px);
            border: 2px solid rgba(255,255,255,0.25);
            box-shadow: 0 8px 25px rgba(0,0,0,0.15);
            transition: all 0.3s ease;
        }
        .feature-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 35px rgba(0,0,0,0.25);
            border-color: rgba(255,255,255,0.4);
        }
        .feature-title {
            font-weight: 800;
            margin-bottom: 1rem;
            font-size: 1.3rem;
            color: #ffffff;
            text-shadow: 0 1px 2px rgba(0,0,0,0.3);
            letter-spacing: -0.01em;
        }
        .feature-desc {
            color: #e2e8f0;
            line-height: 1.6;
            font-weight: 400;
            text-shadow: 0 1px 2px rgba(0,0,0,0.2);
        }
        .benefits-section {
            background: rgba(255,255,255,0.1);
            padding: 2.5rem;
            border-radius: 16px;
            margin-top: 2.5rem;
            border: 1px solid rgba(255,255,255,0.2);
        }
        .benefits-title {
            font-weight: 800;
            margin-bottom: 1.5rem;
            font-size: 1.4rem;
            color: #ffffff;
            text-shadow: 0 1px 2px rgba(0,0,0,0.3);
            letter-spacing: -0.01em;
        }
        .benefit-item {
            margin: 1rem 0;
            padding: 0.75rem 0;
            border-bottom: 1px solid rgba(255,255,255,0.15);
            color: #e2e8f0;
            line-height: 1.6;
            text-shadow: 0 1px 2px rgba(0,0,0,0.2);
        }
        .benefit-item strong {
            color: #ffffff;
            font-weight: 700;
        }
        .section-header {
            font-size: 1.8rem;
            font-weight: 800;
            margin-bottom: 2rem;
            color: #1a202c;
            border-bottom: 3px solid #667eea;
            padding-bottom: 0.75rem;
            letter-spacing: -0.01em;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: white;
            padding: 1.5rem;
            border-radius: 12px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.08);
            margin: 1rem 0;
        }
        .upload-section {
            background: #f8fafc !important;
            padding: 2.5rem !important;
            border-radius: 16px !important;
            border: 3px dashed #cbd5e0 !important;
            transition: all 0.3s ease !important;
            margin: 1rem 0 !important;
            box-shadow: 0 4px 15px rgba(0,0,0,0.08) !important;
        }
        .upload-container {
            background: #f8fafc !important;
            padding: 2.5rem !important;
            border-radius: 16px !important;
            border: 3px dashed #cbd5e0 !important;
            transition: all 0.3s ease !important;
            margin: 1rem 0 !important;
            box-shadow: 0 4px 15px rgba(0,0,0,0.08) !important;
            display: block !important;
            width: 100% !important;
        }
        .upload-container:hover {
            border-color: #667eea !important;
            background: #f1f5f9 !important;
            box-shadow: 0 8px 25px rgba(0,0,0,0.12) !important;
        }
        .upload-container > * {
            margin-bottom: 1rem !important;
        }
        .upload-container > *:last-child {
            margin-bottom: 0 !important;
        }
        .action-button {
            background: linear-gradient(135deg, #1a202c 0%, #2d3748 100%);
            border: none;
            color: white;
            font-weight: 800;
            padding: 1rem 2rem;
            border-radius: 12px;
            transition: all 0.3s ease;
            font-size: 1.1rem;
            letter-spacing: 0.01em;
            text-transform: uppercase;
            box-shadow: 0 4px 15px rgba(26, 32, 44, 0.3);
        }
        .action-button:hover {
            transform: translateY(-3px);
            box-shadow: 0 12px 30px rgba(26, 32, 44,0.4);
            background: linear-gradient(135deg, #2d3748 0%, #4a5568 100%);
        }
        .secondary-button {
            background: #4a5568;
            border: none;
            color: white;
            font-weight: 700;
            padding: 0.75rem 1.5rem;
            border-radius: 10px;
            transition: all 0.3s ease;
            font-size: 1rem;
            letter-spacing: 0.01em;
        }
        .secondary-button:hover {
            background: #2d3748;
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(74, 85, 104, 0.3);
        }
        .hero-quote {
            margin-top: 2.5rem;
            font-style: italic;
            opacity: 0.95;
            color: #e2e8f0;
            font-size: 1.1rem;
            font-weight: 500;
            line-height: 1.6;
            text-shadow: 0 1px 2px rgba(0,0,0,0.2);
            padding: 1.5rem;
            background: rgba(255,255,255,0.08);
            border-radius: 12px;
            border-left: 4px solid #667eea;
        }
        .gradio-row {
            background: white;
            padding: 2rem;
            border-radius: 16px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.08);
            margin: 1rem 0;
            border: 1px solid #e2e8f0;
        }
        """
    ) as dashboard:
        
        # Hero Section with Refined Pitch
        with gr.Row():
            gr.HTML("""
            <div class="hero-section">
                <div class="hero-title">sem.io cicd : AI Security Analysis Agent</div>
                <div class="hero-subtitle">
                    Stop drowning in false alarms. sem.io uses AI to analyze security scan results, filter out noise, and provide intelligent fix recommendations that developers can trust.
                </div>
                
                <div class="features-grid">
                    <div class="feature-card">
                        <div class="feature-title">AI-Powered Analysis</div>
                        <div class="feature-desc">Processes security scan results from tools like Semgrep using advanced AI</div>
                    </div>
                    <div class="feature-card">
                        <div class="feature-title">Intelligent Filtering</div>
                        <div class="feature-desc">Reduces noise by 80% by understanding code context and patterns</div>
                    </div>
                    <div class="feature-card">
                        <div class="feature-title">Smart Fixes</div>
                        <div class="feature-desc">Generates specific, tested solutions for each real security issue</div>
                    </div>
                    <div class="feature-card">
                        <div class="feature-title">Complete Transparency</div>
                        <div class="feature-desc">Tracks every analysis decision with full audit trails</div>
                    </div>
                </div>
                
                <div class="benefits-section">
                    <div class="benefits-title">How the Security Process Works:</div>
                    <div class="benefit-item">• <strong>Automated Scanning:</strong> Your CI/CD pipeline automatically triggers security scans on every code commit</div>
                    <div class="benefit-item">• <strong>AI Analysis:</strong> sem.io receives scan results and uses AI to separate real threats from false alarms</div>
                    <div class="benefit-item">• <strong>Actionable Insights:</strong> Provides prioritized, context-aware recommendations that developers can implement immediately</div>
                    <div class="benefit-item">• <strong>Continuous Learning:</strong> Improves accuracy over time by learning from your codebase patterns</div>
                </div>
                
                <div class="hero-quote">
                    Think of it as having a security expert who takes the raw output from your security tools and transforms it into clear, actionable intelligence that your team can trust and act upon.
                </div>
            </div>
            """)
        
        # Main Content Section
        # Security Analysis Engine Section
        with gr.Row():
            gr.HTML('<div class="section-header">Security Analysis Engine</div>')
        
        with gr.Row():
            with gr.Column(scale=1):
                # File upload section - using proper Gradio components with CSS styling
                with gr.Group(elem_classes=["upload-container"]):
                    file_input = gr.File(
                        label="Upload Semgrep JSON File",
                        file_types=[".json"],
                        file_count="single"
                    )
                    
                    # Sample data button
                    sample_btn = gr.Button("Load Sample Data", elem_classes=["secondary-button"])
                    
                    # Analyze button
                    analyze_btn = gr.Button("Analyze Vulnerabilities", elem_classes=["action-button"], size="lg")
                    
                    # Instructions text
                    gr.HTML('<p style="margin-top: 1rem; color: #4a5568; font-style: italic; text-align: center;">Upload a Semgrep JSON file and click "Analyze Vulnerabilities" to get started.</p>')
                
                # Status
                status_output = gr.Textbox(
                    label="Status",
                    interactive=False,
                    value="Ready to analyze..."
                )
                
                # File info display
                file_info = gr.Textbox(
                    label="Uploaded File",
                    interactive=False,
                    value="No file uploaded"
                )
            
            with gr.Column(scale=2):
                # Results display
                results_output = gr.Markdown(
                    label="Analysis Results",
                    value=""
                )
        
        # Report generation section
        with gr.Row():
            gr.HTML('<div class="section-header">Generate Reports</div>')
        
        with gr.Row():
            with gr.Column():
                with gr.Row():
                    json_btn = gr.Button("JSON Report", elem_classes=["secondary-button"])
                    md_btn = gr.Button("Markdown Report", elem_classes=["secondary-button"])
                    html_btn = gr.Button("HTML Report", elem_classes=["secondary-button"])
                
                report_output = gr.Textbox(
                    label="Generated Report",
                    lines=10,
                    value="Click a report button to generate..."
                )
        
        # Store current analysis data
        current_data = gr.State({})
        
        # Event handlers
        def analyze_file(file):
            print(f"Analyze file called with: {file}")
            print(f"File type: {type(file)}")
            
            if file is None or (isinstance(file, list) and len(file) == 0):
                return "Please upload a Semgrep JSON file", {}
            
            # Analyze file
            result = analyze_semgrep_file(file)
            
            if "error" in result:
                return f"**Error:** {result['error']}", {}
            
            # Format results for display
            formatted_results = format_results(result)
            
            return formatted_results, result
        
        def load_sample_data():
            sample_file = create_sample_data()
            return sample_file, "Sample data loaded! Click 'Analyze Vulnerabilities' to test.", f"{os.path.basename(sample_file)}"
        
        def update_file_info(file):
            if file is None or (isinstance(file, list) and len(file) == 0):
                return "No file uploaded"
            
            # Get filename from file object
            if isinstance(file, list) and len(file) > 0:
                filename = os.path.basename(file[0])
            elif isinstance(file, str):
                filename = os.path.basename(file)
            elif hasattr(file, 'name'):
                filename = os.path.basename(file.name)
            else:
                filename = "Unknown file"
            
            return f"{filename}"
        
        def generate_json_report(data):
            if not data:
                return "No analysis data available. Please analyze a file first."
            return json.dumps(data, indent=2)
        
        def generate_markdown_report(data):
            if not data:
                return "No analysis data available. Please analyze a file first."
            return generate_report(data, "markdown")
        
        def generate_html_report(data):
            if not data:
                return "No analysis data available. Please analyze a file first."
            return generate_report(data, "html")
        
        # Connect events
        analyze_btn.click(
            analyze_file,
            inputs=[file_input],
            outputs=[results_output, current_data]
        )
        
        sample_btn.click(
            load_sample_data,
            outputs=[file_input, status_output, file_info]
        )
        
        # Update file info when file is uploaded
        file_input.change(
            update_file_info,
            inputs=[file_input],
            outputs=[file_info]
        )
        
        json_btn.click(
            generate_json_report,
            inputs=[current_data],
            outputs=[report_output]
        )
        
        md_btn.click(
            generate_markdown_report,
            inputs=[current_data],
            outputs=[report_output]
        )
        
        html_btn.click(
            generate_html_report,
            inputs=[current_data],
            outputs=[report_output]
        )
        
        # Instructions
        gr.HTML("""
        <div class="main-content" style="margin-top: 2rem;">
            <div class="section-header">How to Use</div>
            
            <div style="line-height: 1.8; color: #4a5568;">
                <p><strong>1. Upload Semgrep Results:</strong> Upload a JSON file from your Semgrep scan</p>
                <p><strong>2. Analyze:</strong> Click "Analyze Vulnerabilities" to process with sem.io</p>
                <p><strong>3. Review:</strong> View detailed vulnerability analysis and AI-generated fixes</p>
                <p><strong>4. Generate Reports:</strong> Create JSON, Markdown, or HTML reports</p>
                <p><strong>5. Reach out for a Demo:</strong> Connect with me on <a href="https://www.linkedin.com/in/jordan-leong-69b57495/" target="_blank" style="color: #667eea; text-decoration: none;">LinkedIn</a> and drop me a message for a demo on a GitLab pipeline on how to use sem.io via CLI to automate the security analysis and fix recommendations.</p>
                <p><strong>6. (Near) Future enhancements:</strong></p>
                <ul style="margin-left: 2rem; margin-top: 0.5rem;">
                    <li>False Positive Filtering</li>
                    <li>Implementation of fixes into code for high confidence fixes (with human approval)</li>
                </ul>
            </div>
            
            <div class="section-header" style="margin-top: 2rem;">Testing</div>
            <p style="color: #4a5568;">Click "Load Sample Data" to test with example vulnerabilities including:</p>
            <ul style="color: #4a5568; margin-left: 2rem;">
                <li>Command injection vulnerabilities (subprocess with shell=True)</li>
                <li>SQL injection vulnerability</li>
            </ul>
        </div>
        """)
    
    return dashboard

if __name__ == "__main__":
    # Create and launch dashboard
    dashboard = create_dashboard()
    
    # Get server configuration from environment or use defaults
    server_host = os.getenv("SEMIO_DASHBOARD_HOST", "0.0.0.0")
    server_port = int(os.getenv("SEMIO_DASHBOARD_PORT", "7860"))
    
    print(f"Starting sem.io Dashboard on {server_host}:{server_port}")
    print(f"API URL: {get_api_url()}")
    
    dashboard.launch(
        server_name=server_host,
        server_port=server_port,
        share=False,
        show_error=True
    )
