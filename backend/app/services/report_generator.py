import json
import os
from datetime import datetime
from typing import Dict, List, Any
from jinja2 import Environment, FileSystemLoader, Template

class ReportGenerator:
    """Generate reports in JSON, Markdown, and HTML formats."""
    
    def __init__(self):
        # Set up Jinja2 environment
        template_dir = os.path.join(os.path.dirname(__file__), "..", "templates")
        if os.path.exists(template_dir):
            self.env = Environment(loader=FileSystemLoader(template_dir))
        else:
            # Fallback to string templates if directory doesn't exist
            self.env = None
    
    def generate_json_report(self, data: Dict[str, Any]) -> str:
        """Generate JSON report."""
        return json.dumps(data, indent=2, ensure_ascii=False)
    
    def generate_markdown_report(self, data: Dict[str, Any]) -> str:
        """Generate Markdown report."""
        if self.env:
            template = self.env.get_template("report.md.j2")
        else:
            template = self._get_markdown_template()
        
        return template.render(data=data, timestamp=datetime.now(), zip=zip)
    
    def generate_html_report(self, data: Dict[str, Any]) -> str:
        """Generate HTML report."""
        if self.env:
            template = self.env.get_template("report.html.j2")
        else:
            template = self._get_html_template()
        
        return template.render(data=data, timestamp=datetime.now(), zip=zip)
    
    def generate_report(self, data: Dict[str, Any], format_type: str = "json") -> str:
        """Generate report in specified format."""
        format_type = format_type.lower()
        
        if format_type == "json":
            return self.generate_json_report(data)
        elif format_type == "markdown":
            return self.generate_markdown_report(data)
        elif format_type == "html":
            return self.generate_html_report(data)
        else:
            raise ValueError(f"Unsupported format: {format_type}")
    
    def _get_markdown_template(self) -> Template:
        """Fallback markdown template."""
        template_str = """
# Security Analysis Report

**Generated:** {{ timestamp.strftime('%Y-%m-%d %H:%M:%S') }}  
**Upload ID:** {{ data.upload_id }}

## Summary

- **Total Vulnerabilities:** {{ data.total_vulnerabilities }}
- **High Confidence Fixes:** {{ data.high_confidence_fixes }}
- **Medium Confidence Fixes:** {{ data.medium_confidence_fixes }}
- **Low Confidence Fixes:** {{ data.low_confidence_fixes }}
- **Errors:** {{ data.errors|length }}

## Severity Distribution

{% for severity, count in data.summary.severity_distribution.items() %}
- **{{ severity }}:** {{ count }}
{% endfor %}

## Fix Types

{% for fix_type, count in data.summary.fix_types.items() %}
- **{{ fix_type }}:** {{ count }}
{% endfor %}

## Vulnerabilities and Fixes

{% for finding, fix in zip(data.findings, data.fixes) %}
### {{ finding.rule_id }}

**File:** `{{ finding.path }}`  
**Line:** {{ finding.start_line }}  
**Severity:** {{ finding.severity }}  
**Message:** {{ finding.message }}

**Vulnerable Code:**
```{{ finding.path.split('.')[-1] if '.' in finding.path else 'text' }}
{{ finding.code }}
```

**Suggested Fix:**
```{{ finding.path.split('.')[-1] if '.' in finding.path else 'text' }}
{{ fix.suggested_fix }}
```

**Confidence:** {{ "%.1f"|format(fix.confidence_score * 100) }}%  
**Impact:** {{ fix.impact }}  
**Explanation:** {{ fix.explanation }}

{% if fix.required_imports %}
**Required Imports:**
{% for import_stmt in fix.required_imports %}
```{{ finding.path.split('.')[-1] if '.' in finding.path else 'text' }}
{{ import_stmt }}
```
{% endfor %}
{% endif %}

---
{% endfor %}

{% if data.errors %}
## Errors

{% for error in data.errors %}
- **{{ error.finding_id }}** ({{ error.file }}): {{ error.error }}
{% endfor %}
{% endif %}
"""
        return Template(template_str)
    
    def _get_html_template(self) -> Template:
        """Fallback HTML template."""
        template_str = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
        .header { background: #f5f5f5; padding: 20px; border-radius: 5px; margin-bottom: 30px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .summary-card { background: #fff; border: 1px solid #ddd; padding: 15px; border-radius: 5px; }
        .vulnerability { background: #fff; border: 1px solid #ddd; margin: 20px 0; padding: 20px; border-radius: 5px; }
        .code-block { background: #f8f8f8; padding: 15px; border-radius: 5px; overflow-x: auto; }
        .high-confidence { border-left: 4px solid #28a745; }
        .medium-confidence { border-left: 4px solid #ffc107; }
        .low-confidence { border-left: 4px solid #dc3545; }
        .confidence-badge { padding: 4px 8px; border-radius: 3px; color: white; font-size: 12px; }
        .high { background: #28a745; }
        .medium { background: #ffc107; color: #000; }
        .low { background: #dc3545; }
        .errors { background: #f8d7da; border: 1px solid #f5c6cb; padding: 15px; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Analysis Report</h1>
        <p><strong>Generated:</strong> {{ timestamp.strftime('%Y-%m-%d %H:%M:%S') }}</p>
        <p><strong>Upload ID:</strong> {{ data.upload_id }}</p>
    </div>

    <div class="summary">
        <div class="summary-card">
            <h3>Total Vulnerabilities</h3>
            <p style="font-size: 24px; font-weight: bold;">{{ data.total_vulnerabilities }}</p>
        </div>
        <div class="summary-card">
            <h3>High Confidence Fixes</h3>
            <p style="font-size: 24px; font-weight: bold; color: #28a745;">{{ data.high_confidence_fixes }}</p>
        </div>
        <div class="summary-card">
            <h3>Medium Confidence Fixes</h3>
            <p style="font-size: 24px; font-weight: bold; color: #ffc107;">{{ data.medium_confidence_fixes }}</p>
        </div>
        <div class="summary-card">
            <h3>Low Confidence Fixes</h3>
            <p style="font-size: 24px; font-weight: bold; color: #dc3545;">{{ data.low_confidence_fixes }}</p>
        </div>
    </div>

    {% if data.findings and data.fixes %}
    <h2>Vulnerabilities and Fixes</h2>
    {% for finding, fix in zip(data.findings, data.fixes) %}
    <div class="vulnerability {% if fix.confidence_score >= 0.8 %}high-confidence{% elif fix.confidence_score >= 0.5 %}medium-confidence{% else %}low-confidence{% endif %}">
        <h3>{{ finding.rule_id }}</h3>
        <p><strong>File:</strong> <code>{{ finding.path }}</code></p>
        <p><strong>Line:</strong> {{ finding.start_line }}</p>
        <p><strong>Severity:</strong> {{ finding.severity }}</p>
        <p><strong>Message:</strong> {{ finding.message }}</p>
        
        <h4>Vulnerable Code:</h4>
        <div class="code-block">
            <pre><code>{{ finding.code }}</code></pre>
        </div>
        
        <h4>Suggested Fix:</h4>
        <div class="code-block">
            <pre><code>{{ fix.suggested_fix }}</code></pre>
        </div>
        
        <p>
            <strong>Confidence:</strong> 
            <span class="confidence-badge {% if fix.confidence_score >= 0.8 %}high{% elif fix.confidence_score >= 0.5 %}medium{% else %}low{% endif %}">
                {{ "%.1f"|format(fix.confidence_score * 100) }}%
            </span>
        </p>
        <p><strong>Impact:</strong> {{ fix.impact }}</p>
        <p><strong>Explanation:</strong> {{ fix.explanation }}</p>
        
        {% if fix.required_imports %}
        <h4>Required Imports:</h4>
        {% for import_stmt in fix.required_imports %}
        <div class="code-block">
            <pre><code>{{ import_stmt }}</code></pre>
        </div>
        {% endfor %}
        {% endif %}
    </div>
    {% endfor %}
    {% endif %}

    {% if data.errors %}
    <div class="errors">
        <h2>Errors</h2>
        <ul>
        {% for error in data.errors %}
            <li><strong>{{ error.finding_id }}</strong> ({{ error.file }}): {{ error.error }}</li>
        {% endfor %}
        </ul>
    </div>
    {% endif %}
</body>
</html>
"""
        return Template(template_str)
