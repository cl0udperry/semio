# Semio GitLab Integration Guide

This guide explains how to integrate Semio with your GitLab CI/CD pipeline for automated security analysis and fix generation.

## Overview

Semio provides CLI-specific endpoints that allow direct API access with API key authentication, perfect for GitLab pipeline integration. These endpoints:

- **No rate limiting** - Designed for CI/CD workflows
- **API key authentication** - Simple and secure
- **Multiple output formats** - JSON, Markdown, HTML
- **Enhanced agentic analysis** - For automated fix application

## Quick Setup

### 1. Set GitLab CI/CD Variables

Go to your GitLab project → Settings → CI/CD → Variables and add:

```bash
# Required
SEMIO_API_URL = "http://semio-production.eba-di323hkd.ap-southeast-1.elasticbeanstalk.com"
SEMIO_API_KEY = "your-api-key-here"

# Optional
SEMGREP_CONFIG = "auto"  # or path to custom config
```

### 2. Add GitLab CI Configuration

Copy the example configuration to your project's `.gitlab-ci.yml`:

```yaml
# Basic Semio integration
semio-analysis:
  stage: analyze
  image: python:3.9-slim
  before_script:
    - pip install requests
  script:
    - |
      curl -X POST "$SEMIO_API_URL/api/review-cli" \
        -H "Content-Type: application/json" \
        -d @semgrep-results.json \
        --data-urlencode "api_key=$SEMIO_API_KEY" \
        --data-urlencode "format=json" \
        -o semio-report.json
  artifacts:
    paths: [semio-report.json]
  dependencies:
    - semgrep-scan
```

## Available Endpoints

### 1. Basic CLI Endpoint
```bash
POST /api/review-cli
```

**Parameters:**
- `api_key` (required): Your Semio API key
- `format` (optional): `json`, `markdown`, `html` (default: `json`)
- `include_code_context` (optional): `true`/`false` (default: `true`)
- `custom_prompt` (optional): Custom prompt for analysis

**Example:**
```bash
curl -X POST "http://semio-production.eba-di323hkd.ap-southeast-1.elasticbeanstalk.com/api/review-cli" \
  -H "Content-Type: application/json" \
  -d @semgrep-results.json \
  --data-urlencode "api_key=your-api-key" \
  --data-urlencode "format=json"
```

### 2. Agentic CLI Endpoint
```bash
POST /api/review-agentic-cli
```

**Enhanced features:**
- Validation data for automated fix application
- Context information for better understanding
- Dependency tracking
- Metadata for fix categorization

**Example:**
```bash
curl -X POST "http://semio-production.eba-di323hkd.ap-southeast-1.elasticbeanstalk.com/api/review-agentic-cli" \
  -H "Content-Type: application/json" \
  -d @semgrep-results.json \
  --data-urlencode "api_key=your-api-key" \
  --data-urlencode "format=json"
```

## Response Format

### Basic Response
```json
{
  "upload_id": "abc123_def456",
  "timestamp": "2024-01-15T10:30:00",
  "total_vulnerabilities": 5,
  "high_confidence_fixes": 3,
  "medium_confidence_fixes": 1,
  "low_confidence_fixes": 1,
  "findings": [...],
  "fixes": [...],
  "summary": {
    "severity_distribution": {"HIGH": 2, "MEDIUM": 3},
    "fix_types": {"code_replacement": 4, "import_addition": 1},
    "code_context_stats": {
      "findings_with_code": 5,
      "findings_without_code": 0,
      "code_coverage_percentage": 100.0
    }
  },
  "errors": []
}
```

### Enhanced Agentic Response
```json
{
  "fixes": [
    {
      "fix_id": "fix_123",
      "confidence_score": 0.95,
      "fix_type": "code_replacement",
      "original_code": "import hashlib\nhashlib.md5()",
      "fixed_code": "import hashlib\nhashlib.sha256()",
      "validation": {
        "syntax_check": "valid",
        "semantic_check": "valid",
        "security_check": "improved"
      },
      "context": {
        "scope": "function",
        "dependencies": ["hashlib"],
        "impact": "medium"
      },
      "dependencies": {
        "requires_fixes": [],
        "conflicts_with": []
      },
      "metadata": {
        "fix_category": "cryptography",
        "priority": "high",
        "estimated_time": "5 minutes"
      }
    }
  ]
}
```

## 🛠️ Complete GitLab CI/CD Example

See `gitlab-ci-example.yml` for a complete pipeline configuration that includes:

- Semgrep security scanning
- Semio basic analysis
- Semio agentic analysis
- Multiple report formats (JSON, Markdown, HTML)
- Security summary generation
- Automated fix application (high confidence)
- Manual review workflow (medium/low confidence)

## Testing Your Integration

### 1. Test Locally
```bash
# Set environment variables
export SEMIO_API_URL="http://semio-production.eba-di323hkd.ap-southeast-1.elasticbeanstalk.com"
export SEMIO_API_KEY="your-api-key"

# Run the test script
python test_gitlab_integration.py
```

### 2. Test with CLI Tool
```bash
# Set environment variables
export SEMIO_API_URL="http://semio-production.eba-di323hkd.ap-southeast-1.elasticbeanstalk.com"
export SEMIO_API_KEY="your-api-key"
export SEMGREP_FILE="semgrep-results.json"

# Run CLI tool
python semio_cli.py
```

## Security Best Practices

### 1. API Key Management
- Store API keys in GitLab CI/CD Variables (not in code)
- Use masked variables for sensitive data
- Rotate API keys regularly
- Use different keys for different environments

### 2. Pipeline Security
- Run security scans on merge requests
- Block merges with high-severity vulnerabilities
- Review medium/low confidence fixes manually
- Store reports as artifacts for audit trails

### 3. Access Control
- Limit API key permissions
- Monitor API usage
- Set up alerts for unusual activity

## Advanced Features

### 1. Custom Prompts
```bash
curl -X POST "$SEMIO_API_URL/api/review-cli" \
  -H "Content-Type: application/json" \
  -d @semgrep-results.json \
  --data-urlencode "api_key=$SEMIO_API_KEY" \
  --data-urlencode "custom_prompt=Focus on OWASP Top 10 vulnerabilities"
```

### 2. Multiple Output Formats
```bash
# JSON (default)
--data-urlencode "format=json"

# Markdown
--data-urlencode "format=markdown"

# HTML
--data-urlencode "format=html"
```

### 3. Code Context Control
```bash
# Include code context (default)
--data-urlencode "include_code_context=true"

# Exclude code context (faster processing)
--data-urlencode "include_code_context=false"
```

## Troubleshooting

### Common Issues

1. **401 Unauthorized**
   - Check API key is correct
   - Verify API key is not expired
   - Ensure API key has proper permissions

2. **400 Bad Request**
   - Verify Semgrep JSON format is correct
   - Check required fields are present
   - Validate JSON syntax

3. **503 Service Unavailable**
   - Check Semio service status
   - Verify network connectivity
   - Check rate limits (should not apply to CLI endpoints)

4. **Timeout Errors**
   - Increase timeout for large files
   - Check network connectivity
   - Consider breaking large scans into smaller chunks

### Debug Mode
Enable debug mode to get more detailed error information:

```bash
export DEBUG=true
python semio_cli.py
```

## 📞 Support

For issues or questions:

1. Check the troubleshooting section above
2. Review the API documentation
3. Test with the provided CLI tools
4. Contact support with error logs and configuration details

## 🔄 Updates

- **v1.0**: Initial CLI endpoints
- **v1.1**: Added agentic analysis
- **v1.2**: Enhanced validation and context data
- **v1.3**: Multiple output formats support

---

**Note**: This integration is designed for GitLab CI/CD pipelines and provides no rate limiting for automated workflows. For manual testing, use the web interface or standard API endpoints.
