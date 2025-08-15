# 🔒 Semio DevSecOps Demo

This repository demonstrates a complete **DevSecOps pipeline** with Semio AI-powered security analysis integration in GitLab CI/CD.

## 🎯 Demo Overview

This demo showcases the full DevSecOps workflow:
1. **🔄 Code Push** → Triggers automated pipeline
2. **🔍 Security Scan** → Semgrep finds vulnerabilities  
3. **🤖 AI Analysis** → Semio generates intelligent fix recommendations
4. **🔧 Automated Fixes** → Creates branch with applied fixes
5. **📝 Merge Request** → Ready for human review
6. **🚀 Deploy** → Secure application deployment

## 🚀 Quick Start

### Prerequisites
- Semio API running (localhost:8000 or your deployment)
- GitLab repository with CI/CD enabled
- Docker registry access

### 1. Set Up GitLab CI Variables

Go to your GitLab project → Settings → CI/CD → Variables:
```
SEMIO_API_KEY = your_api_key_here
SEMIO_API_URL = http://localhost:8000
GITLAB_TOKEN = your_gitlab_token_here
```

### 2. Test the DevSecOps Pipeline

1. **Push code** to trigger the pipeline
2. **Watch the pipeline run** automatically through all stages
3. **See Semio create security fixes** in a new branch
4. **Review the generated Merge Request** with fixes
5. **Deploy the secure application**

## 📋 Pipeline Stages

### 🔨 Build Stage
- Builds Docker image from vulnerable code
- Pushes to GitLab container registry
- Prepares for security analysis

### 🔍 Security Scan Stage
- Runs Semgrep with comprehensive security rules
- Detects multiple vulnerability types
- Generates detailed security report

### 🤖 Semio AI Analysis Stage
- Sends Semgrep results to Semio API
- AI generates intelligent fix recommendations
- Provides confidence scores and explanations

### 🔧 Create Fixes Stage
- Creates new branch: `security-fixes-YYYYMMDD-HHMMSS`
- Applies recommended security fixes
- Generates detailed fix documentation
- Creates Merge Request for review

### 🚀 Deploy Stage
- Deploys the secure application
- Uses the fixed Docker image
- Updates production environment

## 🎭 Demo Vulnerabilities

The application contains **8 intentional security vulnerabilities**:

1. **🔓 SQL Injection** → Direct string concatenation in queries
2. **🔐 Weak Crypto** → MD5 password hashing
3. **⚡ Command Injection** → Unsanitized subprocess calls
4. **📁 Path Traversal** → No path validation
5. **🌐 XSS** → Direct user input in HTML
6. **🔑 Hardcoded Secrets** → Credentials in code
7. **🎲 Insecure Random** → Predictable random generation
8. **🐛 Debug Mode** → Debug enabled in production

## 📊 Expected Pipeline Output

### Successful Security Analysis
```
✅ Semio AI Analysis Complete

📊 Analysis Results:
  - Total vulnerabilities: 8
  - High confidence fixes: 8
  - Medium confidence fixes: 0
  - Low confidence fixes: 0

🔧 Automated Fixes Applied:
  - Fixed SQL injection vulnerabilities
  - Replaced MD5 with bcrypt
  - Added input validation
  - Removed hardcoded secrets
  - Disabled debug mode

✅ Security fixes MR created! Please review the automated fixes before merging.
```

### Clean Code Scenario
```
✅ Semio AI Analysis Complete

🎉 No vulnerabilities found! Your code is secure.
```

## 🔧 Configuration

### Semgrep Rules
The pipeline uses comprehensive security rules:
- `p/security-audit` - General security issues
- `p/secrets` - Secret detection
- `p/owasp-top-ten` - OWASP Top 10 vulnerabilities
- `p/python` - Python-specific security issues

### Semio API Settings
Update these in your CI variables:
```yaml
SEMIO_API_URL: "https://api.semio.app"  # Production URL
SEMIO_API_KEY: "your_api_key_here"
```

### Docker Configuration
The pipeline builds and deploys a containerized Flask application with:
- Python 3.11 base image
- SQLite database for testing
- Exposed on port 5000

## 🔍 Troubleshooting

### Common Issues

1. **API Connection Failed**
   - Check `SEMIO_API_URL` is correct
   - Ensure Semio API is running
   - Verify network connectivity

2. **Authentication Failed**
   - Verify `SEMIO_API_KEY` is set correctly
   - Check API key permissions
   - Ensure GitLab token has proper access

3. **No Vulnerabilities Found**
   - Ensure `app.py` and `test_vulnerable_code.py` are included
   - Check Semgrep rules are working
   - Verify file paths in pipeline

4. **Permission Denied**
   - Ensure CI has write permissions
   - Check GitLab token permissions
   - Verify Docker registry access

## 🎯 Demo Best Practices

1. **Use Real Vulnerabilities** - The app contains actual security issues
2. **Show Full Workflow** - Demonstrate complete DevSecOps pipeline
3. **Highlight AI Capabilities** - Show Semio's intelligent fix generation
4. **Emphasize Automation** - Demonstrate hands-off security fixes
5. **Include Human Review** - Show the Merge Request review process

## 📈 Next Steps

After successful demo:
1. **Production Deployment** - Deploy Semio API to production
2. **Custom Rules** - Add organization-specific security rules
3. **Team Integration** - Add team notifications and approvals
4. **Metrics Dashboard** - Track security improvement over time
5. **Compliance Reporting** - Generate compliance reports

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   GitLab Repo   │───▶│  CI/CD Pipeline │───▶│  Semio API      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │  Security Fixes │
                       │  Branch + MR    │
                       └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │  Production     │
                       │  Deployment     │
                       └─────────────────┘
```

---

**Ready to demo!** 🚀 Push code to see the complete DevSecOps pipeline in action!
