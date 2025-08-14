# Semio CI Integration Demo Guide

This guide demonstrates how to integrate Semio into your CI/CD pipeline for automated security analysis and fix recommendations.

## 🎯 Demo Overview

The demo showcases the complete workflow:
1. **Semgrep Security Scan** → Finds vulnerabilities
2. **Semio Analysis** → Generates intelligent fix recommendations
3. **Automated Fix Creation** → Creates new branch with fixes
4. **Pull Request Generation** → Opens PR for review

## 🚀 Quick Start

### Prerequisites
- Semio API running (localhost:8000)
- Valid API key
- GitLab or GitHub repository

### 1. Set Up Environment Variables

#### GitLab CI/CD Variables
Go to your GitLab project → Settings → CI/CD → Variables:
```
SEMIO_API_KEY = your_api_key_here
SEMIO_API_URL = http://localhost:8000
```

#### GitHub Secrets
Go to your GitHub repository → Settings → Secrets and variables → Actions:
```
SEMIO_API_KEY = your_api_key_here
SEMIO_API_URL = http://localhost:8000
```

### 2. Add CI Configuration

#### For GitLab
Copy `.gitlab-ci.yml` to your repository root.

#### For GitHub
Copy `.github/workflows/semio-security.yml` to your repository.

### 3. Test the Integration

1. **Create a test file with vulnerabilities:**
```python
# test_vulnerable.py
import hashlib
import sqlite3

def weak_password_hash(password):
    return hashlib.md5(password).hexdigest()  # Vulnerable!

def sql_injection(user_input):
    query = "SELECT * FROM users WHERE id = " + user_input  # Vulnerable!
    return query
```

2. **Commit and push:**
```bash
git add test_vulnerable.py
git commit -m "Add vulnerable code for testing"
git push origin main
```

3. **Create a Pull Request/Merge Request**

4. **Watch the magic happen!** 🎉

## 📋 Demo Workflow

### Step 1: Security Scan
```yaml
# Semgrep runs automatically on PR/MR
security-scan:
  - Runs Semgrep with security rules
  - Outputs JSON results
  - Finds vulnerabilities in code
```

### Step 2: Semio Analysis
```yaml
# Results sent to Semio API
semio-analysis:
  - Uploads Semgrep results to Semio
  - AI generates fix recommendations
  - Returns structured analysis
```

### Step 3: Fix Creation
```yaml
# Automated fix application
create-fixes:
  - Creates new branch: security-fixes-YYYYMMDD-HHMMSS
  - Applies recommended fixes
  - Commits changes with detailed message
```

### Step 4: Pull Request
```yaml
# Review-ready PR created
- Title: "🔒 Security Fixes - Semio Analysis"
- Description: Detailed vulnerability report
- Files: Only modified files
- Comments: Analysis summary
```

## 🔧 Configuration Options

### Semgrep Rules
Customize security rules in CI config:
```yaml
# GitLab
semgrep ci --config p/security-audit p/secrets p/owasp-top-ten

# GitHub
config: >-
  p/security-audit
  p/secrets
  p/owasp-top-ten
```

### Semio API Settings
```yaml
variables:
  SEMIO_API_URL: "https://api.semio.app"  # Production URL
  SEMIO_API_KEY: "$SEMIO_API_KEY"
```

### Branch Naming
```yaml
FIXES_BRANCH="security-fixes-$(date +%Y%m%d-%H%M%S)"
# Results in: security-fixes-20240814-143022
```

## 📊 Expected Output

### Successful Analysis
```
✅ Semio Security Analysis Complete

Vulnerabilities Found: 2
High Confidence Fixes: 2
Medium Confidence Fixes: 0
Low Confidence Fixes: 0

✅ Security fixes PR created! Please review the automated fixes before merging.
```

### No Vulnerabilities
```
✅ Semio Security Analysis Complete

✅ No vulnerabilities found! Your code is secure.
```

## 🎭 Demo Scenarios

### Scenario 1: SQL Injection
**Vulnerable Code:**
```python
query = "SELECT * FROM users WHERE id = " + user_input
```

**Semio Fix:**
```python
query = "SELECT * FROM users WHERE id = %s"
cursor.execute(query, (user_input,))
```

### Scenario 2: Weak Crypto
**Vulnerable Code:**
```python
password_hash = hashlib.md5(password).hexdigest()
```

**Semio Fix:**
```python
import bcrypt
password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
```

### Scenario 3: XSS Vulnerability
**Vulnerable Code:**
```javascript
document.getElementById('output').innerHTML = userInput;
```

**Semio Fix:**
```javascript
document.getElementById('output').textContent = userInput;
```

## 🔍 Troubleshooting

### Common Issues

1. **API Connection Failed**
   ```
   Error: connection to server at "localhost" failed
   ```
   **Solution:** Update `SEMIO_API_URL` to your actual Semio API URL

2. **Authentication Failed**
   ```
   Error: Invalid API key
   ```
   **Solution:** Check your `SEMIO_API_KEY` secret is set correctly

3. **No Vulnerabilities Found**
   ```
   Semgrep scan completed. Found 0 vulnerabilities
   ```
   **Solution:** Add vulnerable code for testing, or check Semgrep rules

4. **Permission Denied**
   ```
   Error: push access denied
   ```
   **Solution:** Ensure CI has write permissions to repository

### Debug Mode
Enable debug logging in CI:
```yaml
script:
  - set -x  # Enable debug mode
  - echo "Debug: Starting Semio analysis..."
  - curl -v -X POST "$SEMIO_API_URL/api/review" ...
```

## 🎯 Demo Best Practices

1. **Use Real Vulnerabilities**: Include actual security issues for realistic demo
2. **Test Both Scenarios**: Show both "vulnerabilities found" and "clean code" cases
3. **Review Process**: Demonstrate the human review step
4. **Customization**: Show how to modify rules and settings
5. **Integration**: Connect with existing security tools

## 📈 Next Steps

After successful demo:
1. **Production Deployment**: Deploy Semio API to production
2. **Custom Rules**: Add organization-specific security rules
3. **Team Integration**: Add team notifications and approvals
4. **Metrics**: Track security improvement over time
5. **Compliance**: Add compliance reporting features

## 🎉 Demo Success Checklist

- [ ] CI pipeline runs on PR/MR creation
- [ ] Semgrep finds vulnerabilities in test code
- [ ] Semio API processes results successfully
- [ ] Security fixes branch is created
- [ ] Pull Request is generated with fixes
- [ ] PR description includes vulnerability summary
- [ ] Comments are posted to original PR
- [ ] Fixes can be reviewed and merged

---

**Ready to demo?** 🚀 Your Semio integration is now demo-ready!
