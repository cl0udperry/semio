# Semio GitLab CI Demo

This repository demonstrates Semio security analysis integration with GitLab CI/CD pipelines.

## 🎯 Demo Overview

This demo showcases the complete automated security workflow:
1. **Semgrep Security Scan** → Finds vulnerabilities
2. **Semio Analysis** → Generates intelligent fix recommendations
3. **Automated Fix Creation** → Creates new branch with fixes
4. **Merge Request Generation** → Opens MR for review

## 🚀 Quick Start

### Prerequisites
- Semio API running (localhost:8000 or your deployment)
- Valid API key from Semio

### 1. Set Up GitLab CI Variables

Go to your GitLab project → Settings → CI/CD → Variables:
```
SEMIO_API_KEY = your_api_key_here
SEMIO_API_URL = http://localhost:8000
```

### 2. Test the Integration

1. **Create a Merge Request** with the vulnerable test code
2. **Watch the pipeline run** automatically
3. **See Semio create security fixes** in a new branch
4. **Review the generated Merge Request** with fixes

## 📋 Demo Workflow

### Step 1: Security Scan
- Semgrep runs automatically on MR creation
- Scans for security vulnerabilities
- Outputs JSON results

### Step 2: Semio Analysis
- Results sent to Semio API
- AI generates fix recommendations
- Returns structured analysis

### Step 3: Fix Creation
- Creates new branch: `security-fixes-YYYYMMDD-HHMMSS`
- Applies recommended fixes
- Commits changes with detailed message

### Step 4: Merge Request
- Title: "🔒 Security Fixes - Semio Analysis"
- Description: Detailed vulnerability report
- Comments: Analysis summary

## 🎭 Demo Scenarios

The `test_vulnerable_code.py` file contains 8 intentional vulnerabilities:

1. **SQL Injection** → Parameterized queries
2. **Weak Crypto** → bcrypt hashing
3. **Command Injection** → Input validation
4. **Path Traversal** → Path validation
5. **XSS** → Output encoding
6. **Hardcoded Secrets** → Environment variables
7. **Insecure Random** → secrets module
8. **Debug Mode** → Production settings

## 📊 Expected Output

### Successful Analysis
```
✅ Semio Security Analysis Complete

Vulnerabilities Found: 8
High Confidence Fixes: 8
Medium Confidence Fixes: 0
Low Confidence Fixes: 0

✅ Security fixes MR created! Please review the automated fixes before merging.
```

### No Vulnerabilities
```
✅ Semio Security Analysis Complete

✅ No vulnerabilities found! Your code is secure.
```

## 🔧 Configuration

### Semgrep Rules
The pipeline uses these security rules:
- `p/security-audit` - General security issues
- `p/secrets` - Secret detection
- `p/owasp-top-ten` - OWASP Top 10 vulnerabilities

### Semio API Settings
Update these in your CI variables:
```yaml
SEMIO_API_URL: "https://api.semio.app"  # Production URL
SEMIO_API_KEY: "your_api_key_here"
```

## 🔍 Troubleshooting

### Common Issues

1. **API Connection Failed**
   - Check `SEMIO_API_URL` is correct
   - Ensure Semio API is running

2. **Authentication Failed**
   - Verify `SEMIO_API_KEY` is set correctly
   - Check API key permissions

3. **No Vulnerabilities Found**
   - Ensure `test_vulnerable_code.py` is included
   - Check Semgrep rules are working

4. **Permission Denied**
   - Ensure CI has write permissions
   - Check GitLab token permissions

## 🎯 Demo Best Practices

1. **Use Real Vulnerabilities** - The test file contains actual security issues
2. **Test Both Scenarios** - Show both "vulnerabilities found" and "clean code" cases
3. **Review Process** - Demonstrate the human review step
4. **Customization** - Show how to modify rules and settings

## 📈 Next Steps

After successful demo:
1. **Production Deployment** - Deploy Semio API to production
2. **Custom Rules** - Add organization-specific security rules
3. **Team Integration** - Add team notifications and approvals
4. **Metrics** - Track security improvement over time

---

**Ready to demo!** 🚀 Create a Merge Request to see Semio in action!
