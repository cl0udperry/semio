# Semio Demo Repositories

This directory contains demo repository templates for showcasing Semio CI integration.

## 📁 Structure

```
demo-repos/
├── gitlab-demo/          # GitLab CI demo template
├── github-demo/          # GitHub Actions demo template
├── setup-demos.sh        # Script to create demo repositories (Linux/Mac)
├── setup-demos.bat       # Script to create demo repositories (Windows)
└── README.md            # This file
```

## 🚀 Quick Start

### Option 1: Using Setup Scripts

#### Linux/Mac
```bash
cd demo-repos
./setup-demos.sh
```

#### Windows
```cmd
cd demo-repos
setup-demos.bat
```

### Option 2: Manual Setup

1. **Create demo repositories:**
   ```bash
   # Create directories
   mkdir semio-demo-gitlab
   mkdir semio-demo-github
   
   # Copy GitLab demo
   xcopy demo-repos\gitlab-demo\* semio-demo-gitlab\ /E /I
   
   # Copy GitHub demo
   xcopy demo-repos\github-demo\* semio-demo-github\ /E /I
   ```

2. **Push to separate repositories:**
   - Create `semio-demo-gitlab` repository on GitLab
   - Create `semio-demo-github` repository on GitHub
   - Push the respective demo folders

## 📋 Demo Features

- **Automated Security Scanning** with Semgrep
- **AI-Powered Fix Recommendations** from Semio
- **Automated Branch Creation** with fixes
- **Pull Request Generation** for review
- **Real Vulnerabilities** for testing

## 🎯 Demo Workflow

1. **Security Scan** → Semgrep finds vulnerabilities
2. **Semio Analysis** → AI generates fix recommendations
3. **Fix Creation** → New branch with applied fixes
4. **Pull Request** → Review-ready PR with detailed report

## 🔧 Setup Scripts

### Linux/Mac (`setup-demos.sh`)
- **Prerequisites**: Git installed
- **Features**: Colored output, error handling, interactive prompts
- **Usage**: `./setup-demos.sh`

### Windows (`setup-demos.bat`)
- **Prerequisites**: Git installed, Windows 10+ for colors
- **Features**: Same functionality as Linux version
- **Usage**: `setup-demos.bat`

Both scripts will:
- ✅ Check prerequisites (Git installation)
- ✅ Validate directory structure
- ✅ Create demo repositories with custom names
- ✅ Initialize Git repositories
- ✅ Create initial commits
- ✅ Provide next steps instructions

## 🎭 Demo Scenarios

The demo includes 8 intentional vulnerabilities:
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

✅ Security fixes PR created! Please review the automated fixes before merging.
```

### No Vulnerabilities
```
✅ Semio Security Analysis Complete

✅ No vulnerabilities found! Your code is secure.
```

## 🔍 Troubleshooting

### Common Issues

1. **Script not found**
   - Ensure you're in the `demo-repos` directory
   - Check file permissions (Linux/Mac: `chmod +x setup-demos.sh`)

2. **Git not installed**
   - Install Git from https://git-scm.com/
   - Ensure Git is in your PATH

3. **Colors not working (Windows)**
   - Windows 10+ supports ANSI colors
   - Older versions will show color codes (still functional)

4. **Permission denied**
   - Run as administrator if needed
   - Check antivirus software interference

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

**Note:** These are demo templates. Copy to separate repositories for actual demos.
