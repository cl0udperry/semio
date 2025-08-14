# Semio Demo Repositories

This directory contains demo repository templates for showcasing Semio CI integration.

## 📁 Structure

```
demo-repos/
├── gitlab-demo/          # GitLab CI demo template
├── github-demo/          # GitHub Actions demo template
├── setup-demos.sh        # Script to create demo repositories
└── README.md            # This file
```

## 🚀 Quick Start

1. **Create demo repositories:**
   ```bash
   cd demo-repos
   ./setup-demos.sh
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

---

**Note:** These are demo templates. Copy to separate repositories for actual demos.
