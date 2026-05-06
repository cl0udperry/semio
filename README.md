---
title: Semio - Unified Security Findings Layer
emoji: 🔒
colorFrom: blue
colorTo: purple
sdk: gradio
sdk_version: 4.7.1
app_file: app.py
pinned: false
license: mit
short_description: Unified security findings layer for CI/CD pipelines
---

# Semio — Unified Security Findings Layer

Semio normalises output from multiple security scanners (Semgrep, Bandit, Trivy, OWASP Dependency-Check) into a single findings layer, adds AI-assisted triage and fix suggestions, and tracks vulnerability trends across scan runs over time.

## Features

- **Multi-Scanner Support**: Ingests JSON output from Semgrep, Bandit, Trivy, and OWASP Dependency-Check — no vendor lock-in
- **AI-Assisted Triage**: Context-aware analysis classifies each finding as AUTO_FIX, SUGGEST, or MANUAL_REVIEW
- **Fix Suggestions**: AI-generated code fixes with confidence scores and explanations
- **Scan History & Trends**: Track findings count and severity distribution across scan runs per project
- **CI/CD Integration**: Integrates with GitLab and GitHub pipelines via CLI
- **Self-Hostable**: Run entirely on your own infrastructure — no code leaves your environment

## How It Works

1. **Run your scanner**: Any supported tool outputs JSON
2. **Upload or pipe to Semio**: Via the demo UI or `semio analyze` CLI
3. **AI triage**: Each finding is classified and a fix is suggested with a confidence score
4. **Track over time**: Findings are stored per project so you can see trends across runs

## Usage

1. **Demo**: Click "Load Sample Data" to see Semio in action
2. **Upload**: Upload scanner JSON output (Semgrep, Bandit, Trivy, or OWASP DC)
3. **Analyze**: Click "Analyze" to get prioritised findings with fix suggestions
4. **Review**: Inspect AI decisions, copy fixes, track across runs

## 🔧 CLI Integration

For production use in CI/CD pipelines:

```bash
# Install sem.io CLI
pip install semio-cli

# Run analysis in your pipeline
semio analyze --input semgrep-results.json --output analysis-report.json
```

## 🔗 Links

- **LinkedIn**: [Connect for a demo](https://www.linkedin.com/in/jordan-leong-69b57495/)
- **GitHub**: [Source Code](https://github.com/cl0udperry/semio)
- **GitLab**: [CI/CD Integration](https://gitlab.com/cl0udperrycicd/semio-demo-gitlab)

## 📄 License

MIT License - see LICENSE file for details.