---
title: Sem.io CICD - AI Security Analysis Agent
emoji: 🔒
colorFrom: blue
colorTo: purple
sdk: gradio
sdk_version: 4.7.1
app_file: app.py
pinned: false
license: mit
short_description: AI-powered security analysis agent for CI/CD pipelines
---

# Sem.io CICD : AI Security Analysis Agent

An intelligent security analysis agent that transforms static security scan results into actionable insights with AI-powered false positive detection and fix recommendations.

## 🚀 Features

- **Context-Aware Analysis**: Reads actual source code to understand vulnerability context
- **AI-Powered False Positive Detection**: Reduces noise with intelligent filtering
- **Automated Fix Generation**: Provides secure code fixes with explanations
- **CI/CD Integration**: Seamlessly integrates with GitLab and GitHub pipelines
- **Comprehensive Reporting**: Detailed analysis with confidence scores and reasoning

## 🛠️ How It Works

1. **Upload Semgrep Results**: Upload JSON output from your Semgrep security scan
2. **AI Analysis**: sem.io reads your codebase and performs context-aware analysis
3. **False Positive Detection**: Intelligent filtering reduces false positives
4. **Fix Recommendations**: Get AI-generated secure code fixes with explanations
5. **Pipeline Integration**: Use the CLI for automated CI/CD integration

## 📋 Usage

1. **Demo**: Use the "Load Sample Data" button to see sem.io in action
2. **Upload**: Upload your own Semgrep JSON results
3. **Analyze**: Click "Analyze Vulnerabilities" to get detailed insights
4. **Review**: Examine false positive analysis and fix recommendations

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