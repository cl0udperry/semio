# Semio - AI-Powered Security Analysis Tool

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.116.1-green.svg)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Semio is an AI-powered security analysis tool that automatically generates security fix recommendations from Semgrep JSON reports. It's designed to integrate seamlessly into CI/CD pipelines and provide developers with actionable, minimal code changes to address security vulnerabilities.

## 🚀 Features

### Core Capabilities

- **🔍 Semgrep Integration**: Processes Semgrep JSON output to identify security vulnerabilities
- **🤖 AI-Powered Fixes**: Uses Google Gemini to generate intelligent security fix recommendations
- **📊 Structured Output**: Returns detailed, structured JSON responses with confidence scores
- **🎯 Minimal Changes**: Focuses on line-by-line fixes that preserve original functionality
- **⚡ High Performance**: Fast processing with optimized LLM prompts and response parsing

### API Endpoints

#### `/api/scan` (Legacy)
- **Method**: POST
- **Content-Type**: application/json
- **Purpose**: Direct JSON processing for simple use cases
- **Input**: Raw Semgrep JSON data
- **Output**: Structured fix recommendations

#### `/api/review` (Primary)
- **Method**: POST
- **Content-Type**: multipart/form-data
- **Purpose**: File upload processing with enhanced features
- **Input**: Semgrep JSON file upload
- **Output**: Comprehensive analysis with statistics and metadata

### CLI Tool

A command-line interface for easy integration into CI/CD pipelines:

```bash
# Basic usage
semio scan semgrep-output.json

# With custom options
semio scan semgrep-output.json --format markdown --output report.md

# With custom API endpoint
semio scan semgrep-output.json --url https://api.semio.app
```

## 🏗️ Architecture

### Backend (FastAPI)

```
backend/
├── app/
│   ├── main.py              # FastAPI application entry point
│   ├── routes/
│   │   ├── scan.py          # Legacy scan endpoint
│   │   └── review.py        # Primary review endpoint
│   ├── services/
│   │   ├── semgrep_parser.py    # Semgrep JSON parsing
│   │   ├── llm_recommender.py   # Gemini integration
│   │   ├── report_generator.py  # Report generation (JSON/MD/HTML)
│   │   └── tier_service.py      # Freemium tier management
│   └── models/
│       └── user.py          # User and tier models
└── requirements.txt         # Python dependencies
```

### CLI Tool

```
cli/
├── semio_cli/
│   └── main.py              # CLI application
└── pyproject.toml           # Package configuration
```

## 🛠️ Installation

### Backend Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd semio
   ```

2. **Set up Python environment**
   ```bash
   cd backend
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Configure environment variables**
   ```bash
   # Create .env file in backend directory
   GOOGLE_API_KEY=your_google_api_key_here
   DEBUG=False
   ```

4. **Run the server**
   ```bash
   python -m uvicorn app.main:app --reload --port 8000
   ```

### CLI Tool Setup

1. **Install the CLI package**
   ```bash
   cd cli
   pip install -e .
   ```

2. **Test installation**
   ```bash
   semio --help
   ```

## 📖 Usage

### API Usage

#### Basic Scan
```bash
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"results":[{"check_id":"python.weak-crypto","path":"auth.py","start":{"line":8},"extra":{"lines":"password_hash = hashlib.md5(password).hexdigest()","message":"Weak cryptographic algorithm used","severity":"HIGH"}}]}'
```

#### File Upload Review
```bash
curl -X POST http://localhost:8000/api/review \
  -F "file=@semgrep-output.json" \
  -H "Content-Type: multipart/form-data"
```

#### With Custom Format
```bash
curl -X POST "http://localhost:8000/api/review?format=markdown" \
  -F "file=@semgrep-output.json"
```

### CLI Usage

```bash
# Basic scan
semio scan semgrep-output.json

# Generate markdown report
semio scan semgrep-output.json --format markdown --output security-report.md

# Verbose output
semio scan semgrep-output.json --verbose

# Custom API endpoint
semio scan semgrep-output.json --url https://api.semio.app
```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GOOGLE_API_KEY` | Google Gemini API key | Required |
| `DEBUG` | Enable debug mode | `False` |
| `SECURE_REVIEW_SYSTEM_PROMPT` | Custom system prompt | Built-in default |
| `SECURE_REVIEW_USER_TEMPLATE` | Custom user template | Built-in default |

### API Response Format

```json
{
  "upload_id": "unique_identifier",
  "timestamp": "2025-08-14T10:15:56.040863",
  "total_vulnerabilities": 2,
  "high_confidence_fixes": 2,
  "medium_confidence_fixes": 0,
  "low_confidence_fixes": 0,
  "findings": [...],
  "fixes": [
    {
      "rule_id": "python.weak-crypto",
      "file_path": "auth.py",
      "line_number": 8,
      "original_code": "password_hash = hashlib.md5(password).hexdigest()",
      "suggested_fix": "password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')",
      "confidence_score": 0.95,
      "fix_type": "line_replacement",
      "explanation": "Replaced MD5 with bcrypt for password hashing",
      "required_imports": ["import bcrypt"],
      "impact": "high"
    }
  ],
  "summary": {
    "total_vulnerabilities": 2,
    "high_confidence_fixes": 2,
    "medium_confidence_fixes": 0,
    "low_confidence_fixes": 0,
    "fix_types": {"line_replacement": 2},
    "severity_distribution": {"HIGH": 1, "CRITICAL": 1},
    "errors_count": 0
  },
  "errors": []
}
```

## 🏢 Freemium Model (Planned)

The system is designed to support a freemium business model with the following tiers:

### Free Tier
- 100 monthly requests
- Shared LLM access
- Basic features

### Pro Tier
- 1,000 monthly requests
- Shared LLM access
- Custom prompts
- Priority queue

### Enterprise Tier
- Unlimited requests
- Dedicated LLM access
- Custom prompts
- Data isolation
- Audit logs

## 🔒 Security Features

- **Input Validation**: Comprehensive validation of Semgrep JSON format
- **Error Handling**: Graceful handling of malformed inputs and LLM failures
- **Rate Limiting**: Built-in rate limiting for API endpoints
- **CORS Support**: Configurable CORS middleware for web integration

## 🧪 Testing

### Test with Sample Data

```bash
# Use the provided test file
curl -X POST http://localhost:8000/api/review \
  -F "file=@test_semgrep.json" \
  -H "Content-Type: multipart/form-data"
```

The `test_semgrep.json` file contains sample vulnerabilities:
- Weak cryptographic algorithm (MD5)
- SQL injection vulnerability

## 🚧 Development Status

### ✅ Completed Features
- [x] FastAPI backend with CORS support
- [x] Semgrep JSON parsing and validation
- [x] Gemini LLM integration with structured output
- [x] File upload endpoint with multipart support
- [x] CLI tool with rich output
- [x] Error handling and fallback mechanisms
- [x] JSON response cleaning and parsing
- [x] Confidence scoring system
- [x] Report generation framework
- [x] Freemium tier service architecture

### 🚧 In Progress
- [ ] GitLab/GitHub CI integration
- [ ] Web dashboard (Gradio/React)
- [ ] GitHub/GitLab comment bot
- [ ] Production deployment

### 📋 Planned Features
- [ ] User authentication and session management
- [ ] Database integration for request tracking
- [ ] Advanced report formats (PDF, custom templates)
- [ ] Batch processing for large codebases
- [ ] Custom Semgrep rule integration
- [ ] Performance optimization and caching

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

For support and questions:
- Create an issue in the repository
- Check the documentation
- Review the test examples

## 🙏 Acknowledgments

- [Semgrep](https://semgrep.dev/) for static analysis capabilities
- [Google Gemini](https://ai.google.dev/) for AI-powered fix generation
- [FastAPI](https://fastapi.tiangolo.com/) for the web framework
- [Rich](https://rich.readthedocs.io/) for beautiful CLI output

---

**Semio** - Making security fixes as simple as a scan.
