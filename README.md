# Semio - AI-Powered Security Analysis

Semio is an intelligent security analysis tool that processes Semgrep results and generates AI-powered fix recommendations. It provides both a REST API and a web dashboard for analyzing security vulnerabilities.

## Features

- **AI-Powered Fix Generation**: Uses LLM to generate intelligent security fixes
- **Enhanced Code Context**: Multiple strategies for extracting code from Semgrep results
- **Tier-Based System**: Free, Pro, and Enterprise tiers with different capabilities
- **Multiple Output Formats**: JSON, Markdown, and HTML reports
- **Web Dashboard**: Gradio-based interface for easy analysis
- **Rate Limiting**: Built-in rate limiting for API usage
- **Authentication**: User registration and API key management

## Prerequisites

- Python 3.8+
- Semgrep CLI tool
- Google API key (for LLM functionality)

## Installation

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd semio
   ```

2. **Install dependencies:**
   ```bash
   cd backend
   pip install -r requirements.txt
   ```

3. **Set up environment variables:**
   Create a `.env` file in the `backend` directory:
   ```env
   GOOGLE_API_KEY=your_google_api_key_here
   SECURE_REVIEW_SYSTEM_PROMPT=Your custom system prompt
   SECURE_REVIEW_USER_TEMPLATE=Your custom user template
   DEBUG=False
   ```

4. **Initialize the database:**
   ```bash
   cd backend
   python -c "from app.database import init_db; init_db()"
   ```

## Quick Start

### Start the API Server

```bash
cd backend
python -m uvicorn app.main:app --reload --port 8000
```

The API will be available at `http://localhost:8000`

### Start the Dashboard

```bash
cd backend
python app/dashboard.py
```

The dashboard will be available at `http://localhost:7860`

## API Usage

### Basic Usage

```bash
# Analyze Semgrep results
curl -X POST "http://localhost:8000/api/review" \
  -H "Content-Type: application/json" \
  -d @semgrep-results.json

# Get optimal Semgrep command
curl "http://localhost:8000/api/semgrep-config?target_path=.&rules=auto"
```

### With Code Context

```bash
# Include code context (recommended)
curl -X POST "http://localhost:8000/api/review?include_code_context=true" \
  -H "Content-Type: application/json" \
  -d @semgrep-results.json

# Without code context (faster)
curl -X POST "http://localhost:8000/api/review?include_code_context=false" \
  -H "Content-Type: application/json" \
  -d @semgrep-results.json
```

### Generate Reports

```bash
# JSON report
curl -X POST "http://localhost:8000/api/review?format=json" \
  -H "Content-Type: application/json" \
  -d @semgrep-results.json

# Markdown report
curl -X POST "http://localhost:8000/api/review?format=markdown" \
  -H "Content-Type: application/json" \
  -d @semgrep-results.json

# HTML report
curl -X POST "http://localhost:8000/api/review?format=html" \
  -H "Content-Type: application/json" \
  -d @semgrep-results.json
```

## Semgrep Configuration

For optimal results with Semio, use these Semgrep flags:

```bash
# Basic optimal command
semgrep --json --include-parse-tree --max-lines-per-finding 20 --config auto .

# With specific rules
semgrep --json --include-parse-tree --max-lines-per-finding 20 --config p/security-audit .

# With custom output
semgrep --json --include-parse-tree --max-lines-per-finding 20 --config auto --output semgrep-results.json .
```

### Key Flags Explained

- `--include-parse-tree`: Provides better code extraction
- `--max-lines-per-finding 20`: Includes more context around findings
- `--json`: Output in JSON format for Semio processing

## 🏗️ Project Structure

```
semio/
├── backend/
│   ├── app/
│   │   ├── models/           # Database models
│   │   ├── routes/           # API routes
│   │   ├── services/         # Business logic
│   │   ├── middleware/       # Rate limiting, etc.
│   │   ├── templates/        # Report templates
│   │   ├── dashboard.py      # Gradio dashboard
│   │   ├── main.py          # FastAPI app
│   │   └── database.py      # Database configuration
│   ├── requirements.txt     # Python dependencies
│   └── .env                # Environment variables
└── README.md
```

## Authentication

Semio supports user authentication with different tiers:

### Free Tier
- Basic vulnerability analysis
- Shared LLM access
- Rate limited

### Pro Tier
- Enhanced features
- Custom prompts
- Higher rate limits

### Enterprise Tier
- Full features
- Custom API keys
- Unlimited usage

### API Endpoints

```bash
# Register user
curl -X POST "http://localhost:8000/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password123"}'

# Login
curl -X POST "http://localhost:8000/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password123"}'

# Generate API key
curl -X POST "http://localhost:8000/auth/generate-api-key" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## 🧪 Testing

### Test with Sample Data

1. Start the API server
2. Open the dashboard at `http://localhost:7860`
3. Click "Load Sample Data" to test with example vulnerabilities
4. Click "Analyze Vulnerabilities" to see the results

### Test API Directly

```bash
# Test the API health
curl "http://localhost:8000/health"

# Test Semgrep configuration
curl "http://localhost:8000/api/semgrep-config"
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GOOGLE_API_KEY` | Google API key for LLM | Required |
| `SECURE_REVIEW_SYSTEM_PROMPT` | Custom system prompt | Built-in |
| `SECURE_REVIEW_USER_TEMPLATE` | Custom user template | Built-in |
| `DEBUG` | Enable debug mode | `False` |

### Database Configuration

By default, Semio uses SQLite for development. For production, configure PostgreSQL:

```env
DATABASE_URL=postgresql://user:password@localhost/semio
USE_SQLITE=false
```

## Deployment

### Docker Deployment

```bash
# Build the image
docker build -t semio .

# Run the container
docker run -p 8000:8000 -p 7860:7860 semio
```

### Production Deployment

1. Set up a production database (PostgreSQL recommended)
2. Configure environment variables
3. Set up reverse proxy (nginx)
4. Use a process manager (systemd, supervisor)
5. Enable HTTPS

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:
- Create an issue on GitHub
- Check the documentation
- Review the API documentation at `http://localhost:8000/docs`

## 🔄 Changelog

### v1.0.0
- Initial release
- AI-powered security fix generation
- Enhanced code context extraction
- Web dashboard
- Tier-based authentication system
- Multiple report formats
