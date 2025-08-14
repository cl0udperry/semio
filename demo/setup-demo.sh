#!/bin/bash

# Semio CI Integration Demo Setup Script
# This script sets up the demo environment

echo "🔒 Setting up Semio CI Integration Demo..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if Semio API is running
echo -e "${BLUE}Checking Semio API status...${NC}"
if curl -s http://localhost:8000/health > /dev/null; then
    echo -e "${GREEN}✅ Semio API is running${NC}"
else
    echo -e "${RED}❌ Semio API is not running${NC}"
    echo -e "${YELLOW}Please start the Semio API first:${NC}"
    echo "cd backend && python -m uvicorn app.main:app --reload --port 8000"
    exit 1
fi

# Test API key
echo -e "${BLUE}Testing API key...${NC}"
if [ -z "$SEMIO_API_KEY" ]; then
    echo -e "${YELLOW}⚠️  SEMIO_API_KEY not set. Please set it:${NC}"
    echo "export SEMIO_API_KEY=your_api_key_here"
    echo -e "${YELLOW}Or register a new user:${NC}"
    echo "curl -X POST http://localhost:8000/auth/register -H \"Content-Type: application/json\" -d '{\"email\":\"demo@example.com\",\"password\":\"demopassword123\"}'"
else
    echo -e "${GREEN}✅ API key is set${NC}"
fi

# Create demo repository structure
echo -e "${BLUE}Setting up demo repository...${NC}"

# Create .gitignore if it doesn't exist
if [ ! -f .gitignore ]; then
    cat > .gitignore << EOF
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg
MANIFEST

# Virtual environments
venv/
env/
ENV/
env.bak/
venv.bak/

# Environment variables
.env
.env.local
.env.development.local
.env.test.local
.env.production.local

# Database
*.db
*.sqlite
*.sqlite3

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# OS
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db

# Logs
*.log
logs/

# Temporary files
*.tmp
*.temp
EOF
    echo -e "${GREEN}✅ Created .gitignore${NC}"
fi

# Initialize git if not already done
if [ ! -d .git ]; then
    git init
    echo -e "${GREEN}✅ Initialized git repository${NC}"
fi

# Add CI configuration files
echo -e "${BLUE}Adding CI configuration files...${NC}"

# Create .github/workflows directory
mkdir -p .github/workflows

# Copy CI files
if [ -f .gitlab-ci.yml ]; then
    echo -e "${GREEN}✅ GitLab CI configuration exists${NC}"
else
    echo -e "${YELLOW}⚠️  GitLab CI configuration not found${NC}"
fi

if [ -f .github/workflows/semio-security.yml ]; then
    echo -e "${GREEN}✅ GitHub Actions configuration exists${NC}"
else
    echo -e "${YELLOW}⚠️  GitHub Actions configuration not found${NC}"
fi

# Add vulnerable test file
if [ -f demo/test_vulnerable_code.py ]; then
    echo -e "${GREEN}✅ Vulnerable test file exists${NC}"
else
    echo -e "${YELLOW}⚠️  Vulnerable test file not found${NC}"
fi

# Create README for demo
cat > DEMO_README.md << 'EOF'
# Semio CI Integration Demo

This repository demonstrates the Semio security analysis tool integrated with CI/CD pipelines.

## Quick Demo

1. **Start Semio API:**
   ```bash
   cd backend
   python -m uvicorn app.main:app --reload --port 8000
   ```

2. **Set up CI variables:**
   - GitLab: Go to Settings → CI/CD → Variables
   - GitHub: Go to Settings → Secrets and variables → Actions
   - Add: `SEMIO_API_KEY` and `SEMIO_API_URL`

3. **Create a Pull Request/Merge Request**
   - Add the vulnerable test file: `demo/test_vulnerable_code.py`
   - Push to trigger CI pipeline
   - Watch Semio create security fixes!

## Expected Results

- Semgrep finds 8+ vulnerabilities
- Semio generates fix recommendations
- New branch created with fixes
- Pull Request opened for review

## Files

- `.gitlab-ci.yml` - GitLab CI configuration
- `.github/workflows/semio-security.yml` - GitHub Actions
- `demo/test_vulnerable_code.py` - Vulnerable test code
- `demo/ci-integration-demo.md` - Detailed demo guide

## Demo Scenarios

1. **SQL Injection** → Parameterized queries
2. **Weak Crypto** → bcrypt hashing
3. **Command Injection** → Input validation
4. **XSS** → Output encoding
5. **Hardcoded Secrets** → Environment variables
6. **Path Traversal** → Path validation
7. **Insecure Random** → secrets module
8. **Debug Mode** → Production settings

---

**Ready to demo!** 🚀
EOF

echo -e "${GREEN}✅ Created DEMO_README.md${NC}"

# Final instructions
echo -e "${BLUE}🎯 Demo Setup Complete!${NC}"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Commit your changes:"
echo "   git add ."
echo "   git commit -m 'Add Semio CI integration demo'"
echo ""
echo "2. Push to your repository:"
echo "   git push origin main"
echo ""
echo "3. Create a Pull Request/Merge Request"
echo ""
echo "4. Watch the CI pipeline run and Semio create security fixes!"
echo ""
echo -e "${GREEN}🎉 Your Semio demo is ready!${NC}"
