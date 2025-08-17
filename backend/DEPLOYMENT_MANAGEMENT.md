# 🚀 Deployment Environment Management

## 📁 File Structure
```
backend/
├── requirements.txt          # Base requirements (AWS production)
├── requirements-dev.txt      # Development requirements (local)
├── requirements-prod.txt     # Production requirements (AWS)
├── .ebextensions/           # AWS Elastic Beanstalk config
├── Procfile                 # AWS deployment process
└── AWS_DEPLOYMENT_GUIDE.md  # Deployment instructions
```

## 🔄 Environment Management Strategy

### **Local Development:**
```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run locally
python -m uvicorn app.main:app --reload
```

### **AWS Production:**
```bash
# AWS uses requirements.txt automatically
# No manual installation needed
```

## 📋 Dependency Differences Explained

### **Development (requirements-dev.txt):**
- **openai==1.3.7**: LLM API integration
- **httpx==0.25.2**: Modern HTTP client
- **psycopg2-binary==2.9.9**: PostgreSQL support
- **alembic==1.13.1**: Database migrations
- **gradio==4.15.0**: Latest Gradio version

### **Production (requirements.txt):**
- **requests==2.31.0**: Stable HTTP client
- **gradio==4.7.1**: AWS-compatible version
- **markdown==3.5.1**: Report generation
- **No LLM dependencies**: Production doesn't need OpenAI

## 🎯 Why This Approach?

### **Benefits:**
1. **Environment Isolation**: Local dev vs production
2. **AWS Compatibility**: Tested versions for cloud
3. **Flexibility**: Easy to add/remove features
4. **Maintenance**: Clear separation of concerns

### **When to Update:**
- **requirements.txt**: When deploying to AWS
- **requirements-dev.txt**: When adding local features
- **requirements-prod.txt**: When updating production stack

## 🔧 Management Commands

### **Update Dependencies:**
```bash
# Update development
pip install -r requirements-dev.txt

# Update production (for AWS)
pip install -r requirements-prod.txt

# Generate requirements from current environment
pip freeze > requirements-current.txt
```

### **Deploy to AWS:**
```bash
# AWS automatically uses requirements.txt
eb deploy
```

## ⚠️ Important Notes

### **Version Pinning:**
- All versions are pinned (==) for consistency
- Prevents unexpected updates
- Ensures reproducible deployments

### **AWS Requirements:**
- AWS Elastic Beanstalk only reads `requirements.txt`
- Must be in the root of your application
- No support for multiple requirements files

### **Local Development:**
- Use `requirements-dev.txt` for full feature set
- Includes development tools and latest versions
- Can experiment with new packages

## 🚀 Best Practices

1. **Keep requirements.txt production-ready**
2. **Test AWS deployment regularly**
3. **Document dependency changes**
4. **Use virtual environments locally**
5. **Monitor for security updates**

## 🔄 Workflow

### **Development:**
1. Install dev requirements: `pip install -r requirements-dev.txt`
2. Develop and test locally
3. When ready for production, update `requirements.txt`

### **Production:**
1. AWS reads `requirements.txt` automatically
2. Deploy with: `eb deploy`
3. Monitor logs: `eb logs`

This approach gives you the best of both worlds: full development capabilities locally and stable production deployment on AWS!
