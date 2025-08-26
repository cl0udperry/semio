# Semio Environment Variables Guide

This document lists all environment variables needed for Semio deployment.

## 🔐 **REQUIRED Environment Variables**

### **Admin Interface (MUST SET)**
```bash
ADMIN_USERNAME=your-admin-username
ADMIN_PASSWORD=your-secure-password
ADMIN_SECRET_KEY=your-32-character-secret-key
```

**Description:**
- `ADMIN_USERNAME`: Username for admin interface login
- `ADMIN_PASSWORD`: Password for admin interface login
- `ADMIN_SECRET_KEY`: Flask session secret (32+ characters)

**Example:**
```bash
ADMIN_USERNAME=admin-jordan
ADMIN_PASSWORD=super-secure-password-2024
ADMIN_SECRET_KEY=my-secret-key-32-chars-long-here
```

## 🗄️ **Database Configuration**

### **Option 1: SQLite (Default - No setup required)**
```bash
USE_SQLITE=true
# No DATABASE_URL needed
```

### **Option 2: PostgreSQL (Production)**
```bash
USE_SQLITE=false
DATABASE_URL=postgresql://username:password@host:5432/database_name
```

### **Option 3: PostgreSQL with Advanced Settings**
```bash
USE_SQLITE=false
DATABASE_URL=postgresql://username:password@host:5432/database_name
DB_POOL_SIZE=10
DB_MAX_OVERFLOW=20
DB_POOL_RECYCLE=3600
SQL_ECHO=false
```

**Database Variables:**
- `USE_SQLITE`: Set to "false" for PostgreSQL, "true" for SQLite (default)
- `DATABASE_URL`: PostgreSQL connection string (required if USE_SQLITE=false)
- `DB_POOL_SIZE`: Connection pool size (default: 10)
- `DB_MAX_OVERFLOW`: Max overflow connections (default: 20)
- `DB_POOL_RECYCLE`: Connection recycle time in seconds (default: 3600)
- `SQL_ECHO`: Enable SQL logging (default: false)

## 🔑 **Optional Environment Variables**

### **Demo API Key**
```bash
DEMO_API_KEY=your-demo-api-key
```
**Description:** API key for testing and demo purposes (optional)

### **Google API Key**
```bash
GOOGLE_API_KEY=your-google-api-key
```
**Description:** Google API key for LLM features (optional)

## 🚀 **AWS Deployment Examples**

### **Elastic Beanstalk Environment Properties:**
```
ADMIN_USERNAME = admin-jordan
ADMIN_PASSWORD = super-secure-password-2024
ADMIN_SECRET_KEY = my-secret-key-32-chars-long-here
USE_SQLITE = true
DEMO_API_KEY = demo-key-2024
GOOGLE_API_KEY = your-google-api-key
```

### **EC2 Environment Variables:**
```bash
# Add to /etc/environment
ADMIN_USERNAME=admin-jordan
ADMIN_PASSWORD=super-secure-password-2024
ADMIN_SECRET_KEY=my-secret-key-32-chars-long-here
USE_SQLITE=true
DEMO_API_KEY=demo-key-2024
GOOGLE_API_KEY=your-google-api-key
```

## 🔧 **Quick Setup Commands**

### **Generate Secure Admin Secret Key:**
```bash
# Generate a 32-character random string
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

### **Test Environment Variables:**
```bash
# Check if variables are set
echo $ADMIN_USERNAME
echo $ADMIN_PASSWORD
echo $ADMIN_SECRET_KEY
echo $USE_SQLITE
echo $DATABASE_URL
```

## ⚠️ **Security Notes**

1. **Never commit environment variables** to version control
2. **Use strong passwords** for admin credentials
3. **Generate random secret keys** for ADMIN_SECRET_KEY
4. **Use HTTPS** in production
5. **Rotate credentials** regularly

## 🧪 **Testing Your Configuration**

### **Test Admin Interface:**
```bash
curl -X GET "http://your-instance-ip:5001"
```

### **Test Main API:**
```bash
curl -X GET "http://your-instance-ip:8000/health"
```

### **Test CLI with Demo Key:**
```bash
export SEMIO_API_KEY="your-demo-api-key"
export SEMIO_API_URL="http://your-instance-ip:8000"
python semio_cli.py
```

## 📋 **Deployment Checklist**

- [ ] Set `ADMIN_USERNAME`
- [ ] Set `ADMIN_PASSWORD`
- [ ] Set `ADMIN_SECRET_KEY`
- [ ] Configure database (`USE_SQLITE` and `DATABASE_URL`)
- [ ] Set `DEMO_API_KEY` (optional)
- [ ] Set `GOOGLE_API_KEY` (optional)
- [ ] Test admin interface login
- [ ] Test main API endpoints
- [ ] Test CLI functionality

---

**Remember:** All hardcoded credentials have been removed. You MUST set the required environment variables for the application to work!
