# AWS Console Deployment Guide for Semio

This guide walks you through deploying Semio to AWS using the console upload method.

## 📋 Pre-Deployment Checklist

### ✅ Code Preparation
- [x] Hardcoded credentials updated (admin password changed)
- [x] Database configuration uses environment variables
- [x] Demo API key warnings added
- [x] All code committed to git

## 🔧 Environment Variables Configuration

### **CRITICAL: Set These Environment Variables in AWS**

You **MUST** configure these environment variables in your AWS deployment:

#### **1. Admin Interface Credentials (REQUIRED)**
```bash
ADMIN_USERNAME=your-admin-username
ADMIN_PASSWORD=your-secure-password
ADMIN_SECRET_KEY=your-32-character-secret-key
```

#### **2. Database Configuration (Optional)**
```bash
DATABASE_URL=postgresql://user:password@host:port/db
```

#### **3. Optional: Change Demo API Key**
```bash
DEMO_API_KEY=your-production-demo-key
```

## 🚀 Deployment Steps

### Step 1: Prepare Your Code
1. **Create deployment package**:
   ```bash
   # In your local semio directory
   cd backend
   zip -r semio-deployment.zip . -x "*.pyc" "__pycache__/*" "*.log" "venv/*"
   ```

### Step 2: AWS Console Upload

#### Option A: Elastic Beanstalk (Recommended)
1. **Go to AWS Console** → **Elastic Beanstalk**
2. **Create Application**:
   - Application name: `semio`
   - Platform: `Python 3.11`
   - Platform branch: `Python 3.11 running on 64bit Amazon Linux 2`
   - Platform version: `Latest`

3. **Configure Environment**:
   - Environment name: `semio-prod`
   - Domain: `semio.yourdomain.com` (optional)
   - Environment type: `Single instance` (for cost savings)

4. **Upload Code**:
   - Upload your `semio-deployment.zip` file
   - Click "Create environment"

5. **Set Environment Variables** (CRITICAL STEP):
   - Go to your environment → **Configuration**
   - Click **Software** → **Edit**
   - Scroll down to **Environment properties**
   - Add these key-value pairs:
     ```
     ADMIN_USERNAME = your-admin-username
     ADMIN_PASSWORD = your-secure-password
     ADMIN_SECRET_KEY = your-32-character-secret-key
     DATABASE_URL = your-database-url (optional)
     ```
   - Click **Apply**

#### Option B: EC2 Instance
1. **Launch EC2 Instance**:
   - AMI: `Amazon Linux 2023`
   - Instance type: `t3.micro` (free tier) or `t3.small`
   - Security Group: Open ports 22 (SSH), 80 (HTTP), 443 (HTTPS), 5001 (Admin), 8000 (API)

2. **Upload Code**:
   - Use AWS Systems Manager Session Manager
   - Or SCP the zip file to the instance

3. **Set Environment Variables**:
   ```bash
   # SSH into your instance
   sudo nano /etc/environment
   
   # Add these lines:
   ADMIN_USERNAME=your-admin-username
   ADMIN_PASSWORD=your-secure-password
   ADMIN_SECRET_KEY=your-32-character-secret-key
   DATABASE_URL=your-database-url
   
   # Save and reload environment
   source /etc/environment
   ```

## 🔐 Security Configuration

### **Environment Variables You MUST Set:**

| Variable | Description | Example | Required |
|----------|-------------|---------|----------|
| `ADMIN_USERNAME` | Admin login username | `admin-jordan` | ✅ Yes |
| `ADMIN_PASSWORD` | Admin login password | `super-secure-password-2024` | ✅ Yes |
| `ADMIN_SECRET_KEY` | Flask session secret | `my-secret-key-32-chars-long-here` | ✅ Yes |
| `DATABASE_URL` | Database connection | `postgresql://user:pass@host:5432/db` | ❌ No (uses SQLite by default) |
| `DEMO_API_KEY` | Demo API key for testing | `your-demo-api-key` | ❌ No |
| `GOOGLE_API_KEY` | Google API key | `your-google-api-key` | ❌ No |

### **Database Configuration Options:**

#### **Option 1: SQLite (Default - No setup required)**
```bash
USE_SQLITE=true
# No DATABASE_URL needed - uses local SQLite file
```

#### **Option 2: PostgreSQL (Production)**
```bash
USE_SQLITE=false
DATABASE_URL=postgresql://username:password@host:5432/database_name
```

#### **Option 3: PostgreSQL with Advanced Settings**
```bash
USE_SQLITE=false
DATABASE_URL=postgresql://username:password@host:5432/database_name
DB_POOL_SIZE=10
DB_MAX_OVERFLOW=20
DB_POOL_RECYCLE=3600
SQL_ECHO=false
```

### **Security Notes:**
- **Admin credentials**: MUST be set via environment variables (no defaults)
- **Demo API Key**: Set via `DEMO_API_KEY` environment variable (optional)
- **Database**: Uses SQLite by default, set `USE_SQLITE=false` and `DATABASE_URL` for PostgreSQL

## 🧪 Post-Deployment Testing

### 1. Test Main API:
```bash
curl -X GET "http://your-instance-ip:8000/health"
```

### 2. Test Admin Interface:
```bash
curl -X GET "http://your-instance-ip:5001"
```

### 3. Test CLI with Demo Key:
```bash
export SEMIO_API_KEY="your-demo-api-key"
export SEMIO_API_URL="http://your-instance-ip:8000"
python semio_cli.py
```

## 🔧 Troubleshooting

### Common Issues:

1. **Admin login fails**:
   - ✅ Verify `ADMIN_USERNAME` and `ADMIN_PASSWORD` are set correctly
   - ✅ Check admin interface logs
   - ✅ Ensure environment variables are loaded

2. **Port 5001 not accessible**:
   - ✅ Check security group rules (port 5001)
   - ✅ Verify admin interface is running

3. **Database connection errors**:
   - ✅ Check `DATABASE_URL` environment variable
   - ✅ Ensure database is accessible from instance

### **Where to Check Environment Variables:**

#### Elastic Beanstalk:
- Console → Environment → Configuration → Software → Environment properties

#### EC2:
```bash
# Check if variables are set
echo $ADMIN_USERNAME
echo $ADMIN_PASSWORD
echo $ADMIN_SECRET_KEY

# View all environment variables
env | grep ADMIN
```

## 📞 Support

If you encounter issues:
1. ✅ Check AWS CloudWatch logs
2. ✅ Verify environment variables are set correctly
3. ✅ Test connectivity to all required services

## 🎯 Next Steps

After successful deployment:
1. **Generate production API keys** via admin interface
2. **Set up monitoring** and alerts
3. **Configure SSL certificates** for HTTPS
4. **Set up automated backups** for database
5. **Monitor usage** and performance

---

**🚨 CRITICAL SECURITY REMINDER**: 
- Always change the default admin credentials!
- Set `ADMIN_PASSWORD` to a strong password
- Set `ADMIN_SECRET_KEY` to a random 32-character string
- Consider changing the demo API key for production
