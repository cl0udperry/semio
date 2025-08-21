# Semio AWS Admin Management Guide

This guide covers all the practical ways to manage Semio's API keys and users when deployed on AWS.

## 🚀 **AWS Admin Management Options**

### **Option 1: Web Admin Interface (Recommended)**

The easiest way to manage Semio in AWS is through the web-based admin interface.

#### **Setup:**

1. **Install Dependencies:**
```bash
cd backend
pip install flask flask-login
```

2. **Set Environment Variables:**
```bash
# Set secure admin credentials
export ADMIN_USERNAME="your-admin-username"
export ADMIN_PASSWORD="your-secure-password"
export ADMIN_SECRET_KEY="your-secret-key-for-sessions"

# Set admin interface settings
export ADMIN_HOST="0.0.0.0"  # Allow external access
export ADMIN_PORT="5001"     # Different port from main app
```

3. **Start Admin Interface:**
```bash
cd backend
python web_admin_interface.py
```

4. **Access via Browser:**
```
http://your-aws-instance-ip:5001
```

#### **Security Configuration:**

**For Production Security:**
```bash
# Use strong credentials
export ADMIN_USERNAME="admin-jordan"
export ADMIN_PASSWORD="super-secure-password-2024"
export ADMIN_SECRET_KEY="random-secret-key-32-chars-long"

# Restrict to specific IPs (optional)
export ADMIN_HOST="127.0.0.1"  # Local only
```

**AWS Security Group Configuration:**
- Open port 5001 for admin interface
- Restrict to your IP address only
- Use AWS VPC for additional security

### **Option 2: SSH + CLI Interface**

If you prefer command-line management:

#### **Connect to AWS Instance:**
```bash
# Connect via SSH
ssh -i your-key.pem ec2-user@your-aws-instance-ip

# Navigate to Semio
cd /var/app/current/backend

# Run CLI admin interface
python admin_key_manager.py
```

### **Option 3: AWS Systems Manager (Advanced)**

For enterprise environments:

#### **Setup AWS Systems Manager:**
```bash
# Install SSM Agent (usually pre-installed on AWS instances)
sudo yum install -y amazon-ssm-agent

# Start SSM Agent
sudo systemctl start amazon-ssm-agent
sudo systemctl enable amazon-ssm-agent
```

#### **Use AWS Console:**
1. Go to AWS Systems Manager
2. Select "Session Manager"
3. Connect to your instance
4. Run admin commands directly

## 🔧 **Practical AWS Deployment Scenarios**

### **Scenario 1: Single Instance Deployment**

```bash
# 1. SSH into your instance
ssh -i semio-key.pem ec2-user@ec2-xx-xx-xx-xx.compute-1.amazonaws.com

# 2. Start web admin interface
cd /var/app/current/backend
export ADMIN_USERNAME="admin"
export ADMIN_PASSWORD="secure-password-123"
python web_admin_interface.py

# 3. Access via browser
# http://ec2-xx-xx-xx-xx.compute-1.amazonaws.com:5001
```

### **Scenario 2: Elastic Beanstalk Deployment**

```bash
# 1. Add to your .ebextensions configuration
# Create file: .ebextensions/admin_interface.config

option_settings:
  aws:elasticbeanstalk:application:environment:
    ADMIN_USERNAME: admin
    ADMIN_PASSWORD: your-secure-password
    ADMIN_PORT: 5001

# 2. Deploy with admin interface
eb deploy

# 3. Access via load balancer
# http://your-eb-environment.elasticbeanstalk.com:5001
```

### **Scenario 3: Docker Deployment**

```dockerfile
# Add to your Dockerfile
RUN pip install flask flask-login

# Add admin interface startup
CMD ["sh", "-c", "python web_admin_interface.py & python -m uvicorn app.main:app --host 0.0.0.0 --port 8000"]
```

## 🛡️ **Security Best Practices for AWS**

### **1. Network Security**
```bash
# AWS Security Group Rules
Type: Custom TCP
Port: 5001
Source: Your IP address only
Description: Semio Admin Interface
```

### **2. Environment Variables**
```bash
# Never hardcode credentials
export ADMIN_USERNAME="admin-jordan"
export ADMIN_PASSWORD="complex-password-2024"
export ADMIN_SECRET_KEY="random-32-character-string"

# Use AWS Secrets Manager for production
aws secretsmanager create-secret \
    --name "semio-admin-credentials" \
    --secret-string '{"username":"admin","password":"secure-password"}'
```

### **3. Access Control**
```bash
# Restrict admin interface to specific times
# Add to crontab for scheduled access
0 9-17 * * 1-5 /usr/bin/python /var/app/current/backend/web_admin_interface.py
```

## 📊 **Admin Interface Features**

### **Web Dashboard Capabilities:**
- ✅ **User Management**: Create, list, update users
- ✅ **API Key Management**: Generate, revoke, monitor keys
- ✅ **Real-time Monitoring**: View usage statistics
- ✅ **Secure Authentication**: Login required
- ✅ **Audit Trail**: All actions logged

### **CLI Interface Capabilities:**
- ✅ **Full Control**: All admin functions
- ✅ **Scriptable**: Can be automated
- ✅ **Secure**: Server access only
- ✅ **Lightweight**: No web dependencies

## 🔄 **Common Admin Workflows**

### **Creating a New Production User:**
```bash
# Via Web Interface:
1. Go to http://your-aws-ip:5001
2. Login with admin credentials
3. Fill in user details:
   - Email: production@company.com
   - Password: secure-password-123
   - Tier: pro
4. Click "Create User"
5. Copy the generated API key

# Via CLI:
ssh -i key.pem ec2-user@aws-ip
cd /var/app/current/backend
python admin_key_manager.py
# Choose option 4: Create new user
```

### **Generating API Keys for CI/CD:**
```bash
# Via Web Interface:
1. Login to admin dashboard
2. Go to "Generate API Key" section
3. Enter:
   - User ID: [from user list]
   - Key Name: gitlab-pipeline
   - Expires: 90 days
4. Copy the generated key

# Via CLI:
python admin_key_manager.py
# Choose option 5: Generate API key
```

### **Monitoring Usage:**
```bash
# Via Web Interface:
1. View "Users" table for usage stats
2. Check "API Keys" table for active keys
3. Monitor monthly request limits

# Via CLI:
python admin_key_manager.py
# Choose option 1: List all users
# Choose option 2: List all API keys
```

## 🚨 **Troubleshooting**

### **Common Issues:**

#### **1. Can't Access Admin Interface:**
```bash
# Check if admin interface is running
ps aux | grep web_admin_interface

# Check port availability
netstat -tlnp | grep 5001

# Check firewall rules
sudo iptables -L | grep 5001
```

#### **2. Database Connection Issues:**
```bash
# Check database file permissions
ls -la /var/app/current/backend/semio.db

# Test database connection
python -c "from app.database import SessionLocal; db = SessionLocal(); print('DB OK')"
```

#### **3. Permission Issues:**
```bash
# Fix file permissions
sudo chown -R ec2-user:ec2-user /var/app/current/backend
sudo chmod 755 /var/app/current/backend
```

## 📋 **Quick Reference Commands**

### **Start Admin Interface:**
```bash
# Web Interface
cd backend
export ADMIN_USERNAME="admin"
export ADMIN_PASSWORD="password"
python web_admin_interface.py

# CLI Interface
cd backend
python admin_key_manager.py
```

### **Check Status:**
```bash
# Check if running
ps aux | grep admin

# Check ports
netstat -tlnp | grep 5001

# Check logs
tail -f /var/log/web.stdout.log
```

### **Emergency Access:**
```bash
# If web interface is down, use CLI
ssh -i key.pem ec2-user@aws-ip
cd /var/app/current/backend
python admin_key_manager.py
```

## 🎯 **Recommended AWS Setup**

### **For Production:**
1. **Use Web Admin Interface** on port 5001
2. **Restrict access** to your IP only
3. **Use strong credentials** via environment variables
4. **Monitor usage** regularly
5. **Backup database** regularly

### **For Development:**
1. **Use CLI interface** for quick access
2. **Use demo key** for testing
3. **Keep it simple** with basic security

---

**⚠️ Security Note**: Always use strong passwords and restrict admin access to authorized personnel only. The admin interface should never be publicly accessible.
