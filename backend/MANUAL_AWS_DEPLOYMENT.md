# 🚀 Manual AWS Console Deployment Guide

## 📦 **Deployment Package Ready!**
- **File**: `semio-deployment.zip` (98KB)
- **Location**: `backend/semio-deployment.zip`
- **Contents**: Your complete Semio application

---

## 🔧 **Step 1: AWS Account Setup**

### 1.1 Create AWS Account
1. Go to [AWS Console](https://aws.amazon.com/)
2. Click "Create an AWS Account"
3. Follow the signup process
4. **IMPORTANT**: Use a credit card (won't be charged if you stay in free tier)

### 1.2 Set Up Billing Alerts (CRITICAL!)
1. Go to AWS Console → Billing Dashboard
2. Set up CloudWatch Budgets:
   - Alert at $0.01
   - Alert at $1.00
   - Alert at $5.00
3. This prevents unexpected charges

---

## 🛠️ **Step 2: Configure AWS CLI**

### 2.1 Get AWS Access Keys
1. Go to AWS Console → IAM → Users
2. Create a new user or use your root user
3. Attach "AWSElasticBeanstalkFullAccess" policy
4. Create Access Key ID and Secret Access Key
5. **SAVE THESE SECURELY** - you won't see the secret key again

### 2.2 Configure AWS CLI
```bash
aws configure
# AWS Access Key ID: [your-access-key]
# AWS Secret Access Key: [your-secret-key]
# Default region name: us-east-1 (or your preferred region)
# Default output format: json
```

---

## 🚀 **Step 3: Deploy via AWS Console**

### 3.1 Navigate to Elastic Beanstalk
1. Go to AWS Console
2. Search for "Elastic Beanstalk"
3. Click "Create Application"

### 3.2 Create Application
1. **Application name**: `semio`
2. **Platform**: `Python`
3. **Platform version**: `Python 3.11`
4. **Application code**: `Upload your code`
5. Click "Choose file" and select `semio-deployment.zip`

### 3.3 Configure Environment
1. **Environment name**: `semio-production`
2. **Domain**: Leave default (or choose custom)
3. **Platform**: `Python 3.11`
4. **Platform branch**: `Python 3.11 running on 64bit Amazon Linux 2`

### 3.4 Configure Instance
1. **Environment type**: `Single instance (free tier eligible)`
2. **Instance type**: `t2.micro`
3. **EC2 key pair**: `No key pair` (for now)

### 3.5 Advanced Configuration
1. Click "Configure more options"
2. **Software**: 
   - Set environment variables:
     - `SEMIO_ENVIRONMENT`: `production`
     - `DEBUG`: `False`
     - `PUBLIC_RATE_LIMIT`: `5`
     - `RATE_LIMIT_WINDOW`: `3600`
     - `AUTH_RATE_LIMIT`: `100`
     - `AUTH_RATE_LIMIT_WINDOW`: `3600`
3. **Capacity**: Ensure single instance
4. **Load balancer**: Disabled (free tier)

### 3.6 Deploy
1. Click "Create application"
2. Wait for deployment (5-10 minutes)
3. Monitor the deployment process

---

## 🔍 **Step 4: Verify Deployment**

### 4.1 Check Application Status
1. In Elastic Beanstalk console
2. Look for green checkmark ✓
3. Note your application URL

### 4.2 Test Your Application
1. Visit your application URL
2. Test health endpoint: `https://your-app.elasticbeanstalk.com/health`
3. Test rate limiting: Make multiple requests to `/api/review-public`
4. Verify UI-only access protection

### 4.3 Update Dashboard URL
Update your Gradio dashboard to use the new AWS URL:
```python
# In dashboard.py, update the default API URL
DEFAULT_API_URL = "https://your-app.elasticbeanstalk.com"
```

---

## 💰 **Step 5: Cost Management**

### 5.1 Monitor Usage
1. AWS Console → Billing Dashboard
2. Check EC2 usage (should be ~750 hours/month max)
3. Monitor for any unexpected charges

### 5.2 Stop When Not Testing
1. Go to Elastic Beanstalk console
2. Select your environment
3. Click "Actions" → "Terminate environment"
4. Recreate when needed

---

## 🔄 **Step 6: Update Deployment**

### 6.1 Update Application
1. Make code changes locally
2. Create new deployment package:
   ```bash
   cd backend
   Compress-Archive -Path "app", "requirements.txt", "Procfile", ".ebextensions" -DestinationPath "semio-deployment-v2.zip" -Force
   ```
3. Upload new ZIP file in Elastic Beanstalk console

### 6.2 Deploy Updates
1. Go to Elastic Beanstalk console
2. Select your environment
3. Click "Upload and deploy"
4. Select your new ZIP file
5. Deploy

---

## ⚠️ **Important Notes**

### Free Tier Limits:
- **750 hours/month** of t2.micro instances
- **Single instance only** (no load balancer)
- **12 months** of free tier benefits

### Cost-Saving Tips:
1. **Always use single instance**
2. **Set up billing alerts**
3. **Stop environment when not testing**
4. **Monitor usage regularly**
5. **Use t2.micro instances only**

### Security:
- Your app will be publicly accessible
- AWS handles basic security (firewall, HTTPS)
- Your rate limiting and authentication still work

---

## 🆘 **Troubleshooting**

### Common Issues:
1. **Deployment fails**: Check environment logs in console
2. **App not responding**: Check instance health
3. **High costs**: Verify single instance configuration

### Useful AWS Console Features:
- **Environment logs**: View application logs
- **Health**: Monitor application health
- **Configuration**: Modify environment settings
- **Monitoring**: View metrics and alarms

---

## 🎯 **Success Checklist**
- [ ] AWS account created
- [ ] Billing alerts configured
- [ ] Application deployed successfully
- [ ] Health endpoint responding
- [ ] Security features working
- [ ] Rate limiting functional
- [ ] Usage within free tier limits
- [ ] Application accessible via public URL

**Your Semio application is now live on AWS! 🎉**

---

## 📚 **Learning Benefits**

This manual approach teaches you:
- ✅ AWS Console navigation
- ✅ Elastic Beanstalk concepts
- ✅ Environment configuration
- ✅ Deployment process
- ✅ Cost management
- ✅ Troubleshooting skills

**You can now replicate this process for any future applications!**
