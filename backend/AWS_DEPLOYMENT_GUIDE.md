# AWS Elastic Beanstalk Deployment Guide for Semio

## Prerequisites Checklist
- [ ] AWS Account (Free Tier)
- [ ] AWS CLI installed
- [ ] EB CLI installed
- [ ] Git repository ready
- [ ] Billing alerts set up

---

## Step 1: AWS Account Setup

### 1.1 Create AWS Account
1. Go to [AWS Console](https://aws.amazon.com/)
2. Click "Create an AWS Account"
3. Follow the signup process
4. **IMPORTANT**: Use a credit card (won't be charged if you stay in free tier)

### 1.2 Set Up Billing Alerts (CRITICAL!)
1. Go to AWS Billing Dashboard
2. Set up CloudWatch Budgets:
   - Alert at $0.01
   - Alert at $1.00
   - Alert at $5.00
3. This prevents unexpected charges

---

## 🛠️ Step 2: Install Required Tools

### 2.1 Install AWS CLI
```bash
# Windows (PowerShell)
winget install -e --id Amazon.AWSCLI

# Verify installation
aws --version
```

### 2.2 Install EB CLI
```bash
pip install awsebcli

# Verify installation
eb --version
```

---

## 🔑 Step 3: Configure AWS Credentials

### 3.1 Get AWS Access Keys
1. Go to AWS Console → IAM → Users
2. Create a new user or use your root user
3. Attach "AWSElasticBeanstalkFullAccess" policy
4. Create Access Key ID and Secret Access Key
5. **SAVE THESE SECURELY** - you won't see the secret key again

### 3.2 Configure AWS CLI
```bash
aws configure
# AWS Access Key ID: [your-access-key]
# AWS Secret Access Key: [your-secret-key]
# Default region name: us-east-1 (or your preferred region)
# Default output format: json
```

---

## Step 4: Deploy to AWS

### 4.1 Initialize EB Application
```bash
cd backend
eb init
```

**Follow the prompts:**
- Select region: `us-east-1` (or your region)
- Create new application: `semio`
- Platform: `Python`
- Platform version: `Python 3.11`
- Set up SSH: `No` (for now)

### 4.2 Create Environment (SINGLE INSTANCE)
```bash
eb create semio-production --single-instance
```

**This command:**
- Creates a single instance environment (free tier)
- Uses t2.micro instance type
- Disables load balancer
- Deploys your application

### 4.3 Monitor Deployment
```bash
# Check status
eb status

# View logs
eb logs

# Open application
eb open
```

---

## Step 5: Verify Security Features

### 5.1 Test Your Application
1. Visit the URL provided by EB
2. Test the health endpoint: `https://your-app.elasticbeanstalk.com/health`
3. Test rate limiting: Make multiple requests to `/api/review-public`
4. Verify UI-only access protection

### 5.2 Update Dashboard URL
Update your Gradio dashboard to use the new AWS URL:
```python
# In dashboard.py, update the default API URL
DEFAULT_API_URL = "https://your-app.elasticbeanstalk.com"
```

---

## 💰 Step 6: Cost Management

### 6.1 Monitor Usage
1. AWS Console → Billing Dashboard
2. Check EC2 usage (should be ~750 hours/month max)
3. Monitor for any unexpected charges

### 6.2 Stop When Not Testing
```bash
# Stop environment (saves money)
eb terminate semio-production

# Recreate when needed
eb create semio-production --single-instance
```

### 6.3 Set Up Lifecycle Policies
1. Go to EB Console → Application → Configuration
2. Set up automatic cleanup of old versions
3. Configure S3 bucket lifecycle (if using)

---

## 🔄 Step 7: Update Deployment

### 7.1 Deploy Changes
```bash
# After making code changes
git add .
git commit -m "Update for AWS deployment"
eb deploy
```

### 7.2 View Logs
```bash
eb logs
```

---

## Important Notes

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

## 🆘 Troubleshooting

### Common Issues:
1. **Deployment fails**: Check `eb logs`
2. **App not responding**: Check instance health
3. **High costs**: Verify single instance configuration

### Useful Commands:
```bash
eb status          # Check environment status
eb logs            # View application logs
eb health          # Check application health
eb ssh             # SSH into instance (if enabled)
eb terminate       # Delete environment
```

---

## Success Checklist
- [ ] Application deployed successfully
- [ ] Health endpoint responding
- [ ] Security features working
- [ ] Rate limiting functional
- [ ] Billing alerts configured
- [ ] Usage within free tier limits
- [ ] Application accessible via public URL

**Your Semio application is now live on AWS!**
