# Semio Quick Start Guide

## **Immediate Steps After Deployment**

### **1. Create Your First Admin Account**
```bash
# After deployment, create your admin account
python api_key_manager.py register-admin \
  --email admin@yourcompany.com \
  --password your_secure_password
```

### **2. Generate Your First API Key**
```bash
# Generate API key for your admin account
python api_key_manager.py generate \
  --email admin@yourcompany.com \
  --password your_secure_password \
  --key-name "admin-production-2024" \
  --expires-in-days 365
```

### **3. Test Your Setup**
```bash
# Test the API key works
python semio_cli.py test-connection \
  --api-key YOUR_GENERATED_API_KEY \
  --api-url http://your-semio-url
```

---

## **Daily Operations**

### **Create New User Account**
```bash
# Register a new user
python api_key_manager.py register \
  --email user@company.com \
  --password user_password
```

### **Generate API Key for User**
```bash
# Generate API key for the user
python api_key_manager.py generate \
  --email user@company.com \
  --password user_password \
  --key-name "user-production-2024" \
  --expires-in-days 90
```

### **List All API Keys**
```bash
# List keys for a user
python api_key_manager.py list \
  --email user@company.com \
  --password user_password
```

### **Revoke API Key**
```bash
# Revoke a specific key
python api_key_manager.py revoke \
  --email user@company.com \
  --password user_password \
  --key-name "user-production-2024"
```

---

## **Common Tasks**

### **Check User Status**
```bash
python api_key_manager.py get-user-info \
  --email user@company.com \
  --admin-email admin@yourcompany.com \
  --admin-password admin_password
```

### **Upgrade User Tier**
```bash
python api_key_manager.py upgrade-user \
  --email user@company.com \
  --tier pro \
  --admin-email admin@yourcompany.com \
  --admin-password admin_password
```

### **Monitor API Usage**
```bash
python api_key_manager.py monitor-usage \
  --key-name "user-production-2024"
```

---

## **Security Checklist**

### **Weekly Tasks**
- [ ] Review API key usage
- [ ] Check for expired keys
- [ ] Monitor failed authentication attempts
- [ ] Review user account status

### **Monthly Tasks**
- [ ] Rotate API keys (90-day cycle)
- [ ] Audit user permissions
- [ ] Review rate limit violations
- [ ] Update security documentation

### **Quarterly Tasks**
- [ ] Full security audit
- [ ] Update user tiers as needed
- [ ] Review and update rate limits
- [ ] Backup user database

---

## **Emergency Procedures**

### **API Key Compromise**
```bash
# Immediately revoke compromised key
python api_key_manager.py revoke \
  --email user@company.com \
  --password user_password \
  --key-name "compromised-key"

# Generate new key
python api_key_manager.py generate \
  --email user@company.com \
  --password user_password \
  --key-name "emergency-replacement" \
  --expires-in-days 7
```

### **User Account Compromise**
```bash
# Deactivate user account
python api_key_manager.py deactivate-user \
  --email user@company.com \
  --admin-email admin@yourcompany.com \
  --admin-password admin_password

# Revoke all user's API keys
python api_key_manager.py revoke-all-keys \
  --email user@company.com \
  --admin-email admin@yourcompany.com \
  --admin-password admin_password
```

---

## 📞 **Support Contacts**

- **Technical Issues**: Check logs and documentation first
- **Account Issues**: Use admin commands above
- **Security Incidents**: Immediate action required
- **Feature Requests**: Document and prioritize

---

## **Pro Tips**

1. **Use Environment Variables**: Never hardcode API keys
2. **Descriptive Names**: Use clear naming for API keys
3. **Regular Rotation**: Rotate keys every 90 days
4. **Monitor Usage**: Keep track of API usage patterns
5. **Document Everything**: Maintain clear records of all changes
