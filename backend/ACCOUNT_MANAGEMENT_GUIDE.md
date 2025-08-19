# Semio Account & API Key Management Guide

## 🏗️ **System Architecture Overview**

### **User Tiers & Access Levels**
```
┌─────────────────┬─────────────────┬─────────────────┬─────────────────┐
│   Free Tier     │   Pro Tier      │ Enterprise Tier │   Admin Tier    │
├─────────────────┼─────────────────┼─────────────────┼─────────────────┤
│ • UI Access     │ • UI Access     │ • UI Access     │ • UI Access     │
│ • Rate Limited  │ • Higher Limits │ • No Limits     │ • No Limits     │
│ • Basic Fixes   │ • Enhanced AI   │ • Agentic AI    │ • All Features  │
│ • No API Keys   │ • API Keys      │ • API Keys      │ • System Admin  │
└─────────────────┴─────────────────┴─────────────────┴─────────────────┘
```

### **Authentication Methods**
1. **UI Access**: JWT tokens (login/register)
2. **CLI Access**: API keys (for automation)
3. **Admin Access**: Admin credentials + API keys

---

## 👤 **User Account Management**

### **1. User Registration Process**

#### **Manual Registration (Admin)**
```bash
# Use the API key manager to create admin accounts
python api_key_manager.py register-admin --email admin@company.com --password secure_password
```

#### **Self-Registration (Users)**
```bash
# Users can register via UI or API
curl -X POST "http://your-semio-url/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@company.com", "password": "secure_password"}'
```

### **2. User Tiers & Upgrades**

#### **Free Tier (Default)**
- **Features**: Basic UI access, rate-limited
- **Limits**: 5 requests/hour, basic fixes only
- **No API keys**: UI-only access

#### **Pro Tier (Paid)**
- **Features**: Enhanced AI, higher limits, API keys
- **Limits**: 100 requests/hour, enhanced fixes
- **API Keys**: Up to 5 active keys

#### **Enterprise Tier (Premium)**
- **Features**: Agentic AI, unlimited access, priority support
- **Limits**: No rate limiting, all features
- **API Keys**: Unlimited keys, advanced features

### **3. User Management Commands**

#### **List All Users**
```bash
python api_key_manager.py list-users --admin-email admin@company.com --admin-password admin_password
```

#### **Upgrade User Tier**
```bash
python api_key_manager.py upgrade-user --email user@company.com --tier pro --admin-email admin@company.com --admin-password admin_password
```

#### **Deactivate User**
```bash
python api_key_manager.py deactivate-user --email user@company.com --admin-email admin@company.com --admin-password admin_password
```

---

## 🔑 **API Key Management**

### **1. API Key Lifecycle**

#### **Generation**
```bash
# Generate API key for a user
python api_key_manager.py generate \
  --email user@company.com \
  --password user_password \
  --key-name "production-cli" \
  --expires-in-days 365
```

#### **Listing**
```bash
# List all API keys for a user
python api_key_manager.py list \
  --email user@company.com \
  --password user_password
```

#### **Revocation**
```bash
# Revoke an API key
python api_key_manager.py revoke \
  --email user@company.com \
  --password user_password \
  --key-name "production-cli"
```

### **2. API Key Best Practices**

#### **Naming Convention**
```
{environment}-{purpose}-{date}
Examples:
- production-cli-2024
- staging-gitlab-pipeline
- development-testing
- production-monitoring
```

#### **Expiration Strategy**
- **Development**: 30 days
- **Staging**: 90 days
- **Production**: 365 days
- **Emergency**: 7 days (for urgent fixes)

#### **Security Guidelines**
- Use descriptive names
- Set appropriate expiration dates
- Rotate keys regularly
- Monitor key usage
- Never share keys in code
- Don't use the same key for multiple purposes

### **3. API Key Usage Examples**

#### **GitLab CI/CD**
```yaml
variables:
  SEMIO_API_KEY: "your-api-key-here"
  SEMIO_API_URL: "http://your-semio-url"

semio-analysis:
  script:
    - curl -X POST "$SEMIO_API_URL/api/review-cli?api_key=$SEMIO_API_KEY" \
        -H "Content-Type: application/json" \
        -d @semgrep-results.json
```

#### **Local Development**
```bash
# Set environment variable
export SEMIO_API_KEY="your-api-key-here"

# Test API
python semio_cli.py test-connection
```

#### **Monitoring Scripts**
```python
import requests

api_key = "your-api-key-here"
api_url = "http://your-semio-url"

response = requests.post(
    f"{api_url}/api/review-cli?api_key={api_key}",
    json=semgrep_data,
    headers={"Content-Type": "application/json"}
)
```

---

## **Security & Access Control**

### **1. Rate Limiting Strategy**

#### **UI Access (Public)**
- **Free Tier**: 5 requests/hour
- **Pro Tier**: 50 requests/hour
- **Enterprise**: 200 requests/hour

#### **CLI Access (API Keys)**
- **Free Tier**: No CLI access
- **Pro Tier**: 100 requests/hour
- **Enterprise**: No limits

### **2. Access Control Matrix**

| Endpoint | Free UI | Pro UI | Enterprise UI | CLI (API Key) |
|----------|---------|--------|---------------|---------------|
| `/api/review-public` | Yes | Yes | Yes | No |
| `/api/review` | Yes | Yes | Yes | No |
| `/api/review-cli` | No | Yes | Yes | Yes |
| `/api/review-agentic` | No | Yes | Yes | No |
| `/api/review-agentic-cli` | No | No | Yes | Yes |

### **3. Security Monitoring**

#### **Key Usage Tracking**
```bash
# Monitor API key usage
python api_key_manager.py monitor-usage --key-name "production-cli"
```

#### **Suspicious Activity Detection**
- Monitor for unusual request patterns
- Track failed authentication attempts
- Alert on rate limit violations

---

## **Production Deployment Checklist**

### **1. Pre-Deployment**
- [ ] Set up admin account
- [ ] Configure environment variables
- [ ] Set up monitoring
- [ ] Test all endpoints
- [ ] Verify rate limiting

### **2. User Onboarding**
- [ ] Create user accounts
- [ ] Assign appropriate tiers
- [ ] Generate API keys
- [ ] Provide documentation
- [ ] Set up support channels

### **3. Ongoing Management**
- [ ] Monitor usage patterns
- [ ] Rotate API keys regularly
- [ ] Update user tiers as needed
- [ ] Review security logs
- [ ] Backup user data

---

## **Administrative Tools**

### **1. User Management Scripts**

#### **Bulk User Creation**
```python
# create_users.py
import requests

users = [
    {"email": "dev1@company.com", "tier": "pro"},
    {"email": "dev2@company.com", "tier": "pro"},
    {"email": "admin@company.com", "tier": "enterprise"}
]

for user in users:
    # Create user account
    # Generate API key
    # Send welcome email
```

#### **Usage Analytics**
```python
# usage_analytics.py
def generate_usage_report():
    # Collect usage data
    # Generate reports
    # Send to stakeholders
```

### **2. Monitoring & Alerts**

#### **Health Checks**
```bash
# Check system health
curl -f "http://your-semio-url/health"

# Check API key validity
python api_key_manager.py validate-key --key-name "production-cli"
```

#### **Automated Alerts**
- API key expiration warnings
- Rate limit violations
- System performance issues
- Security incidents

---

## 🔄 **Migration & Scaling**

### **1. User Migration**
```bash
# Export existing users
python api_key_manager.py export-users --output users.json

# Import to new system
python api_key_manager.py import-users --input users.json
```

### **2. API Key Rotation**
```bash
# Generate new keys
python api_key_manager.py rotate-keys --user-email user@company.com

# Update CI/CD pipelines
# Update monitoring scripts
# Revoke old keys after migration
```

### **3. Scaling Considerations**
- **Database**: Consider moving from SQLite to PostgreSQL
- **Caching**: Implement Redis for session management
- **Load Balancing**: Multiple instances for high availability
- **Monitoring**: Centralized logging and metrics

---

## 📞 **Support & Troubleshooting**

### **1. Common Issues**

#### **API Key Not Working**
```bash
# Check key validity
python api_key_manager.py validate-key --key-name "production-cli"

# Check user tier
python api_key_manager.py get-user-info --email user@company.com
```

#### **Rate Limit Exceeded**
- Check current usage
- Consider upgrading tier
- Implement request batching

#### **Authentication Errors**
- Verify email/password
- Check account status
- Reset password if needed

### **2. Support Channels**
- **Documentation**: README files and guides
- **Email Support**: support@yourcompany.com
- **Slack Channel**: #semio-support
- **Emergency**: Phone support for enterprise customers

---

## **Best Practices Summary**

### **For Administrators**
1. **Regular Audits**: Review user accounts and API keys monthly
2. **Security First**: Implement least-privilege access
3. **Documentation**: Keep procedures updated
4. **Monitoring**: Set up comprehensive logging
5. **Backup**: Regular database backups

### **For Users**
1. **Secure Keys**: Never commit API keys to version control
2. **Key Rotation**: Rotate keys every 90 days
3. **Monitoring**: Monitor your own usage
4. **Reporting**: Report suspicious activity immediately
5. **Updates**: Keep client tools updated

### **For Developers**
1. **Environment Variables**: Use env vars for API keys
2. **Error Handling**: Implement proper error handling
3. **Testing**: Test with different user tiers
4. **Documentation**: Document API usage patterns
5. **Security**: Follow security best practices
