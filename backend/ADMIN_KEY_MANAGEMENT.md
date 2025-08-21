# Semio Admin API Key Management

This document describes the secure admin interface for managing API keys in Semio.

## 🔒 Security Overview

The public API key generation endpoints have been **removed** for security reasons. Instead, we provide a secure admin interface that requires direct server access.

## 🛠️ Admin Interface

### Location
- **File**: `backend/admin_key_manager.py`
- **Access**: Direct server access only (not publicly accessible)
- **Purpose**: Secure API key management for administrators

### Features

#### 1. User Management
- List all users in the system
- Create new users with different tiers
- Update user tiers (free/pro/enterprise)
- View user usage statistics

#### 2. API Key Management
- List all API keys in the system
- Generate new API keys for specific users
- Revoke existing API keys
- View key expiration dates and usage

#### 3. Demo Key Information
- Display information about the demo API key
- Show usage instructions

## 🚀 Usage

### Starting the Admin Interface

```bash
cd backend
python admin_key_manager.py
```

### Available Commands

```
1. List all users
2. List all API keys
3. List API keys for specific user
4. Create new user
5. Generate API key for user
6. Revoke API key
7. Update user tier
8. Show demo API key info
9. Exit
```

### Example Workflow

#### 1. Create a New User
```
Enter your choice (1-9): 4
Email: user@example.com
Password (min 8 chars): securepassword123
Tier (free/pro/enterprise) [free]: pro
```

#### 2. Generate API Key
```
Enter your choice (1-9): 5
User ID: [user-id-from-step-1]
Key name (e.g., 'gitlab-pipeline'): production-cli
Expires in days [30]: 90
```

#### 3. List API Keys
```
Enter your choice (1-9): 2
```

## 🔐 API Key Types

### 1. Demo API Key
- **Key**: `demo-semio-api-key-2024-for-testing-only`
- **Purpose**: Testing and demo only
- **Access**: Free tier
- **Expiration**: Never expires
- **Location**: Hardcoded in `auth_service.py`

### 2. Database API Keys
- **Source**: Generated through admin interface
- **Storage**: Database with hashed values
- **Expiration**: Configurable (default 30 days)
- **Security**: Properly hashed and validated

## 🛡️ Security Benefits

### Removed Security Risks
- ❌ No public API key generation endpoints
- ❌ No credential exposure through public endpoints
- ❌ No brute force attack surface
- ❌ No rate limiting bypass attempts

### Added Security Features
- ✅ Admin-only access (requires server access)
- ✅ Proper key hashing and storage
- ✅ Configurable key expiration
- ✅ Key revocation capabilities
- ✅ User tier management
- ✅ Audit trail through database

## 📋 Best Practices

### For Administrators
1. **Secure Access**: Only use the admin interface on secure servers
2. **Key Rotation**: Regularly rotate API keys
3. **Monitoring**: Monitor key usage and revoke unused keys
4. **Documentation**: Keep records of key assignments

### For Users
1. **Demo Key**: Use only for testing and development
2. **Production Keys**: Request from administrators
3. **Secure Storage**: Store keys securely (environment variables, secure vaults)
4. **Key Rotation**: Replace keys when compromised

## 🔧 Configuration

### Environment Variables
```bash
# For the admin interface
export SEMIO_API_URL="http://your-semio-instance.com"
```

### Database Setup
The admin interface automatically initializes the database if needed:
```python
init_db()  # Called automatically on startup
```

## 🚨 Important Notes

1. **Server Access Required**: The admin interface requires direct server access
2. **No Public Endpoints**: All key management is done through the admin interface
3. **Demo Key Only**: For testing, use the demo key; for production, use admin-generated keys
4. **Backup**: Always backup your database before making changes
5. **Audit**: Monitor key usage and maintain audit logs

## 📞 Support

For issues with the admin interface:
1. Check database connectivity
2. Verify user permissions
3. Review error logs
4. Contact system administrator

---

**⚠️ Security Warning**: This admin interface should only be used by authorized administrators with direct server access. Never expose this interface publicly.
