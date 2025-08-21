#!/usr/bin/env python3
"""
Semio Web Admin Interface
A secure web-based admin interface for managing API keys in AWS.
This should be protected with authentication and only accessible to admins.
"""

import os
import sys
import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Optional, List, Dict
import json
from flask import Flask, render_template_string, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

# Add the backend directory to the path so we can import app modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.database import SessionLocal, init_db
from app.models.database_models import User, APIKey
from app.services.auth_service import AuthService

app = Flask(__name__)
app.secret_key = os.getenv('ADMIN_SECRET_KEY', 'change-this-in-production')

# Simple admin user for web interface
class AdminUser(UserMixin):
    def __init__(self, username):
        self.id = username

# Admin credentials (should be set via environment variables)
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'admin123')

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return AdminUser(user_id)

class WebAdminManager:
    """Web-based admin interface for API key management."""
    
    def __init__(self):
        """Initialize the web admin manager."""
        self.db = SessionLocal()
        
    def __del__(self):
        """Clean up database connection."""
        if hasattr(self, 'db'):
            self.db.close()
    
    def list_users(self) -> List[Dict]:
        """List all users in the system."""
        try:
            users = self.db.query(User).all()
            return [
                {
                    "id": user.id,
                    "email": user.email,
                    "tier": user.tier,
                    "is_active": user.is_active,
                    "monthly_requests": user.monthly_requests,
                    "monthly_limit": user.monthly_limit,
                    "created_at": user.created_at.isoformat()
                }
                for user in users
            ]
        except Exception as e:
            print(f"Error listing users: {e}")
            return []
    
    def list_api_keys(self, user_id: Optional[str] = None) -> List[Dict]:
        """List API keys, optionally filtered by user."""
        try:
            query = self.db.query(APIKey)
            if user_id:
                query = query.filter(APIKey.user_id == user_id)
            
            keys = query.all()
            return [
                {
                    "id": key.id,
                    "user_id": key.user_id,
                    "name": key.name,
                    "is_active": key.is_active,
                    "created_at": key.created_at.isoformat(),
                    "expires_at": key.expires_at.isoformat() if key.expires_at else None,
                    "last_used_at": key.last_used_at.isoformat() if key.last_used_at else None
                }
                for key in keys
            ]
        except Exception as e:
            print(f"Error listing API keys: {e}")
            return []
    
    def create_user(self, email: str, password: str, tier: str = "free") -> Optional[Dict]:
        """Create a new user."""
        try:
            # Check if user already exists
            existing_user = self.db.query(User).filter(User.email == email).first()
            if existing_user:
                return {"error": f"User with email {email} already exists"}
            
            # Create user
            user = AuthService.create_user(
                db=self.db,
                email=email,
                password=password,
                tier=tier
            )
            
            return {
                "id": user.id,
                "email": user.email,
                "tier": user.tier,
                "api_key": user.api_key,
                "created_at": user.created_at.isoformat()
            }
        except Exception as e:
            return {"error": f"Error creating user: {e}"}
    
    def generate_api_key(self, user_id: str, key_name: str, expires_in_days: int = 30) -> Optional[Dict]:
        """Generate a new API key for a user."""
        try:
            # Check if user exists
            user = self.db.query(User).filter(User.id == user_id).first()
            if not user:
                return {"error": f"User with ID {user_id} not found"}
            
            # Generate API key
            api_key = AuthService.generate_secure_api_key()
            expires_at = datetime.now() + timedelta(days=expires_in_days)
            
            # Store API key in database
            api_key_record = APIKey(
                user_id=user_id,
                key_hash=AuthService.hash_api_key(api_key),
                name=key_name,
                expires_at=expires_at,
                is_active=True
            )
            self.db.add(api_key_record)
            self.db.commit()
            
            return {
                "api_key": api_key,
                "key_name": key_name,
                "user_email": user.email,
                "expires_at": expires_at.isoformat(),
                "message": "API key generated successfully"
            }
        except Exception as e:
            return {"error": f"Error generating API key: {e}"}
    
    def revoke_api_key(self, key_id: int) -> Dict:
        """Revoke an API key."""
        try:
            key = self.db.query(APIKey).filter(APIKey.id == key_id).first()
            if not key:
                return {"error": f"API key with ID {key_id} not found"}
            
            key.is_active = False
            self.db.commit()
            return {"success": f"API key '{key.name}' revoked successfully"}
        except Exception as e:
            return {"error": f"Error revoking API key: {e}"}
    
    def update_user_tier(self, user_id: str, new_tier: str) -> Dict:
        """Update user tier."""
        try:
            user = self.db.query(User).filter(User.id == user_id).first()
            if not user:
                return {"error": f"User with ID {user_id} not found"}
            
            user.tier = new_tier
            self.db.commit()
            return {"success": f"User {user.email} tier updated to {new_tier}"}
        except Exception as e:
            return {"error": f"Error updating user tier: {e}"}

# Initialize admin manager
admin_manager = WebAdminManager()

# HTML Templates
LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Semio Admin Login</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { text-align: center; color: #333; }
        input[type=text], input[type=password] { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        button { width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #0056b3; }
        .error { color: red; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Semio Admin Login</h1>
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        <form method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
"""

DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Semio Admin Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .section { background: white; padding: 20px; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type=text], input[type=password], input[type=number], select { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        button { padding: 10px 20px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; margin-right: 10px; }
        button:hover { background: #0056b3; }
        .btn-danger { background: #dc3545; }
        .btn-danger:hover { background: #c82333; }
        .btn-success { background: #28a745; }
        .btn-success:hover { background: #218838; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f8f9fa; }
        .message { padding: 10px; margin: 10px 0; border-radius: 4px; }
        .success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .logout { float: right; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Semio Admin Dashboard</h1>
            <a href="/logout" class="logout">Logout</a>
        </div>

        {% if message %}
        <div class="message {{ message_type }}">{{ message }}</div>
        {% endif %}

        <div class="section">
            <h2>Create New User</h2>
            <form method="POST" action="/create_user">
                <div class="form-group">
                    <label>Email:</label>
                    <input type="text" name="email" required>
                </div>
                <div class="form-group">
                    <label>Password:</label>
                    <input type="password" name="password" required>
                </div>
                <div class="form-group">
                    <label>Tier:</label>
                    <select name="tier">
                        <option value="free">Free</option>
                        <option value="pro">Pro</option>
                        <option value="enterprise">Enterprise</option>
                    </select>
                </div>
                <button type="submit" class="btn-success">Create User</button>
            </form>
        </div>

        <div class="section">
            <h2>Generate API Key</h2>
            <form method="POST" action="/generate_key">
                <div class="form-group">
                    <label>User ID:</label>
                    <input type="text" name="user_id" required>
                </div>
                <div class="form-group">
                    <label>Key Name:</label>
                    <input type="text" name="key_name" placeholder="e.g., gitlab-pipeline" required>
                </div>
                <div class="form-group">
                    <label>Expires in days:</label>
                    <input type="number" name="expires_days" value="30" min="1" max="365">
                </div>
                <button type="submit" class="btn-success">Generate Key</button>
            </form>
        </div>

        <div class="section">
            <h2>Users</h2>
            <table>
                <tr>
                    <th>ID</th>
                    <th>Email</th>
                    <th>Tier</th>
                    <th>Active</th>
                    <th>Requests</th>
                    <th>Created</th>
                </tr>
                {% for user in users %}
                <tr>
                    <td>{{ user.id }}</td>
                    <td>{{ user.email }}</td>
                    <td>{{ user.tier }}</td>
                    <td>{{ user.is_active }}</td>
                    <td>{{ user.monthly_requests }}/{{ user.monthly_limit }}</td>
                    <td>{{ user.created_at[:10] }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>

        <div class="section">
            <h2>API Keys</h2>
            <table>
                <tr>
                    <th>ID</th>
                    <th>User ID</th>
                    <th>Name</th>
                    <th>Active</th>
                    <th>Created</th>
                    <th>Expires</th>
                    <th>Action</th>
                </tr>
                {% for key in keys %}
                <tr>
                    <td>{{ key.id }}</td>
                    <td>{{ key.user_id }}</td>
                    <td>{{ key.name }}</td>
                    <td>{{ key.is_active }}</td>
                    <td>{{ key.created_at[:10] }}</td>
                    <td>{{ key.expires_at[:10] if key.expires_at else 'Never' }}</td>
                    <td>
                        {% if key.is_active %}
                        <form method="POST" action="/revoke_key" style="display: inline;">
                            <input type="hidden" name="key_id" value="{{ key.id }}">
                            <button type="submit" class="btn-danger">Revoke</button>
                        </form>
                        {% endif %}
                    </td>
                </tr>
                {% endfor %}
            </table>
        </div>

        <div class="section">
            <h2>Demo API Key Information</h2>
            <p><strong>Demo API Key:</strong> demo-semio-api-key-2024-for-testing-only</p>
            <p><strong>Purpose:</strong> Testing and demo only</p>
            <p><strong>Access:</strong> Free tier</p>
            <p><strong>Expiration:</strong> Never expires</p>
            <p><strong>Location:</strong> Hardcoded in auth_service.py</p>
        </div>
    </div>
</body>
</html>
"""

@app.route('/')
@login_required
def dashboard():
    """Main admin dashboard."""
    users = admin_manager.list_users()
    keys = admin_manager.list_api_keys()
    return render_template_string(DASHBOARD_TEMPLATE, users=users, keys=keys)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Admin login."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            user = AdminUser(username)
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            return render_template_string(LOGIN_TEMPLATE, error="Invalid credentials")
    
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/logout')
@login_required
def logout():
    """Admin logout."""
    logout_user()
    return redirect(url_for('login'))

@app.route('/create_user', methods=['POST'])
@login_required
def create_user():
    """Create a new user."""
    email = request.form['email']
    password = request.form['password']
    tier = request.form['tier']
    
    if len(password) < 8:
        return redirect(url_for('dashboard', message="Password must be at least 8 characters", message_type="error"))
    
    result = admin_manager.create_user(email, password, tier)
    
    if 'error' in result:
        return redirect(url_for('dashboard', message=result['error'], message_type="error"))
    else:
        message = f"User created successfully! ID: {result['id']}, API Key: {result['api_key']}"
        return redirect(url_for('dashboard', message=message, message_type="success"))

@app.route('/generate_key', methods=['POST'])
@login_required
def generate_key():
    """Generate a new API key."""
    user_id = request.form['user_id']
    key_name = request.form['key_name']
    expires_days = int(request.form['expires_days'])
    
    result = admin_manager.generate_api_key(user_id, key_name, expires_days)
    
    if 'error' in result:
        return redirect(url_for('dashboard', message=result['error'], message_type="error"))
    else:
        message = f"API key generated: {result['api_key']}"
        return redirect(url_for('dashboard', message=message, message_type="success"))

@app.route('/revoke_key', methods=['POST'])
@login_required
def revoke_key():
    """Revoke an API key."""
    key_id = int(request.form['key_id'])
    result = admin_manager.revoke_api_key(key_id)
    
    if 'error' in result:
        return redirect(url_for('dashboard', message=result['error'], message_type="error"))
    else:
        return redirect(url_for('dashboard', message=result['success'], message_type="success"))

if __name__ == '__main__':
    # Initialize database
    try:
        init_db()
        print("✅ Database initialized successfully")
    except Exception as e:
        print(f"❌ Database initialization failed: {e}")
        sys.exit(1)
    
    # Get port from environment or use default
    port = int(os.getenv('ADMIN_PORT', 5001))
    host = os.getenv('ADMIN_HOST', '127.0.0.1')
    
    print(f"🚀 Starting Semio Web Admin Interface on {host}:{port}")
    print(f"📝 Login with username: {ADMIN_USERNAME}")
    print(f"🔐 Set ADMIN_USERNAME and ADMIN_PASSWORD environment variables for security")
    
    app.run(host=host, port=port, debug=False)
