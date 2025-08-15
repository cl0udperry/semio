"""
Flask application with intentional security vulnerabilities for Semio demo.
This demonstrates a realistic application with security issues.
"""

from flask import Flask, request, render_template_string, jsonify
import sqlite3
import hashlib
import subprocess
import os
import random
from datetime import datetime

app = Flask(__name__)

# Global variables (vulnerable)
SECRET_KEY = "super-secret-key-123"  # Hardcoded secret
DEBUG_MODE = True  # Debug mode in production
DATABASE_PATH = "users.db"

# In-memory storage (vulnerable)
users = {}

@app.route('/')
def index():
    """Home page with XSS vulnerability."""
    user_input = request.args.get('name', '')
    template = f"""
    <!DOCTYPE html>
    <html>
    <head><title>Vulnerable App</title></head>
    <body>
        <h1>Welcome {user_input}!</h1>
        <p>This is a demo application with security vulnerabilities.</p>
        <form action="/login" method="POST">
            <input type="text" name="username" placeholder="Username">
            <input type="password" name="password" placeholder="Password">
            <button type="submit">Login</button>
        </form>
    </body>
    </html>
    """
    return render_template_string(template)

@app.route('/login', methods=['POST'])
def login():
    """Login endpoint with multiple vulnerabilities."""
    username = request.form.get('username')
    password = request.form.get('password')
    
    # Vulnerability: Weak password hashing
    password_hash = hashlib.md5(password.encode()).hexdigest()
    
    # Vulnerability: SQL injection
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password_hash}'"
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return jsonify({"status": "success", "message": "Login successful"})
    else:
        return jsonify({"status": "error", "message": "Invalid credentials"})

@app.route('/search')
def search():
    """Search endpoint with command injection vulnerability."""
    query = request.args.get('q', '')
    
    # Vulnerability: Command injection
    if query:
        try:
            result = subprocess.check_output(f"grep -r '{query}' /tmp", shell=True)
            return jsonify({"results": result.decode()})
        except:
            return jsonify({"results": "No results found"})
    
    return jsonify({"results": "Please provide a search query"})

@app.route('/file')
def read_file():
    """File reading endpoint with path traversal vulnerability."""
    filename = request.args.get('file', '')
    
    # Vulnerability: Path traversal
    try:
        with open(filename, 'r') as f:
            content = f.read()
        return jsonify({"content": content})
    except:
        return jsonify({"error": "File not found"})

@app.route('/api/token')
def generate_token():
    """Token generation with insecure random."""
    # Vulnerability: Insecure random
    token = str(random.randint(100000, 999999))
    return jsonify({"token": token})

@app.route('/config')
def get_config():
    """Configuration endpoint exposing sensitive data."""
    # Vulnerability: Information disclosure
    config = {
        "database_url": "sqlite:///users.db",
        "secret_key": SECRET_KEY,
        "debug_mode": DEBUG_MODE,
        "api_key": "sk-1234567890abcdef",
        "admin_password": "admin123"
    }
    return jsonify(config)

@app.route('/health')
def health_check():
    """Health check endpoint."""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0"
    })

if __name__ == '__main__':
    # Vulnerability: Debug mode in production
    app.run(debug=True, host='0.0.0.0', port=5000)
