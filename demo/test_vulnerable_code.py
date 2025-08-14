"""
Test file with intentional vulnerabilities for Semio demo.
This file contains security issues that Semgrep should detect.
"""

import hashlib
import sqlite3
import os
import subprocess
from flask import Flask, request

app = Flask(__name__)

# Vulnerability 1: Weak cryptographic algorithm
def weak_password_hash(password):
    """Vulnerable: Using MD5 for password hashing."""
    return hashlib.md5(password.encode()).hexdigest()

# Vulnerability 2: SQL injection
def get_user_by_id(user_input):
    """Vulnerable: Direct string concatenation in SQL query."""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = " + user_input  # SQL injection!
    cursor.execute(query)
    result = cursor.fetchone()
    conn.close()
    return result

# Vulnerability 3: Command injection
def execute_command(command_input):
    """Vulnerable: Direct command execution without sanitization."""
    result = subprocess.check_output(command_input, shell=True)  # Command injection!
    return result.decode()

# Vulnerability 4: Path traversal
def read_file(filename):
    """Vulnerable: No path validation."""
    with open(filename, 'r') as f:  # Path traversal possible!
        return f.read()

# Vulnerability 5: XSS in Flask (if this were a web app)
@app.route('/search')
def search():
    """Vulnerable: Direct user input in HTML."""
    query = request.args.get('q', '')
    return f"<h1>Search Results for: {query}</h1>"  # XSS!

# Vulnerability 6: Hardcoded credentials
DATABASE_PASSWORD = "admin123"  # Hardcoded password!
API_KEY = "sk-1234567890abcdef"  # Hardcoded API key!

# Vulnerability 7: Insecure random
import random
def generate_token():
    """Vulnerable: Using random instead of secrets."""
    return str(random.randint(1000, 9999))  # Predictable!

# Vulnerability 8: Debug mode in production
app.debug = True  # Debug mode enabled!

if __name__ == "__main__":
    # Test the vulnerable functions
    print("Testing vulnerable functions...")
    
    # Test weak password hash
    password = "mypassword123"
    hash_result = weak_password_hash(password)
    print(f"Password hash: {hash_result}")
    
    # Test SQL injection (don't actually run this!)
    # user = get_user_by_id("1; DROP TABLE users; --")
    
    # Test command injection (don't actually run this!)
    # result = execute_command("ls; rm -rf /")
    
    print("Demo vulnerabilities loaded!")
