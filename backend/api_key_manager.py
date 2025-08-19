#!/usr/bin/env python3
"""
API Key Manager for Semio CLI Access
"""

import os
import sys
import requests
from typing import Optional

# Configuration
DEFAULT_API_URL = "http://localhost:8000"
API_URL = os.getenv("SEMIO_API_URL", DEFAULT_API_URL)

def print_banner():
    """Print CLI banner."""
    print("🔑 Semio API Key Manager")
    print("=" * 40)

def generate_api_key(email: str, password: str, key_name: str, expires_days: int = 30) -> Optional[str]:
    """Generate a new API key."""
    try:
        data = {
            "email": email,
            "password": password,
            "key_name": key_name,
            "expires_in_days": expires_days
        }
        
        response = requests.post(f"{API_URL}/auth/generate-api-key", data=data, timeout=10)
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ API key generated successfully!")
            print(f"   Key Name: {result['key_name']}")
            print(f"   Expires: {result['expires_at']}")
            print(f"   API Key: {result['api_key']}")
            print(f"\n🔐 Store this API key securely in your GitLab CI/CD variables!")
            return result['api_key']
        else:
            print(f"❌ Failed to generate API key: {response.status_code}")
            print(f"   Response: {response.text}")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Request failed: {e}")
        return None

def list_api_keys(email: str, password: str):
    """List all API keys for a user."""
    try:
        params = {
            "email": email,
            "password": password
        }
        
        response = requests.get(f"{API_URL}/auth/list-api-keys", params=params, timeout=10)
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Found {len(result['api_keys'])} API keys:")
            print()
            
            for key in result['api_keys']:
                print(f"   📋 {key['key_name']}")
                print(f"      Created: {key['created_at']}")
                print(f"      Expires: {key['expires_at']}")
                print(f"      Active: {'✅' if key['is_active'] else '❌'}")
                print()
        else:
            print(f"❌ Failed to list API keys: {response.status_code}")
            print(f"   Response: {response.text}")
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Request failed: {e}")

def revoke_api_key(email: str, password: str, key_name: str):
    """Revoke an API key."""
    try:
        data = {
            "email": email,
            "password": password,
            "key_name": key_name
        }
        
        response = requests.delete(f"{API_URL}/auth/revoke-api-key", data=data, timeout=10)
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ {result['message']}")
        else:
            print(f"❌ Failed to revoke API key: {response.status_code}")
            print(f"   Response: {response.text}")
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Request failed: {e}")

def main():
    """Main function."""
    print_banner()
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python api_key_manager.py generate <email> <password> <key_name> [expires_days]")
        print("  python api_key_manager.py list <email> <password>")
        print("  python api_key_manager.py revoke <email> <password> <key_name>")
        print()
        print("Examples:")
        print("  python api_key_manager.py generate user@example.com password123 gitlab-pipeline 90")
        print("  python api_key_manager.py list user@example.com password123")
        print("  python api_key_manager.py revoke user@example.com password123 gitlab-pipeline")
        sys.exit(1)
    
    command = sys.argv[1].lower()
    
    if command == "generate":
        if len(sys.argv) < 5:
            print("❌ Missing arguments for generate command")
            sys.exit(1)
        
        email = sys.argv[2]
        password = sys.argv[3]
        key_name = sys.argv[4]
        expires_days = int(sys.argv[5]) if len(sys.argv) > 5 else 30
        
        print(f"🔑 Generating API key '{key_name}' for {email}...")
        generate_api_key(email, password, key_name, expires_days)
        
    elif command == "list":
        if len(sys.argv) < 4:
            print("❌ Missing arguments for list command")
            sys.exit(1)
        
        email = sys.argv[2]
        password = sys.argv[3]
        
        print(f"📋 Listing API keys for {email}...")
        list_api_keys(email, password)
        
    elif command == "revoke":
        if len(sys.argv) < 5:
            print("❌ Missing arguments for revoke command")
            sys.exit(1)
        
        email = sys.argv[2]
        password = sys.argv[3]
        key_name = sys.argv[4]
        
        print(f"🗑️  Revoking API key '{key_name}' for {email}...")
        revoke_api_key(email, password, key_name)
        
    else:
        print(f"❌ Unknown command: {command}")
        sys.exit(1)

if __name__ == "__main__":
    main()
