#!/usr/bin/env python3
"""
Semio Admin API Key Manager
A secure admin interface for managing API keys.
This should only be accessible to administrators with direct server access.
"""

import os
import sys
import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Optional, List, Dict
import json

# Add the backend directory to the path so we can import app modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.database import SessionLocal, init_db
from app.models.database_models import User, APIKey
from app.services.auth_service import AuthService

class AdminKeyManager:
    """Secure admin interface for API key management."""
    
    def __init__(self):
        """Initialize the admin key manager."""
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
                print(f"User with email {email} already exists")
                return None
            
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
            print(f"Error creating user: {e}")
            return None
    
    def generate_api_key(self, user_id: str, key_name: str, expires_in_days: int = 30) -> Optional[Dict]:
        """Generate a new API key for a user."""
        try:
            # Check if user exists
            user = self.db.query(User).filter(User.id == user_id).first()
            if not user:
                print(f"User with ID {user_id} not found")
                return None
            
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
            print(f"Error generating API key: {e}")
            return None
    
    def revoke_api_key(self, key_id: int) -> bool:
        """Revoke an API key."""
        try:
            key = self.db.query(APIKey).filter(APIKey.id == key_id).first()
            if not key:
                print(f"API key with ID {key_id} not found")
                return False
            
            key.is_active = False
            self.db.commit()
            print(f"API key '{key.name}' revoked successfully")
            return True
        except Exception as e:
            print(f"Error revoking API key: {e}")
            return False
    
    def update_user_tier(self, user_id: str, new_tier: str) -> bool:
        """Update user tier."""
        try:
            user = self.db.query(User).filter(User.id == user_id).first()
            if not user:
                print(f"User with ID {user_id} not found")
                return False
            
            user.tier = new_tier
            self.db.commit()
            print(f"User {user.email} tier updated to {new_tier}")
            return True
        except Exception as e:
            print(f"Error updating user tier: {e}")
            return False

def print_banner():
    """Print admin interface banner."""
    print("=" * 60)
    print("Semio Admin API Key Manager")
    print("=" * 60)
    print("⚠️  WARNING: This is an admin-only interface!")
    print("   Only use this if you have direct server access.")
    print("=" * 60)

def print_menu():
    """Print the main menu."""
    print("\nAvailable Commands:")
    print("1.  List all users")
    print("2.  List all API keys")
    print("3.  List API keys for specific user")
    print("4.  Create new user")
    print("5.  Generate API key for user")
    print("6.  Revoke API key")
    print("7.  Update user tier")
    print("8.  Show demo API key info")
    print("9.  Exit")
    print()

def main():
    """Main admin interface."""
    print_banner()
    
    # Initialize database
    try:
        init_db()
        print("✅ Database initialized successfully")
    except Exception as e:
        print(f"❌ Database initialization failed: {e}")
        return
    
    manager = AdminKeyManager()
    
    while True:
        print_menu()
        choice = input("Enter your choice (1-9): ").strip()
        
        if choice == "1":
            print("\n--- All Users ---")
            users = manager.list_users()
            if users:
                for user in users:
                    print(f"ID: {user['id']}")
                    print(f"Email: {user['email']}")
                    print(f"Tier: {user['tier']}")
                    print(f"Active: {user['is_active']}")
                    print(f"Requests: {user['monthly_requests']}/{user['monthly_limit']}")
                    print(f"Created: {user['created_at']}")
                    print("-" * 40)
            else:
                print("No users found")
        
        elif choice == "2":
            print("\n--- All API Keys ---")
            keys = manager.list_api_keys()
            if keys:
                for key in keys:
                    print(f"ID: {key['id']}")
                    print(f"User ID: {key['user_id']}")
                    print(f"Name: {key['name']}")
                    print(f"Active: {key['is_active']}")
                    print(f"Created: {key['created_at']}")
                    print(f"Expires: {key['expires_at'] or 'Never'}")
                    print("-" * 40)
            else:
                print("No API keys found")
        
        elif choice == "3":
            user_id = input("Enter user ID: ").strip()
            print(f"\n--- API Keys for User {user_id} ---")
            keys = manager.list_api_keys(user_id)
            if keys:
                for key in keys:
                    print(f"ID: {key['id']}")
                    print(f"Name: {key['name']}")
                    print(f"Active: {key['is_active']}")
                    print(f"Created: {key['created_at']}")
                    print(f"Expires: {key['expires_at'] or 'Never'}")
                    print("-" * 40)
            else:
                print("No API keys found for this user")
        
        elif choice == "4":
            print("\n--- Create New User ---")
            email = input("Email: ").strip()
            password = input("Password (min 8 chars): ").strip()
            tier = input("Tier (free/pro/enterprise) [free]: ").strip() or "free"
            
            if len(password) < 8:
                print("❌ Password must be at least 8 characters")
                continue
            
            result = manager.create_user(email, password, tier)
            if result:
                print("✅ User created successfully!")
                print(f"   ID: {result['id']}")
                print(f"   Email: {result['email']}")
                print(f"   Tier: {result['tier']}")
                print(f"   API Key: {result['api_key']}")
            else:
                print("❌ Failed to create user")
        
        elif choice == "5":
            print("\n--- Generate API Key ---")
            user_id = input("User ID: ").strip()
            key_name = input("Key name (e.g., 'gitlab-pipeline'): ").strip()
            expires_days = input("Expires in days [30]: ").strip() or "30"
            
            try:
                expires_days = int(expires_days)
            except ValueError:
                print("❌ Invalid number of days")
                continue
            
            result = manager.generate_api_key(user_id, key_name, expires_days)
            if result:
                print("✅ API key generated successfully!")
                print(f"   API Key: {result['api_key']}")
                print(f"   Name: {result['key_name']}")
                print(f"   User: {result['user_email']}")
                print(f"   Expires: {result['expires_at']}")
                print("\n🔐 Store this API key securely!")
            else:
                print("❌ Failed to generate API key")
        
        elif choice == "6":
            print("\n--- Revoke API Key ---")
            key_id = input("API Key ID: ").strip()
            
            try:
                key_id = int(key_id)
            except ValueError:
                print("❌ Invalid key ID")
                continue
            
            if manager.revoke_api_key(key_id):
                print("✅ API key revoked successfully")
            else:
                print("❌ Failed to revoke API key")
        
        elif choice == "7":
            print("\n--- Update User Tier ---")
            user_id = input("User ID: ").strip()
            new_tier = input("New tier (free/pro/enterprise): ").strip()
            
            if new_tier not in ["free", "pro", "enterprise"]:
                print("❌ Invalid tier. Must be free, pro, or enterprise")
                continue
            
            if manager.update_user_tier(user_id, new_tier):
                print("✅ User tier updated successfully")
            else:
                print("❌ Failed to update user tier")
        
        elif choice == "8":
            print("\n--- Demo API Key Information ---")
            print("Demo API Key: demo-semio-api-key-2024-for-testing-only")
            print("Purpose: Testing and demo only")
            print("Access: Free tier")
            print("Expiration: Never expires")
            print("Location: Hardcoded in auth_service.py")
            print("\n⚠️  This key should only be used for testing!")
        
        elif choice == "9":
            print("\n👋 Goodbye!")
            break
        
        else:
            print("❌ Invalid choice. Please enter 1-9.")

if __name__ == "__main__":
    main()
