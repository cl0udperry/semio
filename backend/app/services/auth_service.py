"""
Authentication service with security best practices.
Includes password hashing, JWT token management, and API key generation.
"""

import os
import uuid
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional, Union
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from jose import JWTError, jwt
from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app.models.database_models import User, APIKey, AuditLog
from app.models.user import UserTier
from app.services.tier_service import TierService
from app.database import get_db

# Security configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
API_KEY_LENGTH = 32

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT token security
security = HTTPBearer()


class AuthService:
    """Authentication service with comprehensive security features."""
    
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash."""
        return pwd_context.verify(plain_password, hashed_password)
    
    @staticmethod
    def get_password_hash(password: str) -> str:
        """Hash a password using bcrypt."""
        return pwd_context.hash(password)
    
    @staticmethod
    def generate_api_key() -> str:
        """Generate a secure API key."""
        return secrets.token_urlsafe(API_KEY_LENGTH)
    
    @staticmethod
    def generate_secure_api_key() -> str:
        """Generate a secure API key for CLI access."""
        # Generate 32 bytes of random data and encode as hex
        return secrets.token_hex(32)
    
    @staticmethod
    def hash_api_key(api_key: str) -> str:
        """Hash an API key for secure storage."""
        return hashlib.sha256(api_key.encode()).hexdigest()
    
    @staticmethod
    def validate_api_key(api_key: str) -> Optional[dict]:
        """Validate an API key and return user info if valid."""
        try:
            # Demo API key for testing purposes (only for development/demo)
            DEMO_API_KEY = "demo-semio-api-key-2024-for-testing-only"
            if api_key == DEMO_API_KEY:
                return {
                    "user_id": "demo-user-id",
                    "email": "demo@semio.com",
                    "tier": "free",
                    "key_name": "demo-key",
                    "expires_at": None  # Demo key doesn't expire
                }
            
            from app.database import SessionLocal
            from app.models.database_models import APIKey, User
            
            # Hash the provided API key
            key_hash = AuthService.hash_api_key(api_key)
            
            # Create a new database session
            db = SessionLocal()
            
            # Check if key exists and is valid
            api_key_record = db.query(APIKey).filter(
                APIKey.key_hash == key_hash,
                APIKey.is_active == True,
                APIKey.expires_at > datetime.now()
            ).first()
            
            if api_key_record:
                user = db.query(User).filter(User.id == api_key_record.user_id).first()
                if user:
                    return {
                        "user_id": user.id,
                        "email": user.email,
                        "tier": user.tier,
                        "key_name": api_key_record.name,
                        "expires_at": api_key_record.expires_at
                    }
            
            return None
            
        except Exception as e:
            print(f"Error validating API key: {e}")
            return None
        finally:
            if 'db' in locals():
                db.close()
    
    @staticmethod
    def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
        """Create a JWT access token."""
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt
    
    @staticmethod
    def verify_token(token: str) -> dict:
        """Verify and decode a JWT token."""
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            return payload
        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
    
    @staticmethod
    def create_user(
        db: Session, 
        email: str, 
        password: str, 
        tier: UserTier = UserTier.FREE
    ) -> User:
        """Create a new user with proper validation."""
        # Check if user already exists
        existing_user = db.query(User).filter(User.email == email).first()
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )
        
        # Create user
        user_id = str(uuid.uuid4())
        hashed_password = AuthService.get_password_hash(password)
        api_key = AuthService.generate_api_key()
        
        user = User(
            id=user_id,
            email=email,
            hashed_password=hashed_password,
            tier=tier,
            api_key=api_key,
            monthly_limit=TierService.get_tier_config(tier)["monthly_limit"]
        )
        
        db.add(user)
        db.commit()
        db.refresh(user)
        
        # Log the event
        AuthService.log_audit_event(
            db, user_id, "user_created", 
            {"email": email, "tier": tier}
        )
        
        return user
    
    @staticmethod
    def authenticate_user(db: Session, email: str, password: str) -> Optional[User]:
        """Authenticate a user with email and password."""
        user = db.query(User).filter(User.email == email).first()
        if not user:
            return None
        if not AuthService.verify_password(password, user.hashed_password):
            return None
        
        # Update last login
        user.last_login_at = datetime.now(timezone.utc)
        db.commit()
        
        # Log the event
        AuthService.log_audit_event(db, user.id, "user_login", {"email": email})
        
        return user
    
    @staticmethod
    def get_user_by_api_key(db: Session, api_key: str) -> Optional[User]:
        """Get user by API key."""
        return db.query(User).filter(
            User.api_key == api_key,
            User.is_active == True
        ).first()
    
    @staticmethod
    def get_user_by_email(db: Session, email: str) -> Optional[User]:
        """Get user by email."""
        return db.query(User).filter(User.email == email).first()
    
    @staticmethod
    def get_user_by_id(db: Session, user_id: str) -> Optional[User]:
        """Get user by ID."""
        return db.query(User).filter(User.id == user_id).first()
    
    @staticmethod
    def update_user_tier(db: Session, user_id: str, new_tier: UserTier) -> User:
        """Update user tier and reset monthly limit."""
        user = AuthService.get_user_by_id(db, user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        old_tier = user.tier
        user.tier = new_tier
        user.monthly_limit = TierService.get_tier_config(new_tier)["monthly_limit"]
        user.monthly_requests = 0  # Reset usage for new tier
        
        db.commit()
        db.refresh(user)
        
        # Log the event
        AuthService.log_audit_event(
            db, user_id, "tier_upgraded", 
            {"old_tier": old_tier, "new_tier": new_tier}
        )
        
        return user
    
    @staticmethod
    def regenerate_api_key(db: Session, user_id: str) -> str:
        """Regenerate user's API key."""
        user = AuthService.get_user_by_id(db, user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        old_api_key = user.api_key
        new_api_key = AuthService.generate_api_key()
        user.api_key = new_api_key
        
        db.commit()
        
        # Log the event
        AuthService.log_audit_event(
            db, user_id, "api_key_regenerated", 
            {"old_api_key": old_api_key[:8] + "..." if old_api_key else None}
        )
        
        return new_api_key
    
    @staticmethod
    def increment_usage(db: Session, user_id: str) -> bool:
        """Increment user's monthly usage and check limits."""
        user = AuthService.get_user_by_id(db, user_id)
        if not user:
            return False
        
        # Check if user has exceeded monthly limit
        if user.monthly_requests >= user.monthly_limit:
            return False
        
        user.monthly_requests += 1
        db.commit()
        return True
    
    @staticmethod
    def reset_monthly_usage(db: Session) -> int:
        """Reset monthly usage for all users. Returns number of users processed."""
        users = db.query(User).filter(User.is_active == True).all()
        processed_count = 0
        
        for user in users:
            user.monthly_requests = 0
            processed_count += 1
        
        db.commit()
        
        # Log the event
        AuthService.log_audit_event(
            db, None, "monthly_usage_reset", 
            {"users_processed": processed_count}
        )
        
        return processed_count
    
    @staticmethod
    def log_audit_event(
        db: Session, 
        user_id: Optional[str], 
        event_type: str, 
        event_data: dict
    ) -> None:
        """Log an audit event."""
        audit_log = AuditLog(
            user_id=user_id,
            event_type=event_type,
            event_data=str(event_data)  # Convert dict to string for storage
        )
        db.add(audit_log)
        db.commit()


# Dependency functions for FastAPI
def get_current_user(
    token: str,
    db: Session = Depends(get_db)
) -> User:
    """Get current user from JWT token."""
    payload = AuthService.verify_token(token)
    user_id = payload.get("sub")
    
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )
    
    user = AuthService.get_user_by_id(db, user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    
    return user


def get_current_user_by_api_key(
    api_key: str,
    db: Session = Depends(get_db)
) -> User:
    """Get current user from API key."""
    user = AuthService.get_user_by_api_key(db, api_key)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key"
        )
    
    return user


# Database dependency is imported from app.database
