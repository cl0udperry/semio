"""
Authentication routes for user management.
Includes registration, login, and API key management endpoints.
"""

from datetime import timedelta
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr

from app.database import get_db
from app.services.auth_service import AuthService, get_current_user
from app.models.database_models import User
from app.models.user import UserTier

router = APIRouter()

# Request/Response models
class UserRegister(BaseModel):
    email: EmailStr
    password: str
    tier: Optional[UserTier] = UserTier.FREE

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    expires_in: int

class UserResponse(BaseModel):
    id: str
    email: str
    tier: UserTier
    api_key: Optional[str]
    monthly_requests: int
    monthly_limit: int
    is_active: bool
    created_at: str
    
    class Config:
        from_attributes = True

class APIKeyResponse(BaseModel):
    api_key: str
    message: str

class UsageResponse(BaseModel):
    monthly_requests: int
    monthly_limit: int
    tier: UserTier
    remaining_requests: int


@router.post("/register", response_model=UserResponse)
async def register_user(
    user_data: UserRegister,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Register a new user.
    
    - **email**: User's email address
    - **password**: User's password (min 8 characters)
    - **tier**: User tier (default: FREE)
    """
    # Validate password length
    if len(user_data.password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters long"
        )
    
    # Create user
    user = AuthService.create_user(
        db=db,
        email=user_data.email,
        password=user_data.password,
        tier=user_data.tier
    )
    
    # Log registration attempt
    AuthService.log_audit_event(
        db, user.id, "user_registered", 
        {"ip_address": request.client.host, "user_agent": request.headers.get("user-agent")}
    )
    
    return UserResponse(
        id=user.id,
        email=user.email,
        tier=user.tier,
        api_key=user.api_key,
        monthly_requests=user.monthly_requests,
        monthly_limit=user.monthly_limit,
        is_active=user.is_active,
        created_at=user.created_at.isoformat()
    )


@router.post("/login", response_model=Token)
async def login_user(
    user_data: UserLogin,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Login user and return JWT token.
    
    - **email**: User's email address
    - **password**: User's password
    """
    # Authenticate user
    user = AuthService.authenticate_user(db, user_data.email, user_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Account is deactivated"
        )
    
    # Create access token
    access_token_expires = timedelta(minutes=30)
    access_token = AuthService.create_access_token(
        data={"sub": user.id}, expires_delta=access_token_expires
    )
    
    # Log login attempt
    AuthService.log_audit_event(
        db, user.id, "user_login", 
        {"ip_address": request.client.host, "user_agent": request.headers.get("user-agent")}
    )
    
    return Token(
        access_token=access_token,
        token_type="bearer",
        expires_in=30 * 60  # 30 minutes in seconds
    )


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get current user information.
    Requires authentication via JWT token.
    """
    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        tier=current_user.tier,
        api_key=current_user.api_key,
        monthly_requests=current_user.monthly_requests,
        monthly_limit=current_user.monthly_limit,
        is_active=current_user.is_active,
        created_at=current_user.created_at.isoformat()
    )


@router.get("/usage", response_model=UsageResponse)
async def get_usage_info(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get current user's usage information.
    Requires authentication via JWT token.
    """
    remaining_requests = max(0, current_user.monthly_limit - current_user.monthly_requests)
    
    return UsageResponse(
        monthly_requests=current_user.monthly_requests,
        monthly_limit=current_user.monthly_limit,
        tier=current_user.tier,
        remaining_requests=remaining_requests
    )


@router.post("/regenerate-api-key", response_model=APIKeyResponse)
async def regenerate_api_key(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Regenerate user's API key.
    Requires authentication via JWT token.
    """
    new_api_key = AuthService.regenerate_api_key(db, current_user.id)
    
    return APIKeyResponse(
        api_key=new_api_key,
        message="API key regenerated successfully"
    )


@router.post("/upgrade-tier")
async def upgrade_tier(
    new_tier: UserTier,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Upgrade user tier.
    Requires authentication via JWT token.
    """
    # Validate tier upgrade
    current_tier_value = {"FREE": 0, "PRO": 1, "ENTERPRISE": 2}[current_user.tier]
    new_tier_value = {"FREE": 0, "PRO": 1, "ENTERPRISE": 2}[new_tier]
    
    if new_tier_value <= current_tier_value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Can only upgrade to a higher tier"
        )
    
    # Update tier
    updated_user = AuthService.update_user_tier(db, current_user.id, new_tier)
    
    return {
        "message": f"Tier upgraded to {new_tier}",
        "new_tier": new_tier,
        "new_monthly_limit": updated_user.monthly_limit
    }


@router.get("/api-key-info")
async def get_api_key_info(
    api_key: str,
    db: Session = Depends(get_db)
):
    """
    Get information about an API key.
    Used for API key validation.
    """
    user = AuthService.get_user_by_api_key(db, api_key)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key"
        )
    
    return {
        "user_id": user.id,
        "email": user.email,
        "tier": user.tier,
        "is_active": user.is_active,
        "monthly_requests": user.monthly_requests,
        "monthly_limit": user.monthly_limit
    }
