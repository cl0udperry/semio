from enum import Enum
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr

class UserTier(str, Enum):
    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"

class User(BaseModel):
    id: str
    email: EmailStr
    tier: UserTier = UserTier.FREE
    api_key: Optional[str] = None
    monthly_requests: int = 0
    monthly_limit: int = 100  # Free tier limit
    created_at: datetime
    updated_at: datetime
    is_active: bool = True
    
    class Config:
        from_attributes = True

class UserCreate(BaseModel):
    email: EmailStr
    password: str

class UserUpdate(BaseModel):
    tier: Optional[UserTier] = None
    api_key: Optional[str] = None
    is_active: Optional[bool] = None

class UsageStats(BaseModel):
    user_id: str
    monthly_requests: int
    monthly_limit: int
    tier: UserTier
    reset_date: datetime
