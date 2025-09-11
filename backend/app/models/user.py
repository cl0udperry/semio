from enum import Enum
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, ConfigDict

class UserTier(str, Enum):
    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"

class User(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: str
    email: str = Field(..., description="User email address")
    tier: UserTier = UserTier.FREE
    api_key: Optional[str] = None
    monthly_requests: int = 0
    monthly_limit: int = 100  # Free tier limit
    created_at: datetime
    updated_at: datetime
    is_active: bool = True

class UserCreate(BaseModel):
    email: str = Field(..., description="User email address")
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
