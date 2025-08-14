import time
import asyncio
from typing import Dict, Optional
from fastapi import Request, HTTPException
from app.models.user import UserTier
from app.services.tier_service import TierService

class RateLimiter:
    """Rate limiter for tier-based request limits."""
    
    def __init__(self):
        self.request_counts: Dict[str, Dict] = {}
        self.lock = asyncio.Lock()
    
    async def check_rate_limit(self, user_id: str, tier: UserTier) -> bool:
        """Check if user has exceeded rate limits."""
        async with self.lock:
            current_time = time.time()
            current_month = int(current_time // (30 * 24 * 60 * 60))  # Monthly window
            
            if user_id not in self.request_counts:
                self.request_counts[user_id] = {
                    "monthly_count": 0,
                    "monthly_window": current_month,
                    "last_request": 0
                }
            
            user_data = self.request_counts[user_id]
            
            # Reset monthly count if new month
            if user_data["monthly_window"] != current_month:
                user_data["monthly_count"] = 0
                user_data["monthly_window"] = current_month
            
            # Check monthly limit
            if not TierService.check_monthly_limit(tier, user_data["monthly_count"]):
                return False
            
            # Check concurrent requests
            concurrent_limit = TierService.get_concurrent_requests(tier)
            time_window = 60  # 1 minute window for concurrent requests
            
            if current_time - user_data["last_request"] < time_window:
                # Count concurrent requests in the time window
                concurrent_count = 1  # Current request
                # This is a simplified implementation - in production you'd use Redis
                
                if concurrent_count > concurrent_limit:
                    return False
            
            # Update counters
            user_data["monthly_count"] += 1
            user_data["last_request"] = current_time
            
            return True
    
    async def increment_usage(self, user_id: str):
        """Increment usage counter for a user."""
        async with self.lock:
            if user_id in self.request_counts:
                self.request_counts[user_id]["monthly_count"] += 1

# Global rate limiter instance
rate_limiter = RateLimiter()

async def check_user_rate_limit(request: Request, user_id: str, tier: UserTier):
    """Middleware function to check rate limits."""
    if not await rate_limiter.check_rate_limit(user_id, tier):
        limit = TierService.get_tier_config(tier)["monthly_limit"]
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Monthly limit: {limit} requests"
        )
