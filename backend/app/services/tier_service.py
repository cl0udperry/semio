from typing import Dict, Any
from app.models.user import UserTier

class TierService:
    """Service to manage tier-specific features and limits."""
    
    # Tier configurations
    TIER_CONFIGS = {
        UserTier.FREE: {
            "monthly_limit": 100,
            "shared_llm": True,
            "custom_prompts": False,
            "data_isolation": False,
            "audit_logs": False,
            "priority_queue": False,
            "max_file_size_mb": 10,
            "concurrent_requests": 1
        },
        UserTier.PRO: {
            "monthly_limit": 1000,
            "shared_llm": True,
            "custom_prompts": True,
            "data_isolation": False,
            "audit_logs": False,
            "priority_queue": True,
            "max_file_size_mb": 50,
            "concurrent_requests": 3
        },
        UserTier.ENTERPRISE: {
            "monthly_limit": -1,  # Unlimited
            "shared_llm": False,
            "custom_prompts": True,
            "data_isolation": True,
            "audit_logs": True,
            "priority_queue": True,
            "max_file_size_mb": 100,
            "concurrent_requests": 10
        }
    }
    
    @classmethod
    def get_tier_config(cls, tier: UserTier) -> Dict[str, Any]:
        """Get configuration for a specific tier."""
        return cls.TIER_CONFIGS.get(tier, cls.TIER_CONFIGS[UserTier.FREE])
    
    @classmethod
    def check_monthly_limit(cls, tier: UserTier, current_usage: int) -> bool:
        """Check if user has exceeded monthly limit."""
        config = cls.get_tier_config(tier)
        limit = config["monthly_limit"]
        return limit == -1 or current_usage < limit
    
    @classmethod
    def get_llm_config(cls, tier: UserTier, user_api_key: str = None) -> Dict[str, Any]:
        """Get LLM configuration based on tier."""
        config = cls.get_tier_config(tier)
        
        if tier == UserTier.ENTERPRISE and user_api_key:
            # Enterprise users can use their own LLM
            return {
                "use_shared": False,
                "api_key": user_api_key,
                "base_url": None,  # User provides their own
                "model": "user-defined"
            }
        else:
            # Free and Pro users use shared LLM
            return {
                "use_shared": True,
                "api_key": None,  # Will use shared API key
                "base_url": "https://generativelanguage.googleapis.com/v1beta/openai/",
                "model": "gemini-2.0-flash"
            }
    
    @classmethod
    def can_use_custom_prompts(cls, tier: UserTier) -> bool:
        """Check if tier allows custom prompt injection."""
        config = cls.get_tier_config(tier)
        return config["custom_prompts"]
    
    @classmethod
    def get_max_file_size(cls, tier: UserTier) -> int:
        """Get maximum file size in MB for tier."""
        config = cls.get_tier_config(tier)
        return config["max_file_size_mb"]
    
    @classmethod
    def get_concurrent_requests(cls, tier: UserTier) -> int:
        """Get maximum concurrent requests for tier."""
        config = cls.get_tier_config(tier)
        return config["concurrent_requests"]
    
    @classmethod
    def has_priority_queue(cls, tier: UserTier) -> bool:
        """Check if tier has priority queue access."""
        config = cls.get_tier_config(tier)
        return config["priority_queue"]
    
    @classmethod
    def can_use_agentic_ai(cls, tier: UserTier) -> bool:
        """Check if tier allows access to agentic AI features."""
        # Pro and Enterprise tiers can use agentic AI
        return tier in [UserTier.PRO, UserTier.ENTERPRISE]
