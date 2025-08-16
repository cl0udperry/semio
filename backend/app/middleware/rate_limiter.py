"""
Rate limiting middleware for public endpoints.
Implements strict rate limiting for demo/trial usage.
"""

import time
import hashlib
from typing import Dict, Tuple
from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
import os

# In-memory storage for rate limiting (use Redis in production)
rate_limit_store: Dict[str, Tuple[int, float]] = {}

class RateLimiter:
    def __init__(self):
        # Rate limit settings for public endpoint
        self.max_requests = int(os.getenv("PUBLIC_RATE_LIMIT", "5"))  # 5 requests per hour
        self.window_seconds = int(os.getenv("RATE_LIMIT_WINDOW", "3600"))  # 1 hour
        
        # Rate limit settings for authenticated endpoints
        self.auth_max_requests = int(os.getenv("AUTH_RATE_LIMIT", "100"))  # 100 requests per hour
        self.auth_window_seconds = int(os.getenv("AUTH_RATE_LIMIT_WINDOW", "3600"))  # 1 hour
    
    def get_client_identifier(self, request: Request) -> str:
        """Get unique identifier for rate limiting."""
        # Use IP address for public endpoints
        client_ip = request.client.host if request.client else "unknown"
        
        # For additional security, include user agent hash
        user_agent = request.headers.get("user-agent", "")
        user_agent_hash = hashlib.md5(user_agent.encode()).hexdigest()[:8]
        
        return f"{client_ip}_{user_agent_hash}"
    
    def is_ui_request(self, request: Request) -> bool:
        """Check if request is coming from the Gradio UI."""
        # Check for Gradio-specific headers
        referer = request.headers.get("referer", "")
        origin = request.headers.get("origin", "")
        user_agent = request.headers.get("user-agent", "")
        
        # Gradio sends specific headers
        is_gradio = (
            "gradio" in user_agent.lower() or
            "localhost:7860" in referer or
            "localhost:7860" in origin or
            request.headers.get("x-gradio-version") is not None
        )
        
        # Additional check for our custom header
        has_ui_header = request.headers.get("x-semio-ui") == "gradio-dashboard"
        
        return is_gradio or has_ui_header
    
    def check_rate_limit(self, request: Request, is_authenticated: bool = False) -> bool:
        """Check if request is within rate limits."""
        client_id = self.get_client_identifier(request)
        current_time = time.time()
        
        # Choose rate limit settings based on authentication
        if is_authenticated:
            max_requests = self.auth_max_requests
            window_seconds = self.auth_window_seconds
        else:
            max_requests = self.max_requests
            window_seconds = self.window_seconds
        
        # Get current usage
        if client_id in rate_limit_store:
            request_count, window_start = rate_limit_store[client_id]
            
            # Check if window has expired
            if current_time - window_start > window_seconds:
                # Reset window
                rate_limit_store[client_id] = (1, current_time)
                return True
            else:
                # Check if limit exceeded
                if request_count >= max_requests:
                    return False
                else:
                    # Increment count
                    rate_limit_store[client_id] = (request_count + 1, window_start)
                    return True
        else:
            # First request for this client
            rate_limit_store[client_id] = (1, current_time)
            return True
    
    def get_remaining_requests(self, request: Request, is_authenticated: bool = False) -> int:
        """Get remaining requests for the current window."""
        client_id = self.get_client_identifier(request)
        current_time = time.time()
        
        if is_authenticated:
            max_requests = self.auth_max_requests
            window_seconds = self.auth_window_seconds
        else:
            max_requests = self.max_requests
            window_seconds = self.window_seconds
        
        if client_id in rate_limit_store:
            request_count, window_start = rate_limit_store[client_id]
            
            # Check if window has expired
            if current_time - window_start > window_seconds:
                return max_requests
            else:
                return max(0, max_requests - request_count)
        
        return max_requests
    
    def get_reset_time(self, request: Request, is_authenticated: bool = False) -> float:
        """Get time when rate limit resets."""
        client_id = self.get_client_identifier(request)
        
        if is_authenticated:
            window_seconds = self.auth_window_seconds
        else:
            window_seconds = self.window_seconds
        
        if client_id in rate_limit_store:
            _, window_start = rate_limit_store[client_id]
            return window_start + window_seconds
        
        return time.time()

# Global rate limiter instance
rate_limiter = RateLimiter()

async def rate_limit_middleware(request: Request, call_next):
    """Rate limiting middleware."""
    # Skip rate limiting for health checks and static files
    if request.url.path in ["/health", "/docs", "/openapi.json"]:
        return await call_next(request)
    
    # Check if this is a public endpoint
    is_public_endpoint = request.url.path == "/api/review-public"
    
    if is_public_endpoint:
        # For public endpoint, check UI access and rate limits
        if not rate_limiter.is_ui_request(request):
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={
                    "error": "Direct API access not allowed",
                    "message": "This endpoint can only be accessed through the Semio dashboard"
                }
            )
        
        # Check rate limit
        if not rate_limiter.check_rate_limit(request, is_authenticated=False):
            remaining_time = rate_limiter.get_reset_time(request, is_authenticated=False) - time.time()
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": "Rate limit exceeded",
                    "message": f"Too many requests. Try again in {int(remaining_time)} seconds",
                    "reset_time": int(rate_limiter.get_reset_time(request, is_authenticated=False))
                }
            )
    
    # For authenticated endpoints, rate limiting is handled by the endpoint itself
    response = await call_next(request)
    
    # Add rate limit headers for public endpoint
    if is_public_endpoint:
        remaining = rate_limiter.get_remaining_requests(request, is_authenticated=False)
        reset_time = rate_limiter.get_reset_time(request, is_authenticated=False)
        
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(int(reset_time))
        response.headers["X-RateLimit-Limit"] = str(rate_limiter.max_requests)
    
    return response
