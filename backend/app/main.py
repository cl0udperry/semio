from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from app.routes.scan import router as scan_router
from app.routes.review import router as review_router
from app.routes.auth import router as auth_router
from app.database import init_db
import time

app = FastAPI(title="Semio API", version="1.0.0")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add rate limiting middleware
@app.middleware("http")
async def rate_limit_middleware_wrapper(request: Request, call_next):
    print(f"🔒 Middleware triggered for: {request.url.path}")
    
    # Test middleware with a simple endpoint
    if request.url.path == "/test-middleware":
        print("🔒 Middleware test endpoint hit!")
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=200,
            content={"message": "Middleware is working!"}
        )
    
    # Check UI-only access for public endpoint
    if request.url.path == "/api/review-public":
        from app.middleware.rate_limiter import rate_limiter
        from fastapi.responses import JSONResponse
        from fastapi import status
        
        # Check if request is coming from UI
        is_ui_request = rate_limiter.is_ui_request(request)
        print(f"🔒 Is UI request: {is_ui_request}")
        
        if not is_ui_request:
            print("🔒 Blocking direct API access")
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={
                    "error": "Direct API access not allowed",
                    "message": "This endpoint can only be accessed through the Semio dashboard"
                }
            )
        
        # Check rate limit for UI requests
        rate_limit_ok = rate_limiter.check_rate_limit(request, is_authenticated=False)
        print(f"🔒 Rate limit check: {rate_limit_ok}")
        
        if not rate_limit_ok:
            remaining_time = rate_limiter.get_reset_time(request, is_authenticated=False) - time.time()
            print(f"🔒 Rate limit exceeded, remaining time: {remaining_time}")
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": "Rate limit exceeded",
                    "message": f"Too many requests. Try again in {int(remaining_time)} seconds"
                }
            )
    
    # For all other requests, proceed normally
    response = await call_next(request)
    return response

# Include routers
app.include_router(auth_router, prefix="/auth", tags=["Authentication"])
app.include_router(scan_router, prefix="/api", tags=["API"])
app.include_router(review_router, prefix="/api", tags=["API"])

@app.on_event("startup")
async def startup_event():
    """Initialize database on startup."""
    init_db()

@app.get("/")
async def root():
    return {"message": "Welcome to Semio API"}

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

@app.get("/test-middleware")
async def test_middleware():
    return {"message": "This should be blocked by middleware"}