from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routes.scan import router as scan_router
from app.routes.review import router as review_router
from app.routes.auth import router as auth_router
from app.database import init_db

app = FastAPI(title="Semio API", version="1.0.0")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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