from fastapi import FastAPI

app = FastAPI(title="Semio API", version="1.0.0")

@app.get("/")
async def root():
    return {"message": "Welcome to Semio API - Simple Version"}

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

@app.get("/test")
async def test():
    return {"message": "Test endpoint working!"}
