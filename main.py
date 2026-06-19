from fastapi import FastAPI

from api.scan import router as scan_router
from api.auth import router as auth_router


app = FastAPI(
    title="ShieldAI Enterprise Security API",
    description="AI-powered Data Leakage Prevention and Prompt Security Platform",
    version="1.0.0"
)


# Authentication APIs
app.include_router(
    auth_router,
    tags=["Authentication"]
)


# Security Scan APIs
app.include_router(
    scan_router,
    tags=["AI Security Scanner"]
)


@app.get("/")
def home():
    return {
        "message": "ShieldAI API Running",
        "status": "ACTIVE"
    }


@app.get("/health")
def health_check():
    return {
        "status": "HEALTHY",
        "service": "ShieldAI",
        "version": "1.0.0"
    }
