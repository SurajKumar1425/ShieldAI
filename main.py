from fastapi import FastAPI

from api.auth import router as auth_router
from api.scan import router as scan_router
from api.dashboard import router as dashboard_router

from database.connection import initialize_database


app = FastAPI(
    title="ShieldAI Enterprise Security API",
    description="AI-powered Data Leakage Prevention and Prompt Security Platform",
    version="1.0.0"
)


@app.on_event("startup")
def startup_event():

    initialize_database()

    print(
        "ShieldAI Database Initialized Successfully"
    )


# Authentication APIs
app.include_router(
    auth_router,
    tags=["Authentication"]
)


# AI Security Scan APIs
app.include_router(
    scan_router,
    tags=["AI Security Scanner"]
)


# Admin Dashboard APIs
app.include_router(
    dashboard_router,
    tags=["Dashboard"]
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
