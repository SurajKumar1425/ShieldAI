from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware

from api.auth import router as auth_router
from api.scan import router as scan_router
from api.dashboard import router as dashboard_router

from database.connection import initialize_database


app = FastAPI(
    title="ShieldAI Enterprise Security API",
    description="""
## ShieldAI - AI Powered Data Leakage Prevention Platform

### Features:

- 🔍 Sensitive Data Detection
- 🛡️ AI Prompt Security
- ⚠️ Risk Scoring Engine
- 🏢 Company Policy Enforcement
- 🔐 JWT Authentication
- 👥 Role Based Access Control
- 📊 Security Dashboard Analytics
- 🚨 Real-Time Security Alerts

### Available APIs:

- POST `/scan` → Analyze AI prompts for sensitive information
- POST `/login` → Generate JWT access token
- GET `/admin/dashboard` → View enterprise security analytics
- GET `/health` → Check ShieldAI system health
""",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)


# =========================
# CORS Configuration
# =========================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "https://shieldai-web.vercel.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================
# Database Initialization
# =========================

@app.on_event("startup")
def startup_event():

    initialize_database()

    print(
        "ShieldAI Database Initialized Successfully"
    )


# =========================
# Input Validation Errors
# =========================

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request,
    exc: RequestValidationError
):

    return JSONResponse(
        status_code=422,
        content={
            "status": "FAILED",
            "error": "Invalid request format",
            "details": exc.errors()
        }
    )


# =========================
# Global Server Errors
# =========================

@app.exception_handler(Exception)
async def global_exception_handler(
    request: Request,
    exc: Exception
):

    return JSONResponse(
        status_code=500,
        content={
            "status": "ERROR",
            "message": "ShieldAI internal server error",
            "detail": str(exc)
        }
    )


# =========================
# Authentication APIs
# =========================

app.include_router(
    auth_router,
    tags=["Authentication"]
)


# =========================
# AI Security Scanner APIs
# =========================

app.include_router(
    scan_router,
    tags=["AI Security Scanner"]
)


# =========================
# Dashboard APIs
# =========================

app.include_router(
    dashboard_router,
    tags=["Dashboard Analytics"]
)


# =========================
# Home API
# =========================

@app.get("/")
def home():

    return {
        "message": "ShieldAI API Running",
        "status": "ACTIVE"
    }


# =========================
# Health Check API
# =========================

@app.get("/health")
def health_check():

    return {
        "status": "HEALTHY",
        "service": "ShieldAI",
        "version": "1.0.0"
    }
