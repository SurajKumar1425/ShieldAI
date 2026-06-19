from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

from api.auth import router as auth_router
from api.scan import router as scan_router
from api.dashboard import router as dashboard_router

from database.connection import initialize_database


app = FastAPI(
    title="ShieldAI Enterprise Security API",
    description="AI-powered Data Leakage Prevention and Prompt Security Platform",
    version="1.0.0"
)


# Startup Event
@app.on_event("startup")
def startup_event():

    initialize_database()

    print(
        "ShieldAI Database Initialized Successfully"
    )


# Validation Error Handler
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


# Global Exception Handler
@app.exception_handler(Exception)
async def global_exception_handler(
    request: Request,
    exc: Exception
):

    return JSONResponse(
        status_code=500,
        content={
            "status": "ERROR",
            "message": "ShieldAI internal security error",
            "detail": str(exc)
        }
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


# Dashboard APIs
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
