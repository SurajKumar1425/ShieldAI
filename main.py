from fastapi import FastAPI


app = FastAPI(
    title="ShieldAI Enterprise Security API",
    description="AI-powered Data Leakage Prevention and Prompt Security Platform",
    version="1.0.0"
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
