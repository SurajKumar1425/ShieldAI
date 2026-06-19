from fastapi import APIRouter
from datetime import datetime


router = APIRouter()


@router.post("/scan")
def scan_prompt(data: dict):

    return {
        "status": "SUCCESS",
        "scan_result": {
            "timestamp": str(datetime.now()),
            "input_text": data.get("text"),
            "message": "ShieldAI scanning engine will process this request",
            "risk_level": "ANALYZING"
        }
    }
