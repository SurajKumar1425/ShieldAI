from fastapi import APIRouter
from datetime import datetime

from core.detector import detect_sensitive_data
from core.risk_engine import calculate_risk


router = APIRouter()


@router.post("/scan")
def scan_prompt(data: dict):

    text = data.get("text", "")

    detections = detect_sensitive_data(text)

    risk = calculate_risk(detections)

    return {
        "status": "SUCCESS",
        "scan_result": {
            "timestamp": str(datetime.now()),
            "input_text": text,
            "detections": detections,
            "risk_score": risk["score"],
            "risk_level": risk["level"],
            "recommended_action": risk["action"]
        }
    }
