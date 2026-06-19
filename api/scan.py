from fastapi import APIRouter
from datetime import datetime

from core.detector import detect_sensitive_data


router = APIRouter()


@router.post("/scan")
def scan_prompt(data: dict):

    text = data.get("text", "")

    detections = detect_sensitive_data(text)

    return {
        "status": "SUCCESS",
        "scan_result": {
            "timestamp": str(datetime.now()),
            "input_text": text,
            "detections": detections,
            "risk_level": (
                "SAFE"
                if not detections
                else "DETECTED"
            )
        }
    }
