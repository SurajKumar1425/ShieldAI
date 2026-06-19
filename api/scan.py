from fastapi import APIRouter
from datetime import datetime

from core.detector import detect_sensitive_data
from core.risk_engine import calculate_risk
from core.intent_analyzer import analyze_intent


router = APIRouter()


@router.post("/scan")
def scan_prompt(data: dict):

    text = data.get("text", "")

    detections = detect_sensitive_data(text)

    intent = analyze_intent(text)

    risk = calculate_risk(detections)

    if intent["safe_context"] and risk["score"] < 100:
        risk["action"] = "WARN"

    return {
        "status": "SUCCESS",
        "scan_result": {
            "timestamp": str(datetime.now()),
            "input_text": text,
            "detections": detections,
            "intent_analysis": intent,
            "risk_score": risk["score"],
            "risk_level": risk["level"],
            "recommended_action": risk["action"]
        }
    }
