from fastapi import APIRouter
from datetime import datetime

from core.detector import detect_sensitive_data
from core.risk_engine import calculate_risk
from core.intent_analyzer import analyze_intent
from core.policy_engine import apply_company_policy


router = APIRouter()


@router.post("/scan")
def scan_prompt(data: dict):

    text = data.get("text", "")
    
    company_type = data.get(
        "company_type",
        "IT_COMPANY"
    )

    detections = detect_sensitive_data(text)

    intent = analyze_intent(text)

    risk = calculate_risk(detections)

    policy = apply_company_policy(
        detections,
        company_type
    )

    final_action = risk["action"]

    if policy["policy_violation"]:
        final_action = "BLOCK"

    elif (
        intent["safe_context"]
        and final_action == "BLOCK"
    ):
        final_action = "WARN"

    return {
        "status": "SUCCESS",
        "scan_result": {
            "timestamp": str(datetime.now()),
            "input_text": text,
            "company_type": company_type,
            "detections": detections,
            "intent_analysis": intent,
            "risk_score": risk["score"],
            "risk_level": risk["level"],
            "recommended_action": final_action,
            "policy_check": policy
        }
    }
