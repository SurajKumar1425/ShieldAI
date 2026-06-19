from fastapi import APIRouter
from datetime import datetime

from core.detector import detect_sensitive_data
from core.risk_engine import calculate_risk
from core.intent_analyzer import analyze_intent
from core.policy_engine import apply_company_policy

from monitoring.audit import save_security_incident
from monitoring.alerts import generate_security_alert
from monitoring.anomaly import track_user_activity


router = APIRouter()


@router.post("/scan")
def scan_prompt(data: dict):

    text = data.get("text", "")
    user_id = data.get("user_id", "anonymous")
    company = data.get("company", "UNKNOWN")
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


    scan_result = {
        "timestamp": str(datetime.now()),
        "input_text": text,
        "company_type": company_type,
        "detections": detections,
        "intent_analysis": intent,
        "risk_score": risk["score"],
        "risk_level": risk["level"],
        "recommended_action": final_action
    }


    incident = None
    alert = None


    if final_action == "BLOCK":

        incident = save_security_incident(
            user_id,
            company,
            scan_result
        )

        alert = generate_security_alert(
            user_id,
            company,
            scan_result
        )


    activity = track_user_activity(
        user_id,
        scan_result
    )


    return {
        "status": "SUCCESS",
        "scan_result": scan_result,
        "incident": incident,
        "alert": alert,
        "user_activity": activity
    }
