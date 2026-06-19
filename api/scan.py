from fastapi import APIRouter
from pydantic import BaseModel
from datetime import datetime

from core.detector import detect_sensitive_data
from core.risk_engine import calculate_risk
from core.intent_analyzer import analyze_intent
from core.policy_engine import apply_company_policy

from monitoring.audit import save_security_incident
from monitoring.alerts import generate_security_alert
from monitoring.anomaly import track_user_activity


router = APIRouter()


class ScanRequest(BaseModel):
    text: str
    user_id: str = "anonymous"
    company: str = "UNKNOWN"
    company_type: str = "IT_COMPANY"


@router.post("/scan")
def scan_prompt(data: ScanRequest):

    text = data.text
    user_id = data.user_id
    company = data.company
    company_type = data.company_type


    # Step 1: Detect sensitive data
    detections = detect_sensitive_data(text)


    # Step 2: Analyze user intent
    intent = analyze_intent(text)


    # Step 3: Calculate risk
    risk = calculate_risk(detections)


    # Step 4: Check company policy
    policy = apply_company_policy(
        detections,
        company_type
    )


    # Final security decision
    final_action = risk["action"]

    if policy["policy_violation"]:
        final_action = "BLOCK"


    # Create final scan report
    scan_result = {
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


    incident = None
    alert = None


    # Store security events
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


    # Track employee behavior
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
