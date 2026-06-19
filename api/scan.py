from fastapi import APIRouter
from pydantic import BaseModel
from datetime import datetime


# ShieldAI v2 Engines
from security.dlp_engine_v2 import scan_sensitive_data
from security.risk_engine_v2 import calculate_risk
from security.policy_engine_v2 import check_company_policy
from security.alert_engine_v2 import generate_alert


# Existing Security Features
from monitoring.audit import save_security_incident
from monitoring.anomaly import track_user_activity
from security.rate_limiter import check_rate_limit


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


    # API abuse protection
    check_rate_limit(user_id)


    # Step 1: Advanced DLP Scan
    dlp_result = scan_sensitive_data(text)

    detections = dlp_result["detections"]


    # Step 2: Risk Intelligence
    risk = calculate_risk(detections)


    # Step 3: Company Policy Check
    policy = check_company_policy(
        detections,
        company_type
    )


    # Final Decision
    final_action = risk["recommended_action"]

    if policy["policy_violation"]:
        final_action = "BLOCK"


    # Final ShieldAI Report
    scan_result = {

        "timestamp": str(datetime.now()),

        "input_text": text,

        "company_type": company_type,

        "detections": detections,


        "dlp_summary": {
            "total_detected":
                dlp_result["total_detections"]
        },


        "risk_score":
            risk["risk_score"],


        "risk_level":
            risk["risk_level"],


        "recommended_action":
            final_action,


        "policy_check":
            policy
    }


    incident = None
    alert = None


    # Critical Event Handling
    if final_action == "BLOCK":

        incident = save_security_incident(
            user_id,
            company,
            scan_result
        )


        alert = generate_alert(
            user_id,
            company,
            risk["risk_level"],
            detections,
            final_action
        )


    # Insider Threat Monitoring
    activity = track_user_activity(
        user_id,
        scan_result
    )


    return {

        "status": "SUCCESS",

        "shieldai_version": "2.0.0",

        "scan_result": scan_result,

        "incident": incident,

        "alert": alert,

        "user_activity": activity
    }
