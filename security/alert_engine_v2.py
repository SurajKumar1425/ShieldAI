from datetime import datetime


alert_counter = 0


def generate_alert(
    user_id,
    company,
    risk_level,
    detections,
    action
):
    """
    ShieldAI v2 Advanced Security Alert Engine
    """

    global alert_counter

    alert_counter += 1


    reasons = []


    if risk_level == "CRITICAL":
        reasons.append(
            "Critical sensitive data leakage detected"
        )

    if action == "BLOCK":
        reasons.append(
            "Security policy blocked this request"
        )


    return {
        "alert_id": alert_counter,
        "timestamp": str(datetime.now()),
        "user_id": user_id,
        "company": company,
        "severity": risk_level,
        "detected_data_types": [
            item["type"]
            for item in detections
        ],
        "reasons": reasons,
        "action_taken": action
    }
