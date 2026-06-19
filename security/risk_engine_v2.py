def calculate_risk(detections):
    """
    ShieldAI v2 Risk Scoring Engine
    """

    risk_weights = {
        "PAN_CARD": 40,
        "EMAIL_ADDRESS": 15,
        "PHONE_NUMBER": 20,
        "CREDIT_CARD": 80,
        "API_KEY_OR_SECRET": 90,
        "PASSWORD_OR_CREDENTIAL": 100,
        "AADHAAR_NUMBER": 100
    }

    score = 0

    for detection in detections:
        data_type = detection["type"]

        score += risk_weights.get(data_type, 10)


    # Maximum score = 100
    score = min(score, 100)


    if score <= 20:
        level = "LOW"
        action = "ALLOW"

    elif score <= 50:
        level = "MEDIUM"
        action = "ALERT"

    elif score <= 80:
        level = "HIGH"
        action = "REVIEW"

    else:
        level = "CRITICAL"
        action = "BLOCK"


    return {
        "risk_score": score,
        "risk_level": level,
        "recommended_action": action
    }
