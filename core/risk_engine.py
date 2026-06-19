RISK_VALUES = {
    "EMAIL": 20,
    "INDIAN_PHONE": 40,
    "PAN_NUMBER": 90,
    "AADHAAR_NUMBER": 100,
    "AWS_API_KEY": 95,
    "PASSWORD": 80,
    "API_TOKEN": 90,
    "IFSC_CODE": 70
}


def calculate_risk(detections):

    total_risk = 0

    for item in detections:
        data_type = item["type"]

        total_risk += RISK_VALUES.get(
            data_type,
            10
        )


    if total_risk == 0:
        return {
            "score": 0,
            "level": "SAFE",
            "action": "ALLOW"
        }

    elif total_risk < 50:
        return {
            "score": total_risk,
            "level": "LOW",
            "action": "ALLOW"
        }

    elif total_risk < 80:
        return {
            "score": total_risk,
            "level": "MEDIUM",
            "action": "WARN"
        }

    elif total_risk < 100:
        return {
            "score": total_risk,
            "level": "HIGH",
            "action": "BLOCK"
        }

    else:
        return {
            "score": 100,
            "level": "CRITICAL",
            "action": "BLOCK"
        }
