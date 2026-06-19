def check_company_policy(detections, company_type):
    """
    ShieldAI v2 Company Policy Engine
    """

    policies = {
        "BANK": [
            "AADHAAR_NUMBER",
            "PAN_CARD",
            "CREDIT_CARD",
            "PASSWORD_OR_CREDENTIAL",
            "API_KEY_OR_SECRET"
        ],

        "IT_COMPANY": [
            "API_KEY_OR_SECRET",
            "PASSWORD_OR_CREDENTIAL"
        ],

        "HEALTHCARE": [
            "AADHAAR_NUMBER",
            "PAN_CARD",
            "EMAIL_ADDRESS",
            "PHONE_NUMBER"
        ]
    }


    restricted_data = policies.get(company_type, [])


    for detection in detections:

        if detection["type"] in restricted_data:

            return {
                "policy_violation": True,
                "action": "BLOCK",
                "reason": f"{detection['type']} is restricted by company policy"
            }


    return {
        "policy_violation": False,
        "action": "ALLOW",
        "reason": "No company policy violation"
    }
