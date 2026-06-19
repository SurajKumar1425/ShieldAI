COMPANY_POLICIES = {
    "BANK": {
        "blocked_types": [
            "AADHAAR_NUMBER",
            "PAN_NUMBER",
            "BANK_ACCOUNT",
            "PASSWORD",
            "API_TOKEN",
            "AWS_API_KEY"
        ]
    },

    "IT_COMPANY": {
        "blocked_types": [
            "PASSWORD",
            "API_TOKEN",
            "AWS_API_KEY"
        ]
    },

    "HEALTHCARE": {
        "blocked_types": [
            "AADHAAR_NUMBER",
            "PAN_NUMBER"
        ]
    }
}


def apply_company_policy(
    detections,
    company_type
):

    policy = COMPANY_POLICIES.get(
        company_type,
        {}
    )

    blocked = policy.get(
        "blocked_types",
        []
    )

    for item in detections:

        if item["type"] in blocked:

            return {
                "policy_violation": True,
                "action": "BLOCK",
                "reason": (
                    f"{item['type']} "
                    "is restricted by company policy"
                )
            }

    return {
        "policy_violation": False,
        "action": "ALLOW",
        "reason": "No policy violation detected"
    }
