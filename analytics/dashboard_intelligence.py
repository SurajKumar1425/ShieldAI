def generate_security_dashboard(
    incidents,
    alerts
):
    """
    ShieldAI v2 Dashboard Intelligence Engine
    """

    total_scans = len(incidents)

    critical_threats = sum(
        1 for item in incidents
        if item.get("risk_level") == "CRITICAL"
    )


    blocked_requests = sum(
        1 for item in alerts
        if item.get("action_taken") == "BLOCK"
    )


    attack_types = {}

    for item in incidents:

        for detection in item.get("detections", []):

            attack_type = detection["type"]

            attack_types[attack_type] = (
                attack_types.get(attack_type, 0) + 1
            )


    return {

        "total_ai_requests": total_scans,

        "critical_threats": critical_threats,

        "blocked_requests": blocked_requests,

        "top_attack_types": attack_types,

        "security_status":
            "SAFE"
            if critical_threats == 0
            else "UNDER_ATTACK"
    }
