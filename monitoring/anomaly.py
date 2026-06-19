user_activity_history = {}


def track_user_activity(
    user_id,
    scan_result
):

    if user_id not in user_activity_history:

        user_activity_history[user_id] = {
            "total_events": 0,
            "critical_events": 0,
            "last_risk_level": "SAFE",
            "anomaly_detected": False
        }


    profile = user_activity_history[user_id]


    profile["total_events"] += 1

    if scan_result["risk_level"] == "CRITICAL":
        profile["critical_events"] += 1


    profile["last_risk_level"] = (
        scan_result["risk_level"]
    )


    if profile["critical_events"] >= 3:
        profile["anomaly_detected"] = True


    return profile
