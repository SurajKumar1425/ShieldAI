from datetime import datetime

from database.connection import get_database_connection


def generate_security_alert(
    user_id,
    company,
    scan_result
):

    reasons = []

    if scan_result["risk_level"] == "CRITICAL":
        reasons.append(
            "Critical data leakage attempt detected"
        )

    if scan_result["recommended_action"] == "BLOCK":
        reasons.append(
            "Security policy blocked this request"
        )


    connection = get_database_connection()

    cursor = connection.cursor()


    cursor.execute(
        """
        INSERT INTO alerts (
            timestamp,
            severity,
            reasons,
            action_taken
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            str(datetime.now()),
            scan_result["risk_level"],
            str(reasons),
            scan_result["recommended_action"]
        )
    )


    alert_id = cursor.lastrowid


    connection.commit()

    connection.close()


    return {
        "alert_id": alert_id,
        "timestamp": str(datetime.now()),
        "user_id": user_id,
        "company": company,
        "severity": scan_result["risk_level"],
        "reasons": reasons,
        "action_taken": scan_result[
            "recommended_action"
        ]
    }
