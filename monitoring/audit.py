import json
from datetime import datetime

from database.connection import get_database_connection


def save_security_incident(
    user_id,
    company,
    scan_result
):

    connection = get_database_connection()

    cursor = connection.cursor()


    cursor.execute(
        """
        INSERT INTO security_incidents (
            timestamp,
            user_id,
            company,
            risk_level,
            action,
            detections,
            prompt_preview
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            str(datetime.now()),
            user_id,
            company,
            scan_result["risk_level"],
            scan_result["recommended_action"],
            json.dumps(
                scan_result["detections"]
            ),
            scan_result["input_text"][:100]
        )
    )


    connection.commit()

    connection.close()


    return {
        "status": "SAVED",
        "message": "Security incident stored successfully"
    }
