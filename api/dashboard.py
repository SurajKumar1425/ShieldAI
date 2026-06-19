from fastapi import APIRouter

from security.rbac import check_permission
from database.connection import get_database_connection


router = APIRouter()


@router.get("/admin/dashboard")
def admin_dashboard(token: str):

    user = check_permission(
        token,
        "VIEW_DASHBOARD"
    )

    connection = get_database_connection()
    cursor = connection.cursor()


    # Total incidents
    cursor.execute(
        "SELECT COUNT(*) FROM security_incidents"
    )

    total_incidents = cursor.fetchone()[0]


    # Critical alerts
    cursor.execute(
        """
        SELECT COUNT(*)
        FROM alerts
        WHERE severity = 'CRITICAL'
        """
    )

    critical_alerts = cursor.fetchone()[0]


    # High risk users
    cursor.execute(
        """
        SELECT user_id, COUNT(*)
        FROM security_incidents
        WHERE risk_level = 'CRITICAL'
        GROUP BY user_id
        ORDER BY COUNT(*) DESC
        LIMIT 5
        """
    )

    risky_users = []

    for row in cursor.fetchall():

        risky_users.append({
            "user_id": row[0],
            "critical_incidents": row[1]
        })


    connection.close()


    return {
        "status": "SUCCESS",
        "message": "ShieldAI Security Dashboard",
        "user": {
            "email": user["email"],
            "role": user["role"],
            "company": user["company"]
        },
        "analytics": {
            "total_incidents": total_incidents,
            "critical_alerts": critical_alerts,
            "high_risk_users": risky_users,
            "system_status": "SECURE"
        }
    }
