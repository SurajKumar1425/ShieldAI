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


    cursor.execute(
        "SELECT COUNT(*) FROM security_incidents"
    )

    total_incidents = cursor.fetchone()[0]


    cursor.execute(
        """
        SELECT COUNT(*)
        FROM alerts
        WHERE severity = 'CRITICAL'
        """
    )

    critical_alerts = cursor.fetchone()[0]


    connection.close()


    return {
        "status": "SUCCESS",
        "message": "Real Dashboard Analytics",
        "user": {
            "email": user["email"],
            "role": user["role"],
            "company": user["company"]
        },
        "analytics": {
            "total_incidents": total_incidents,
            "critical_alerts": critical_alerts,
            "system_status": "SECURE"
        }
    }
