from fastapi import APIRouter

from security.rbac import check_permission


router = APIRouter()


@router.get("/admin/dashboard")
def admin_dashboard(token: str):

    user = check_permission(
        token,
        "VIEW_DASHBOARD"
    )

    return {
        "status": "SUCCESS",
        "message": "Admin Dashboard Access Granted",
        "user": {
            "email": user["email"],
            "role": user["role"],
            "company": user["company"]
        },
        "security_summary": {
            "total_incidents": 0,
            "critical_alerts": 0,
            "high_risk_users": 0,
            "system_status": "SECURE"
        }
    }
