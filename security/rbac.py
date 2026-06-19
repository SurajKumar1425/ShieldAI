from fastapi import HTTPException

from security.jwt_handler import verify_access_token


ROLE_PERMISSIONS = {
    "ADMIN": [
        "VIEW_DASHBOARD",
        "VIEW_ALERTS",
        "MANAGE_USERS",
        "MANAGE_POLICIES"
    ],

    "SECURITY_ANALYST": [
        "VIEW_DASHBOARD",
        "VIEW_ALERTS"
    ],

    "EMPLOYEE": [
        "USE_AI_SCAN"
    ]
}


def check_permission(
    token,
    required_permission
):

    user = verify_access_token(token)

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )

    role = user.get("role")

    permissions = ROLE_PERMISSIONS.get(
        role,
        []
    )

    if required_permission not in permissions:
        raise HTTPException(
            status_code=403,
            detail="Permission denied"
        )

    return user
