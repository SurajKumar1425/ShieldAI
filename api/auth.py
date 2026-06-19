from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from security.jwt_handler import create_access_token


router = APIRouter()


# Temporary users database
USERS_DB = {
    "admin@abc_bank.com": {
        "password": "Admin@123",
        "role": "ADMIN",
        "company": "ABC_BANK"
    },

    "analyst@abc_bank.com": {
        "password": "Analyst@123",
        "role": "SECURITY_ANALYST",
        "company": "ABC_BANK"
    }
}


class LoginRequest(BaseModel):
    email: str
    password: str


@router.post("/login")
def login(request: LoginRequest):

    user = USERS_DB.get(request.email)

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid email"
        )

    if user["password"] != request.password:
        raise HTTPException(
            status_code=401,
            detail="Invalid password"
        )

    token = create_access_token({
        "email": request.email,
        "role": user["role"],
        "company": user["company"]
    })

    return {
        "status": "SUCCESS",
        "access_token": token,
        "token_type": "bearer",
        "role": user["role"]
    }
