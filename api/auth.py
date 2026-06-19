from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from passlib.context import CryptContext

from security.jwt_handler import create_access_token


router = APIRouter()


# Password hashing setup
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)


def hash_password(password):
    return pwd_context.hash(password)


def verify_password(
    plain_password,
    hashed_password
):
    return pwd_context.verify(
        plain_password,
        hashed_password
    )


# Temporary users database
USERS_DB = {
    "admin@abc_bank.com": {
        "password": hash_password(
            "Admin@123"
        ),
        "role": "ADMIN",
        "company": "ABC_BANK"
    },

    "analyst@abc_bank.com": {
        "password": hash_password(
            "Analyst@123"
        ),
        "role": "SECURITY_ANALYST",
        "company": "ABC_BANK"
    }
}


class LoginRequest(BaseModel):
    email: str
    password: str


@router.post("/login")
def login(
    request: LoginRequest
):

    user = USERS_DB.get(
        request.email
    )

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid email"
        )


    if not verify_password(
        request.password,
        user["password"]
    ):
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
        "message": "Login successful",
        "access_token": token,
        "token_type": "bearer",
        "role": user["role"]
    }
