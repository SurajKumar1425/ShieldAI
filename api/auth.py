from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext

import random
import datetime

from database.connection import (
    get_database_connection
)

from security.jwt_handler import (
    create_access_token
)

from security.rate_limiter import (
    check_rate_limit
)


router = APIRouter()


# Password Encryption

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


# Generate 6 digit OTP

def generate_otp():

    return str(
        random.randint(
            100000,
            999999
        )
    )


# =========================
# Request Models
# =========================


class SignupRequest(BaseModel):

    full_name: str

    company_name: str

    email: EmailStr

    employee_id: str

    department: str

    password: str


class LoginRequest(BaseModel):

    email: EmailStr

    password: str
    # =========================
# Signup API
# =========================

@router.post("/signup")
def signup(request: SignupRequest):

    connection = get_database_connection()

    cursor = connection.cursor()


    # Check if email already exists

    cursor.execute(
        """
        SELECT email
        FROM users
        WHERE email = ?
        """,
        (request.email,)
    )


    existing_user = cursor.fetchone()


    if existing_user:

        connection.close()

        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )


    # Hash user password

    hashed_password = hash_password(
        request.password
    )


    # Generate Email OTP

    otp = generate_otp()


    # Current time

    created_time = str(
        datetime.datetime.now()
    )


    # Save user into database

    cursor.execute(
        """
        INSERT INTO users (
            full_name,
            company_name,
            email,
            employee_id,
            department,
            password_hash,
            otp_code,
            created_at
        )

        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            request.full_name,
            request.company_name,
            request.email,
            request.employee_id,
            request.department,
            hashed_password,
            otp,
            created_time
        )
    )


    connection.commit()

    connection.close()


    # TODO:
    # Send OTP to email service


    return {
        "status": "SUCCESS",

        "message":
        "Account created successfully. Verify your email OTP.",

        "otp_for_testing": otp
    }
