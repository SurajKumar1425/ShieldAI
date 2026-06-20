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


# =========================
# Password Security
# =========================

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


# =========================
# OTP Generator
# =========================

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


class OTPRequest(BaseModel):

    email: EmailStr

    otp_code: str


# =========================
# Signup API
# =========================

@router.post("/signup")
def signup(
    request: SignupRequest
):

    connection = (
        get_database_connection()
    )

    cursor = connection.cursor()


    # Check existing email

    cursor.execute(
        """
        SELECT email
        FROM users
        WHERE email = ?
        """,
        (
            request.email,
        )
    )


    user = cursor.fetchone()


    if user:

        connection.close()

        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )


    # Hash Password

    password_hash = hash_password(
        request.password
    )


    # Generate OTP

    otp = generate_otp()


    # Save user

    cursor.execute(
        """
        INSERT INTO users
        (
            full_name,
            company_name,
            email,
            employee_id,
            department,
            password_hash,
            otp_code,
            created_at
        )

        VALUES
        (
            ?, ?, ?, ?, ?, ?, ?, ?
        )
        """,
        (
            request.full_name,
            request.company_name,
            request.email,
            request.employee_id,
            request.department,
            password_hash,
            otp,
            str(
                datetime.datetime.now()
            )
        )
    )


    connection.commit()

    connection.close()


    return {

        "status":
            "SUCCESS",

        "message":
            "Account created. Verify your email OTP.",

        # Remove this in production
        "otp_for_testing":
            otp
    }
    # =========================
# Email OTP Verification API
# =========================

@router.post("/verify-otp")
def verify_otp(
    request: OTPRequest
):

    connection = get_database_connection()

    cursor = connection.cursor()


    cursor.execute(
        """
        SELECT otp_code,
               is_email_verified
        FROM users
        WHERE email = ?
        """,
        (
            request.email,
        )
    )


    user = cursor.fetchone()


    if not user:

        connection.close()

        raise HTTPException(
            status_code=404,
            detail="User not found"
        )


    if user[1] == 1:

        connection.close()

        return {
            "status": "SUCCESS",
            "message": "Email already verified"
        }


    if user[0] != request.otp_code:

        connection.close()

        raise HTTPException(
            status_code=401,
            detail="Invalid OTP"
        )


    cursor.execute(
        """
        UPDATE users
        SET
            is_email_verified = 1,
            otp_code = NULL
        WHERE email = ?
        """,
        (
            request.email,
        )
    )


    connection.commit()

    connection.close()


    return {
        "status": "SUCCESS",
        "message":
        "Email verified successfully. You can now login."
    }


# =========================
# Login API
# =========================

@router.post("/login")
def login(
    request: LoginRequest
):

    # Brute force protection
    check_rate_limit(
        request.email
    )


    connection = get_database_connection()

    cursor = connection.cursor()


    cursor.execute(
        """
        SELECT
            password_hash,
            role,
            company_name,
            is_email_verified,
            account_locked
        FROM users
        WHERE email = ?
        """,
        (
            request.email,
        )
    )


    user = cursor.fetchone()


    if not user:

        connection.close()

        raise HTTPException(
            status_code=401,
            detail="Invalid email"
        )


    if user[4] == 1:

        connection.close()

        raise HTTPException(
            status_code=403,
            detail="Account locked. Contact administrator."
        )


    if user[3] == 0:

        connection.close()

        raise HTTPException(
            status_code=403,
            detail="Verify your email before login."
        )


    if not verify_password(
        request.password,
        user[0]
    ):

        connection.close()

        raise HTTPException(
            status_code=401,
            detail="Invalid password"
        )


    # Update last login

    cursor.execute(
        """
        UPDATE users
        SET last_login = ?
        WHERE email = ?
        """,
        (
            str(datetime.datetime.now()),
            request.email
        )
    )


    connection.commit()

    connection.close()


    # Create JWT Token

    token = create_access_token(
        {
            "email": request.email,
            "role": user[1],
            "company": user[2]
        }
    )


    return {
        "status": "SUCCESS",
        "message": "Login successful",

        "access_token": token,

        "token_type": "bearer",

        "role": user[1]
    }
