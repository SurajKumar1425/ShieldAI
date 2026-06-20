from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext

import random
import hashlib
import re
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

from core.email_service import (
    send_otp_email
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


# Enterprise Password Policy

def validate_password(password):

    pattern = (
        r"^(?=.*[a-z])"
        r"(?=.*[A-Z])"
        r"(?=.*\d)"
        r"(?=.*[@$!%*?&])"
        r"[A-Za-z\d@$!%*?&]{12,}$"
    )


    return bool(
        re.match(
            pattern,
            password
        )
    )


# Generate 6 Digit OTP

def generate_otp():

    return str(
        random.randint(
            100000,
            999999
        )
    )


# Hash OTP before Database Storage

def hash_otp(otp):

    return hashlib.sha256(
        otp.encode()
    ).hexdigest()


# Current Timestamp

def current_time():

    return str(
        datetime.datetime.now()
    )


# OTP Expiry Time

def otp_expiry_time():

    return str(
        datetime.datetime.now()
        + datetime.timedelta(
            minutes=5
        )
    )


# ===============================
# API Request Models
# ===============================


class SignupRequest(BaseModel):

    full_name: str

    company_name: str

    email: EmailStr

    employee_id: str

    department: str

    password: str


class OTPRequest(BaseModel):

    email: EmailStr

    otp_code: str


class LoginRequest(BaseModel):
    # ===============================
# Signup API
# ===============================

@router.post("/signup")
def signup(request: SignupRequest):

    connection = get_database_connection()

    cursor = connection.cursor()


    # Check existing email

    cursor.execute(
        """
        SELECT user_id
        FROM users
        WHERE email = ?
        """,
        (
            request.email,
        )
    )


    existing_user = cursor.fetchone()


    if existing_user:

        connection.close()

        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )


    # Validate password

    if not validate_password(
        request.password
    ):

        connection.close()

        raise HTTPException(
            status_code=400,
            detail="""
Password must contain:
- Minimum 12 characters
- One uppercase letter
- One lowercase letter
- One number
- One special character
"""
        )


    # Hash password

    password_hash = hash_password(
        request.password
    )


    # Create user account

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
            account_status,
            created_at,
            updated_at
        )

        VALUES
        (
            ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
        """,
        (
            request.full_name,
            request.company_name,
            request.email,
            request.employee_id,
            request.department,
            password_hash,
            "PENDING",
            current_time(),
            current_time()
        )
    )


    user_id = cursor.lastrowid


    # Generate OTP

    otp = generate_otp()


    otp_hash = hash_otp(
        otp
    )


    # Store OTP securely

    cursor.execute(
        """
        INSERT INTO otp_codes
        (
            user_id,
            otp_hash,
            otp_type,
            expires_at,
            created_at
        )

        VALUES
        (
            ?, ?, ?, ?, ?
        )
        """,
        (
            user_id,
            otp_hash,
            "EMAIL_VERIFICATION",
            otp_expiry_time(),
            current_time()
        )
    )


    # Create audit log

    cursor.execute(
        """
        INSERT INTO audit_logs
        (
            user_id,
            event_type,
            description,
            created_at
        )

        VALUES
        (
            ?, ?, ?, ?
        )
        """,
        (
            user_id,
            "ACCOUNT_CREATED",
            "New employee account created",
            current_time()
        )
    )


    connection.commit()

    connection.close()


    # Send verification email

    email_sent = send_otp_email(
        request.email,
        otp
    )


    if not email_sent:

        raise HTTPException(
            status_code=500,
            detail="Unable to send verification email"
        )


    return {

        "status":
            "SUCCESS",

        "message":
            "Verification code sent to your company email"

    }
    # ===============================
# Signup API
# ===============================

@router.post("/signup")
def signup(request: SignupRequest):

    connection = get_database_connection()

    cursor = connection.cursor()


    # Check existing email

    cursor.execute(
        """
        SELECT user_id
        FROM users
        WHERE email = ?
        """,
        (
            request.email,
        )
    )


    existing_user = cursor.fetchone()


    if existing_user:

        connection.close()

        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )


    # Validate password

    if not validate_password(
        request.password
    ):

        connection.close()

        raise HTTPException(
            status_code=400,
            detail="""
Password must contain:
- Minimum 12 characters
- One uppercase letter
- One lowercase letter
- One number
- One special character
"""
        )


    # Hash password

    password_hash = hash_password(
        request.password
    )


    # Create user account

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
            account_status,
            created_at,
            updated_at
        )

        VALUES
        (
            ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
        """,
        (
            request.full_name,
            request.company_name,
            request.email,
            request.employee_id,
            request.department,
            password_hash,
            "PENDING",
            current_time(),
            current_time()
        )
    )


    user_id = cursor.lastrowid


    # Generate OTP

    otp = generate_otp()


    otp_hash = hash_otp(
        otp
    )


    # Store OTP securely

    cursor.execute(
        """
        INSERT INTO otp_codes
        (
            user_id,
            otp_hash,
            otp_type,
            expires_at,
            created_at
        )

        VALUES
        (
            ?, ?, ?, ?, ?
        )
        """,
        (
            user_id,
            otp_hash,
            "EMAIL_VERIFICATION",
            otp_expiry_time(),
            current_time()
        )
    )


    # Create audit log

    cursor.execute(
        """
        INSERT INTO audit_logs
        (
            user_id,
            event_type,
            description,
            created_at
        )

        VALUES
        (
            ?, ?, ?, ?
        )
        """,
        (
            user_id,
            "ACCOUNT_CREATED",
            "New employee account created",
            current_time()
        )
    )


    connection.commit()

    connection.close()


    # Send verification email

    email_sent = send_otp_email(
        request.email,
        otp
    )


    if not email_sent:

        raise HTTPException(
            status_code=500,
            detail="Unable to send verification email"
        )


    return {

        "status":
            "SUCCESS",

        "message":
            "Verification code sent to your company email"

    }
    # ===============================
# Login API
# ===============================

@router.post("/login")
def login(request: LoginRequest):

    # Brute force protection
    check_rate_limit(
        request.email
    )


    connection = get_database_connection()

    cursor = connection.cursor()


    cursor.execute(
        """
        SELECT
            user_id,
            password_hash,
            role,
            company_name,
            account_status,
            account_locked,
            failed_login_attempts

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
            detail="Invalid email or password"
        )


    # Account lock check

    if user["account_locked"] == 1:

        connection.close()

        raise HTTPException(
            status_code=403,
            detail="Account locked. Contact administrator."
        )


    # Email verification check

    if user["account_status"] != "ACTIVE":

        connection.close()

        raise HTTPException(
            status_code=403,
            detail="Account is not verified. Please verify your email."
        )


    # Password verification

    if not verify_password(
        request.password,
        user["password_hash"]
    ):


        failed_attempts = (
            user["failed_login_attempts"] + 1
        )


        account_lock = 0


        if failed_attempts >= 5:

            account_lock = 1


        cursor.execute(
            """
            UPDATE users

            SET
                failed_login_attempts = ?,
                account_locked = ?,
                updated_at = ?

            WHERE user_id = ?
            """,
            (
                failed_attempts,
                account_lock,
                current_time(),
                user["user_id"]
            )
        )


        cursor.execute(
            """
            INSERT INTO audit_logs
            (
                user_id,
                event_type,
                description,
                created_at
            )

            VALUES
            (
                ?, ?, ?, ?
            )
            """,
            (
                user["user_id"],
                "FAILED_LOGIN",
                "Invalid password attempt",
                current_time()
            )
        )


        connection.commit()

        connection.close()


        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )


    # Successful login reset

    cursor.execute(
        """
        UPDATE users

        SET
            failed_login_attempts = 0,
            last_login = ?,
            updated_at = ?

        WHERE user_id = ?
        """,
        (
            current_time(),
            current_time(),
            user["user_id"]
        )
    )


    # Create login audit log

    cursor.execute(
        """
        INSERT INTO audit_logs
        (
            user_id,
            event_type,
            description,
            created_at
        )

        VALUES
        (
            ?, ?, ?, ?
        )
        """,
        (
            user["user_id"],
            "LOGIN_SUCCESS",
            "User logged into ShieldAI",
            current_time()
        )
    )


    connection.commit()

    connection.close()


    # Create JWT token

    access_token = create_access_token(
        {
            "user_id": user["user_id"],
            "email": request.email,
            "role": user["role"],
            "company": user["company_name"]
        }
    )


    return {

        "status":
            "SUCCESS",

        "message":
            "Login successful",

        "access_token":
            access_token,

        "token_type":
            "bearer",

        "role":
            user["role"]

    }

    email: EmailStr

    password: str
