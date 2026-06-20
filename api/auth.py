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


# Strong Password Validation

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


# Generate 6 digit OTP

def generate_otp():

    return str(
        random.randint(
            100000,
            999999
        )
    )


# Hash OTP before storing

def hash_otp(otp):

    return hashlib.sha256(
        otp.encode()
    ).hexdigest()


# Current Time

def current_time():

    return str(
        datetime.datetime.now()
    )


# OTP Expiry

def otp_expiry_time():

    return str(
        datetime.datetime.now()
        + datetime.timedelta(
            minutes=5
        )
    )


# ======================
# Request Models
# ======================


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

    email: EmailStr

    password: str
    # ======================
# Signup API
# ======================

@router.post("/signup")
def signup(request: SignupRequest):

    connection = get_database_connection()

    cursor = connection.cursor()


    # Check existing user

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


    # Validate password policy

    if not validate_password(
        request.password
    ):

        connection.close()

        raise HTTPException(
            status_code=400,
            detail="""
Password must contain:
- Minimum 12 characters
- Uppercase letter
- Lowercase letter
- Number
- Special character
"""
        )


    # Encrypt password

    password_hash = hash_password(
        request.password
    )


    # Create new user

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


    # Email service will be added next

    return {

        "status":
            "SUCCESS",

        "message":
            "Account created successfully. Verification code sent to your email.",


        # Remove after email integration
        "development_otp":
            otp
    }
    # ======================
# Email OTP Verification
# ======================

@router.post("/verify-otp")
def verify_otp(request: OTPRequest):

    connection = get_database_connection()

    cursor = connection.cursor()


    cursor.execute(
        """
        SELECT 
            users.user_id,
            otp_codes.otp_id,
            otp_codes.otp_hash,
            otp_codes.expires_at,
            otp_codes.attempt_count,
            otp_codes.is_used

        FROM users

        JOIN otp_codes
        ON users.user_id = otp_codes.user_id

        WHERE users.email = ?
        AND otp_codes.otp_type = ?
        ORDER BY otp_codes.otp_id DESC
        LIMIT 1
        """,
        (
            request.email,
            "EMAIL_VERIFICATION"
        )
    )


    otp_record = cursor.fetchone()


    if not otp_record:

        connection.close()

        raise HTTPException(
            status_code=404,
            detail="Verification request not found"
        )


    if otp_record["is_used"] == 1:

        connection.close()

        raise HTTPException(
            status_code=400,
            detail="OTP already used"
        )


    if otp_record["attempt_count"] >= 3:

        connection.close()

        raise HTTPException(
            status_code=403,
            detail="Maximum OTP attempts exceeded"
        )


    if current_time() > otp_record["expires_at"]:

        connection.close()

        raise HTTPException(
            status_code=401,
            detail="OTP expired"
        )


    if hash_otp(request.otp_code) != otp_record["otp_hash"]:


        cursor.execute(
            """
            UPDATE otp_codes
            SET attempt_count = attempt_count + 1
            WHERE otp_id = ?
            """,
            (
                otp_record["otp_id"],
            )
        )


        connection.commit()

        connection.close()


        raise HTTPException(
            status_code=401,
            detail="Invalid OTP"
        )


    cursor.execute(
        """
        UPDATE otp_codes
        SET is_used = 1
        WHERE otp_id = ?
        """,
        (
            otp_record["otp_id"],
        )
    )


    cursor.execute(
        """
        UPDATE users
        SET 
            email_verified = 1,
            account_status = 'ACTIVE',
            updated_at = ?
        WHERE user_id = ?
        """,
        (
            current_time(),
            otp_record["user_id"]
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
        VALUES (?, ?, ?, ?)
        """,
        (
            otp_record["user_id"],
            "EMAIL_VERIFIED",
            "Employee email verified successfully",
            current_time()
        )
    )


    connection.commit()

    connection.close()


    return {
        "status": "SUCCESS",
        "message": "Account verified successfully"
    }


# ======================
# Login API
# ======================

@router.post("/login")
def login(request: LoginRequest):

    check_rate_limit(request.email)


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


    if user["account_locked"] == 1:

        connection.close()

        raise HTTPException(
            status_code=403,
            detail="Account locked. Contact administrator."
        )


    if user["account_status"] != "ACTIVE":

        connection.close()

        raise HTTPException(
            status_code=403,
            detail="Please verify your email before login"
        )


    if not verify_password(
        request.password,
        user["password_hash"]
    ):

        cursor.execute(
            """
            UPDATE users
            SET failed_login_attempts =
            failed_login_attempts + 1
            WHERE user_id = ?
            """,
            (
                user["user_id"],
            )
        )


        connection.commit()

        connection.close()


        raise HTTPException(
            status_code=401,
            detail="Invalid password"
        )


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


    cursor.execute(
        """
        INSERT INTO audit_logs
        (
            user_id,
            event_type,
            description,
            created_at
        )
        VALUES (?, ?, ?, ?)
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


    token = create_access_token(
        {
            "user_id": user["user_id"],
            "email": request.email,
            "role": user["role"],
            "company": user["company_name"]
        }
    )


    return {
        "status": "SUCCESS",
        "message": "Login successful",
        "access_token": token,
        "token_type": "bearer",
        "role": user["role"]
    }
