from fastapi import APIRouter, HTTPException, Request

from pydantic import BaseModel, EmailStr

from passlib.context import CryptContext


import random
import hashlib
import re
import datetime
import uuid


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


# ===================================
# Password Encryption
# ===================================

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


# ===================================
# Enterprise Password Policy
# ===================================

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


# ===================================
# Time Helper
# ===================================

def current_time():

    return str(
        datetime.datetime.now()
    )


# ===================================
# OTP Functions
# ===================================

def generate_otp():

    return str(
        random.randint(
            100000,
            999999
        )
    )


def hash_otp(otp):

    return hashlib.sha256(
        otp.encode()
    ).hexdigest()


def otp_expiry_time():

    return str(
        datetime.datetime.now()
        +
        datetime.timedelta(
            minutes=5
        )
    )


# ===================================
# Session ID Generator
# ===================================

def generate_session_id():

    return str(
        uuid.uuid4()
    )


# ===================================
# Request Models
# ===================================


class SignupRequest(BaseModel):

    full_name: str

    company_name: str

    email: EmailStr

    employee_id: str

    department: str

    password: str



class VerifyEmailOTPRequest(BaseModel):

    email: EmailStr

    otp_code: str



class LoginRequest(BaseModel):

    email: EmailStr

    password: str



class VerifyLoginOTPRequest(BaseModel):
    # ===================================
# Signup API
# ===================================

@router.post("/signup")
def signup(
    request: SignupRequest
):

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


    # Strong password validation

    if not validate_password(
        request.password
    ):

        connection.close()

        raise HTTPException(
            status_code=400,
            detail=
            """
Password must contain:
- Minimum 12 characters
- One uppercase letter
- One lowercase letter
- One number
- One special character
            """
        )


    # Encrypt password

    password_hash = hash_password(
        request.password
    )


    # Create new user account

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


    # Generate Email Verification OTP

    otp = generate_otp()


    otp_hash = hash_otp(
        otp
    )


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
            "SIGNUP_CREATED",
            "New enterprise account created",
            current_time()
        )
    )


    connection.commit()

    connection.close()


    # Send OTP Email

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
    # ===================================
# Email Verification OTP API
# ===================================

@router.post("/verify-email-otp")
def verify_email_otp(
    request: VerifyEmailOTPRequest
):

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


    otp_data = cursor.fetchone()


    if not otp_data:

        connection.close()

        raise HTTPException(
            status_code=404,
            detail="Verification request not found"
        )


    if otp_data["is_used"] == 1:

        connection.close()

        raise HTTPException(
            status_code=400,
            detail="OTP already used"
        )


    if otp_data["attempt_count"] >= 3:

        connection.close()

        raise HTTPException(
            status_code=403,
            detail="Maximum OTP attempts exceeded"
        )


    if current_time() > otp_data["expires_at"]:

        connection.close()

        raise HTTPException(
            status_code=401,
            detail="OTP expired"
        )


    entered_otp_hash = hash_otp(
        request.otp_code
    )


    if entered_otp_hash != otp_data["otp_hash"]:


        cursor.execute(
            """
            UPDATE otp_codes

            SET attempt_count =
            attempt_count + 1

            WHERE otp_id = ?
            """,
            (
                otp_data["otp_id"],
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
            otp_data["otp_id"],
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
            otp_data["user_id"]
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
            otp_data["user_id"],
            "EMAIL_VERIFIED",
            "Enterprise email verified successfully",
            current_time()
        )
    )


    connection.commit()

    connection.close()


    return {

        "status":
            "SUCCESS",

        "message":
            "Email verified. Your ShieldAI account is now active."

    }
    # ===================================
# Login Step 1 - Password Verification
# Generate MFA OTP
# ===================================

@router.post("/login")
def login(
    request: LoginRequest
):

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
            detail="Account is not active. Verify your email."
        )


    # Password verification

    if not verify_password(
        request.password,
        user["password_hash"]
    ):


        failed_attempts = (
            user["failed_login_attempts"] + 1
        )


        lock_account = 0


        if failed_attempts >= 5:

            lock_account = 1


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
                lock_account,
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
                "FAILED_PASSWORD_LOGIN",
                "Invalid login password",
                current_time()
            )
        )


        connection.commit()

        connection.close()


        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )


    # Reset failed attempts after correct password

    cursor.execute(
        """
        UPDATE users

        SET
            failed_login_attempts = 0,
            updated_at = ?

        WHERE user_id = ?
        """,
        (
            current_time(),
            user["user_id"]
        )
    )


    # Generate MFA OTP

    otp = generate_otp()


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
            user["user_id"],
            hash_otp(otp),
            "LOGIN_MFA",
            otp_expiry_time(),
            current_time()
        )
    )


    # Audit log

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
            "LOGIN_MFA_SENT",
            "MFA verification code generated",
            current_time()
        )
    )


    connection.commit()

    connection.close()


    # Send MFA OTP email

    email_sent = send_otp_email(
        request.email,
        otp
    )


    if not email_sent:

        raise HTTPException(
            status_code=500,
            detail="Unable to send login verification code"
        )


    return {

        "status":
            "SUCCESS",

        "message":
            "Login verification code sent to your email"

    }
    # ===================================
# Login Step 2 - Verify MFA OTP
# Create Session + JWT
# ===================================

@router.post("/verify-login-otp")
def verify_login_otp(
    request: VerifyLoginOTPRequest,
    client_request: Request
):

    connection = get_database_connection()

    cursor = connection.cursor()


    cursor.execute(
        """
        SELECT
            users.user_id,
            users.email,
            users.role,
            users.company_name,

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
            "LOGIN_MFA"
        )
    )


    otp_data = cursor.fetchone()


    if not otp_data:

        connection.close()

        raise HTTPException(
            status_code=404,
            detail="Login verification request not found"
        )


    # Check OTP already used

    if otp_data["is_used"] == 1:

        connection.close()

        raise HTTPException(
            status_code=400,
            detail="OTP already used"
        )


    # Check maximum attempts

    if otp_data["attempt_count"] >= 3:

        connection.close()

        raise HTTPException(
            status_code=403,
            detail="Maximum OTP attempts exceeded"
        )


    # Check OTP expiry

    if current_time() > otp_data["expires_at"]:

        connection.close()

        raise HTTPException(
            status_code=401,
            detail="OTP expired"
        )


    # Verify OTP

    entered_otp_hash = hash_otp(
        request.otp_code
    )


    if entered_otp_hash != otp_data["otp_hash"]:


        cursor.execute(
            """
            UPDATE otp_codes

            SET attempt_count =
            attempt_count + 1

            WHERE otp_id = ?
            """,
            (
                otp_data["otp_id"],
            )
        )


        connection.commit()

        connection.close()


        raise HTTPException(
            status_code=401,
            detail="Invalid OTP"
        )


    # Mark OTP as used

    cursor.execute(
        """
        UPDATE otp_codes

        SET is_used = 1

        WHERE otp_id = ?
        """,
        (
            otp_data["otp_id"],
        )
    )


    # Generate unique session ID

    session_id = generate_session_id()


    # Capture device information

    ip_address = (
        client_request.client.host
        if client_request.client
        else "UNKNOWN"
    )


    user_agent = (
        client_request.headers.get(
            "user-agent",
            "UNKNOWN DEVICE"
        )
    )


    # Store user session

    cursor.execute(
        """
        INSERT INTO user_sessions
        (
            user_id,
            jwt_id,
            ip_address,
            device_info,
            created_at,
            expires_at
        )

        VALUES
        (
            ?, ?, ?, ?, ?, ?
        )
        """,
        (
            otp_data["user_id"],
            session_id,
            ip_address,
            user_agent,
            current_time(),
            str(
                datetime.datetime.now()
                + datetime.timedelta(
                    days=7
                )
            )
        )
    )


    # Create final login audit

    cursor.execute(
        """
        INSERT INTO audit_logs
        (
            user_id,
            event_type,
            description,
            ip_address,
            created_at
        )

        VALUES
        (
            ?, ?, ?, ?, ?
        )
        """,
        (
            otp_data["user_id"],
            "LOGIN_SUCCESS",
            "MFA login completed successfully",
            ip_address,
            current_time()
        )
    )


    connection.commit()

    connection.close()


    # Generate JWT Token

    access_token = create_access_token(
        {
            "user_id": otp_data["user_id"],
            "email": otp_data["email"],
            "role": otp_data["role"],
            "company": otp_data["company_name"],
            "session_id": session_id
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
            otp_data["role"]

    }

    email: EmailStr

    otp_code: str
