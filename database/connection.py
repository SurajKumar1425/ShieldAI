import sqlite3


DATABASE_NAME = "shieldai.db"


# Database Connection
def get_database_connection():

    connection = sqlite3.connect(
        DATABASE_NAME
    )

    return connection


# Initialize ShieldAI Database
def initialize_database():

    connection = get_database_connection()

    cursor = connection.cursor()


    # =========================
    # Security Incidents Table
    # =========================

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_incidents (
        incident_id INTEGER PRIMARY KEY AUTOINCREMENT,

        timestamp TEXT,

        user_id TEXT,

        company TEXT,

        risk_level TEXT,

        action TEXT,

        detections TEXT,

        prompt_preview TEXT
    )
    """)


    # =========================
    # Security Alerts Table
    # =========================

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        alert_id INTEGER PRIMARY KEY AUTOINCREMENT,

        timestamp TEXT,

        severity TEXT,

        reasons TEXT,

        action_taken TEXT
    )
    """)


    # =========================
    # Users Authentication Table
    # =========================

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        user_id INTEGER PRIMARY KEY AUTOINCREMENT,

        full_name TEXT NOT NULL,

        company_name TEXT NOT NULL,

        email TEXT UNIQUE NOT NULL,

        employee_id TEXT,

        department TEXT,

        password_hash TEXT NOT NULL,


        role TEXT DEFAULT 'EMPLOYEE',


        is_email_verified INTEGER DEFAULT 0,


        otp_code TEXT,

        otp_expiry TEXT,


        failed_login_attempts INTEGER DEFAULT 0,


        account_locked INTEGER DEFAULT 0,


        created_at TEXT,


        last_login TEXT
    )
    """)


    connection.commit()

    connection.close()


print(
    "ShieldAI Database System Ready"
)
