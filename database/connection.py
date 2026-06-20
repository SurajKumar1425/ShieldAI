import sqlite3


DATABASE_NAME = "shieldai.db"


def get_database_connection():

    connection = sqlite3.connect(
        DATABASE_NAME
    )

    connection.row_factory = sqlite3.Row

    return connection


def initialize_database():

    connection = get_database_connection()

    cursor = connection.cursor()


    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (

        user_id INTEGER PRIMARY KEY AUTOINCREMENT,

        full_name TEXT NOT NULL,

        company_name TEXT NOT NULL,

        email TEXT UNIQUE NOT NULL,

        employee_id TEXT NOT NULL,

        department TEXT NOT NULL,

        password_hash TEXT NOT NULL,

        role TEXT DEFAULT 'EMPLOYEE',

        account_status TEXT DEFAULT 'PENDING',

        email_verified INTEGER DEFAULT 0,

        failed_login_attempts INTEGER DEFAULT 0,

        account_locked INTEGER DEFAULT 0,

        created_at TEXT,

        updated_at TEXT,

        last_login TEXT
    )
    """)


    cursor.execute("""
    CREATE TABLE IF NOT EXISTS otp_codes (

        otp_id INTEGER PRIMARY KEY AUTOINCREMENT,

        user_id INTEGER NOT NULL,

        otp_hash TEXT NOT NULL,

        otp_type TEXT NOT NULL,

        expires_at TEXT NOT NULL,

        attempt_count INTEGER DEFAULT 0,

        is_used INTEGER DEFAULT 0,

        created_at TEXT,

        FOREIGN KEY (user_id)
        REFERENCES users(user_id)
    )
    """)


    cursor.execute("""
    CREATE TABLE IF NOT EXISTS user_sessions (

        session_id INTEGER PRIMARY KEY AUTOINCREMENT,

        user_id INTEGER NOT NULL,

        jwt_id TEXT NOT NULL,

        ip_address TEXT,

        device_info TEXT,

        created_at TEXT,

        expires_at TEXT,

        FOREIGN KEY (user_id)
        REFERENCES users(user_id)
    )
    """)


    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (

        log_id INTEGER PRIMARY KEY AUTOINCREMENT,

        user_id INTEGER,

        event_type TEXT NOT NULL,

        description TEXT,

        ip_address TEXT,

        created_at TEXT,

        FOREIGN KEY (user_id)
        REFERENCES users(user_id)
    )
    """)


    cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_incidents (

        incident_id INTEGER PRIMARY KEY AUTOINCREMENT,

        user_id INTEGER,

        threat_type TEXT,

        risk_level TEXT,

        prompt_preview TEXT,

        action_taken TEXT,

        created_at TEXT,

        FOREIGN KEY (user_id)
        REFERENCES users(user_id)
    )
    """)


    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (

        alert_id INTEGER PRIMARY KEY AUTOINCREMENT,

        severity TEXT,

        reasons TEXT,

        action_taken TEXT,

        created_at TEXT
    )
    """)


    connection.commit()

    connection.close()


print(
    "ShieldAI Enterprise Database Ready"
)
