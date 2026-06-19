import sqlite3


DATABASE_NAME = "shieldai.db"


def get_database_connection():

    connection = sqlite3.connect(
        DATABASE_NAME
    )

    return connection


def initialize_database():

    connection = get_database_connection()

    cursor = connection.cursor()


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


    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        severity TEXT,
        reasons TEXT,
        action_taken TEXT
    )
    """)


    connection.commit()

    connection.close()
