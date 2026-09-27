import os
import sqlite3
from importlib import import_module

try:
    psycopg2 = import_module("psycopg2")
except ImportError:
    psycopg2 = None

DB_CONFIG = {
    "dbname": os.getenv("POSTGRES_DB", "fraud_detector_db"),
    "user": os.getenv("POSTGRES_USER", "postgres"),
    "password": os.getenv("POSTGRES_PASSWORD", ""),
    "host": os.getenv("POSTGRES_HOST", "localhost"),
    "port": os.getenv("POSTGRES_PORT", "5432"),
}

DB_PATH = os.getenv("DB_PATH", "fraud_detector.sqlite3")


def _sqlite_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            input_type TEXT NOT NULL,
            input_value TEXT NOT NULL,
            status TEXT NOT NULL,
            details TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    return connection

def save_scan(input_type, input_value, status, details):
    database_url = os.getenv("DATABASE_URL")
    if database_url and not database_url.startswith(("postgresql://", "postgres://")):
        database_url = None

    if not database_url:
        with _sqlite_connection() as conn:
            conn.execute(
                "INSERT INTO scan_history (input_type, input_value, status, details) VALUES (?, ?, ?, ?)",
                (input_type, input_value, status, details),
            )
        return

    if psycopg2 is None:
        raise RuntimeError("DATABASE_URL is set, but psycopg2-binary is not installed.")

    conn = None
    cur = None
    try:
        conn = psycopg2.connect(database_url) if database_url else psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id SERIAL PRIMARY KEY,
                input_type VARCHAR(20) NOT NULL,
                input_value TEXT NOT NULL,
                status VARCHAR(50) NOT NULL,
                details TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        query = "INSERT INTO scan_history (input_type, input_value, status, details) VALUES (%s, %s, %s, %s);"
        cur.execute(query, (input_type, input_value, status, details))
        conn.commit()
    except Exception as e:
        if conn:
            conn.rollback()
        raise RuntimeError(f"Database error: {e}") from e
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()