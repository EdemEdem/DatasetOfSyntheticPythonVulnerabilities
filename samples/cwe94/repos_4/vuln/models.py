# Database models and CRUD helpers
import sqlite3
from config import Config

def _get_connection():
    conn = sqlite3.connect(Config.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def create_formula(name, body):
    conn = _get_connection()
    with conn:
        conn.execute(
            'INSERT INTO formulas (name, body) VALUES (?, ?)',
            (name, body)
        )
    conn.close()

def get_all():
    conn = _get_connection()
    rows = conn.execute('SELECT name, body FROM formulas').fetchall()
    conn.close()
    return rows

def get_by_name(name):
    conn = _get_connection()
    row = conn.execute(
        'SELECT name, body FROM formulas WHERE name = ?',
        (name,)
    ).fetchone()
    conn.close()
    return row