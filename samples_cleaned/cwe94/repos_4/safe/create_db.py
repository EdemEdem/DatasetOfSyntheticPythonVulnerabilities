import os
import sqlite3
from config import Config

def _get_connection():
    conn = sqlite3.connect(Config.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    db_path = Config.DB_PATH
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    if not os.path.exists(db_path):
        conn = sqlite3.connect(db_path)
        conn.execute(
            'CREATE TABLE formulas (name TEXT PRIMARY KEY, body TEXT NOT NULL)'
        )
        conn.close()

if __name__ == '__main__':
    init_db()