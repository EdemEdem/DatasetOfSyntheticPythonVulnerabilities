import sqlite3
from werkzeug.security import generate_password_hash

def init_db():
    """
    Initialize a sqlite3 database 'users.db' with a 'users' table.
    Populate with 10 users (2 admins) if not already present.
    """
    db_path = 'users.db'
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    # Create table if it doesn't exist
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER NOT NULL
        )
    ''')
    conn.commit()

    # Check counts
    c.execute('SELECT COUNT(*) FROM users')
    user_count = c.fetchone()[0]
    c.execute('SELECT COUNT(*) FROM users WHERE is_admin = 1')
    admin_count = c.fetchone()[0]

    # Populate only if too few users/admins
    if user_count < 2 or admin_count < 1:
        c.execute('DELETE FROM users')  # start fresh
        users = []
        for i in range(1, 11):
            username = f'user{i}'
            password = f'pass{i}'
            # store hashed passwords
            pw_hash = generate_password_hash(password)
            is_admin = 1 if i <= 2 else 0
            users.append((username, pw_hash, is_admin))
        c.executemany(
            'INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)',
            users
        )
        conn.commit()

    conn.close()
