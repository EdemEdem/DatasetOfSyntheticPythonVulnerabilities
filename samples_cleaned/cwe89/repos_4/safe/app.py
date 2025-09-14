from flask import Flask, request, render_template
import sqlite3
from werkzeug.security import check_password_hash
import init_database

app = Flask(__name__)

init_database.init_db()

@app.route('/')
def login():
    return render_template('login.html')

@app.route('/process_login', methods=['POST'])
def process_login():
    username = request.form['username']
    password = request.form['password']

    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    try:
        cursor.execute(
            "SELECT id, password_hash, is_admin FROM users WHERE username = ?",
            (username,)
        )
        row = cursor.fetchone()
    except Exception:
        conn.close()
        return "An error occurred. Please try again later.", 500

    conn.close()

    if row and check_password_hash(row['password_hash'], password):
        return f"Welcome, {username}! Admin: {bool(row['is_admin'])}"
    else:
        return "Invalid credentials", 401

if __name__ == '__main__':
    app.run(debug=True)
