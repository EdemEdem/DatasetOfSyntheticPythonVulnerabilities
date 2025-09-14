from flask import Flask, request, jsonify, abort
import sqlite3

app = Flask(__name__)
DB = 'blog.db'

def get_db():
    conn = sqlite3.connect(DB)
    return conn

with get_db() as conn:
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            body TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER,
            body TEXT,
            FOREIGN KEY(post_id) REFERENCES posts(id)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS secret_table (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            secret_text TEXT,
        )
    """)
    c.execute("""
        INSERT INTO secret_table (secret_text) VALUES
        ('Super Secret text: The eagle flies at dawn'),
        ('Super Secret text: Project X is greenlit'),
        ('Super Secret text: Password123!');
    """)
    conn.commit()

@app.route('/posts', methods=['GET'])
def list_posts():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, title, body FROM posts")
    posts = [{'id': row[0], 'title': row[1], 'body': row[2]} for row in c.fetchall()]
    return jsonify(posts)

@app.route('/posts', methods=['POST'])
def create_post():
    data = request.json or {}
    title = data.get('title', '')
    body = data.get('body', '')
    conn = get_db()
    c = conn.cursor()
   
    c.execute(
        "INSERT INTO posts (title, body) VALUES (?, ?)",
        (title, body)
    )
    conn.commit()
    return jsonify({'id': c.lastrowid}), 201

@app.route('/posts/<int:post_id>', methods=['DELETE'])
def delete_post(post_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM posts WHERE id = ?", (post_id,))
    conn.commit()
    return '', 204

@app.route('/posts/<int:post_id>/comments', methods=['GET'])
def list_comments(post_id):
    conn = get_db()
    c = conn.cursor()
    c.execute(
        "SELECT id, body FROM comments WHERE post_id = ?",
        (post_id,)
    )
    comments = [{'id': row[0], 'body': row[1]} for row in c.fetchall()]
    return jsonify(comments)

@app.route('/posts/<int:post_id>/comments', methods=['POST'])
def create_comment(post_id):
    data = request.json or {}
    body = data.get('body', '')
    conn = get_db()
    c = conn.cursor()
    c.execute(
        "INSERT INTO comments (post_id, body) VALUES (?, ?)",
        (post_id, body)
    )
    conn.commit()
    return jsonify({'id': c.lastrowid}), 201

@app.route('/comments/<int:comment_id>', methods=['DELETE'])
def delete_comment(comment_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM comments WHERE id = ?", (comment_id,))
    conn.commit()
    return '', 204

if __name__ == '__main__':
    app.run()
