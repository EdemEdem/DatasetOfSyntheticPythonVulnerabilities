from flask import Flask, request, jsonify, abort
import sqlite3

app = Flask(__name__)
DB = 'blog.db'

def get_db():
    conn = sqlite3.connect(DB)
    return conn

# Initialize tables
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

# List posts
@app.route('/posts', methods=['GET'])
def list_posts():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, title, body FROM posts")
    posts = [{'id': row[0], 'title': row[1], 'body': row[2]} for row in c.fetchall()]
    return jsonify(posts)

# Create post (VULNERABLE: f-string SQL)
@app.route('/posts', methods=['POST'])
def create_post():
    data = request.json or {}
    title = data.get('title', '')
    body = data.get('body', '')
    conn = get_db()
    c = conn.cursor()
    # **Danger:** unsanitized input in SQL
    sql = f"INSERT INTO posts (title, body) VALUES ('{title}', '{body}')"
    print(sql)
    c.execute(sql)
    conn.commit()
    return jsonify({'id': c.lastrowid}), 201

# Delete post
@app.route('/posts/<int:post_id>', methods=['DELETE'])
def delete_post(post_id):
    conn = get_db()
    c = conn.cursor()
    # **Danger:** direct interpolation of post_id
    c.execute(f"DELETE FROM posts WHERE id = {post_id}")
    conn.commit()
    return '', 204

# List comments for a post
@app.route('/posts/<int:post_id>/comments', methods=['GET'])
def list_comments(post_id):
    conn = get_db()
    c = conn.cursor()
    c.execute(f"SELECT id, body FROM comments WHERE post_id = {post_id}")
    comments = [{'id': row[0], 'body': row[1]} for row in c.fetchall()]
    return jsonify(comments)

# Create comment (VULNERABLE)
@app.route('/posts/<int:post_id>/comments', methods=['POST'])
def create_comment(post_id):
    data = request.json or {}
    body = data.get('body', '')
    conn = get_db()
    c = conn.cursor()
    c.execute(f"INSERT INTO comments (post_id, body) VALUES ({post_id}, '{body}')")
    conn.commit()
    return jsonify({'id': c.lastrowid}), 201

# Delete comment
@app.route('/comments/<int:comment_id>', methods=['DELETE'])
def delete_comment(comment_id):
    conn = get_db()
    c = conn.cursor()
    c.execute(f"DELETE FROM comments WHERE id = {comment_id}")
    conn.commit()
    return '', 204

if __name__ == '__main__':
    app.run(debug=True)
