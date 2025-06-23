from bottle import Bottle, run, request, redirect
import sqlite3

# ─── Database setup ────────────────────────────────────────────────────────────
# Uses a file-based SQLite DB called forum.db
conn = sqlite3.connect('forum.db', check_same_thread=False)
cur = conn.cursor()
# Create posts table if it doesn't exist
cur.execute(
    'CREATE TABLE IF NOT EXISTS posts ('
    '  id INTEGER PRIMARY KEY AUTOINCREMENT,'
    '  content TEXT'
    ')'
)
conn.commit()

app = Bottle()

# ─── Routes ────────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    # Minimal HTML form for posting and searching
    return '''
    <h1>Simple Forum (Vulnerable)</h1>
    <form action="/post" method="post">
      <input name="content" placeholder="Write something…" />
      <input type="submit" value="Post" />
    </form>
    <form action="/search" method="get">
      <input name="q" placeholder="Search…" />
      <input type="submit" value="Search" />
    </form>
    '''

@app.post('/post')
def post():
    content = request.forms.get('content') or ''
    # ⚠️ VULNERABLE to SQL injection via string concatenation
    sql = "INSERT INTO posts (content) VALUES ('%s')" % content
    cur.execute(sql)
    conn.commit()
    return redirect('/')

@app.get('/search')
def search():
    q = request.query.get('q') or ''
    # ⚠️ VULNERABLE: user-controlled q injected into SQL
    sql = "SELECT id, content FROM posts WHERE content LIKE '%%%s%%'" % q
    cur.execute(sql)
    rows = cur.fetchall()
    # Render results
    if not rows:
        return '<p>No results</p>'
    return ''.join(f'<p>{rid}: {txt}</p>' for rid, txt in rows)

if __name__ == '__main__':
    run(app, host='localhost', port=8080, debug=True)
