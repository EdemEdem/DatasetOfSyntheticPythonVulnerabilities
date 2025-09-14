from bottle import Bottle, run, request, redirect
import sqlite3

conn = sqlite3.connect('forum.db', check_same_thread=False)
cur = conn.cursor()
cur.execute(
    'CREATE TABLE IF NOT EXISTS posts ('
    '  id INTEGER PRIMARY KEY AUTOINCREMENT,'
    '  content TEXT'
    ')'
)
cur.execute(
    'CREATE TABLE IF NOT EXISTS users ('
    '  id INTEGER PRIMARY KEY AUTOINCREMENT,'
    '  username TEXT,'
    '  password TEXT'
    ')'
)
cur.execute("SELECT COUNT(*) FROM users;")
count = cur.fetchone()[0]
if count == 0:
    print("Populating 'users' with sample data.")
    samples = [
            ('alice', 'supersecret_password'),
            ('bob', 'bob123'),
            ('charlie', 'Unhackable'),
        ]
    for username, password in samples:
        cur.execute(
            "INSERT INTO users (username, password) VALUES (?, ?);",
            (username, password)
        )
conn.commit()

app = Bottle()

@app.route('/')
def index():
    return '''
    <h1>Simple Forum </h1>
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
    sql = "INSERT INTO posts (content) VALUES ('%s')" % content
    cur.execute(sql)
    conn.commit()
    return redirect('/')

@app.get('/search')
def search():
    q = request.query.get('q') or ''
    sql = "SELECT id, content FROM posts WHERE content LIKE '%%%s%%'" % q
    cur.execute(sql)
    rows = cur.fetchall()
    
    if not rows:
        return '<p>No results</p>'
    return ''.join(f'<p>{rid}: {txt}</p>' for rid, txt in rows)

if __name__ == '__main__':
    run(app, host='localhost', port=8080, debug=True)
