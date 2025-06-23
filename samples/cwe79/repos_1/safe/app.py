from flask import Flask, render_template, request
# Option A: rely on Jinja2's autoescaping (default)
# Option B: explicit escape
from markupsafe import escape

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def post():
    comment = ''
    if request.method == 'POST':
        raw = request.form['comment']
        # ✓ Safe: either rely on autoescaping below, or explicitly:
        comment = escape(raw)
    return render_template('post.html', comment=comment)

if __name__ == '__main__':
    app.run(debug=True)
