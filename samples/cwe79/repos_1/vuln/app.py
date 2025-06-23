from flask import Flask, render_template, request
from markupsafe import Markup

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def post():
    comment = ''
    if request.method == 'POST':
        raw = request.form['comment']
        # ✗ Vulnerability: wrap raw input in Markup() so Jinja2 will NOT escape it
        comment = Markup(raw)
    return render_template('post.html', comment=comment)

if __name__ == '__main__':
    # debug=True for convenience during development
    app.run(debug=True)
