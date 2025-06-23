# flask_ping_vulnerable/app.py
from flask import Flask, request, render_template
import os

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def ping():
    result = None
    if request.method == 'POST':
        host = request.form['host']
        # WARNING: Directly interpolating user input into shell command!
        cmd = f"ping {host}"
        # This will invoke a shell; any appended commands will execute too.
        result = os.popen(cmd).read()
    return render_template('ping.html', result=result)

if __name__ == '__main__':
    # For simplicity; do not use in production
    app.run(debug=True)
