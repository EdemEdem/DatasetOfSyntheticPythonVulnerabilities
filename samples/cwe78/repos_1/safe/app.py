# flask_ping_safe/app.py
from flask import Flask, request, render_template, flash
import re
import subprocess

app = Flask(__name__)
app.secret_key = 'replace-with-random-secret'

# Strict regex allowing only letters, digits, dots, and dashes
HOST_REGEX = re.compile(r'^[A-Za-z0-9\.\-]+$')

@app.route('/', methods=['GET', 'POST'])
def ping():
    result = None
    if request.method == 'POST':
        host = request.form['host'].strip()
        # Validate against strict pattern
        if not HOST_REGEX.fullmatch(host):
            flash('Invalid host format. Only letters, numbers, dots, and hyphens are allowed.')
        else:
            try:
                # Use a list of args to avoid shell interpretation
                completed = subprocess.run(
                    ["ping",  host],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True
                )
                result = completed.stdout
            except subprocess.CalledProcessError as e:
                result = f"Ping failed:\n{e.stdout}"
    return render_template('ping.html', result=result)

if __name__ == '__main__':
    # For simplicity; do not use in production
    app.run(debug=False)
