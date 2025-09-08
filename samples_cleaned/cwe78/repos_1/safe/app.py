from flask import Flask, request, render_template, flash
import re
import subprocess

app = Flask(__name__)
app.secret_key = 'replace-with-random-secret'

HOST_REGEX = re.compile(r'^[A-Za-z0-9\.\-]+$')

@app.route('/', methods=['GET', 'POST'])
def ping():
    result = None
    if request.method == 'POST':
        host = request.form['host'].strip()
        if not HOST_REGEX.fullmatch(host):
            flash('Invalid host format. Only letters, numbers, dots, and hyphens are allowed.')
        else:
            try:
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
    app.run(debug=False)
