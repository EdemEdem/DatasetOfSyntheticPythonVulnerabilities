from flask import Flask, request, render_template
import os

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def ping():
    result = None
    if request.method == 'POST':
        host = request.form['host']
        cmd = f"ping {host}"
        result = os.popen(cmd).read()
    return render_template('ping.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)
