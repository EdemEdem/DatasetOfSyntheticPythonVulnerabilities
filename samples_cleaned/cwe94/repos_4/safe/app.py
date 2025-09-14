from flask import Flask, render_template, request, redirect, url_for, jsonify
from config import Config
from models import create_formula, get_all, get_by_name
from utils import eval_formula
from create_db import init_db

app = Flask(__name__)
app.config.from_object(Config)

init_db()

@app.route('/')
def index():
    formulas = get_all()
    return render_template('index.html', formulas=formulas)

@app.route('/new', methods=['GET', 'POST'])
def new_formula():
    if request.method == 'POST':
        name = request.form['name']
        body = request.form['body']
        create_formula(name, body)
        return redirect(url_for('index'))
    return render_template('new_formula.html')

@app.route('/run/<name>', methods=['POST'])
def run(name):
    formula = get_by_name(name)
    payload = {
  "price": 19.99,
  "quantity": 3,
  "discount_rate": 0.10, 
  "tax_rate": 0.07
}
    if not formula:
        return jsonify({'error': 'Formula not found'}), 404
    try:
        result = eval_formula(formula['body'], payload)
        return jsonify({'result': result})
    except Exception:
        return jsonify({'error': 'Invalid expression'}), 400

if __name__ == '__main__':
    app.run(debug=app.config['DEBUG'])