# app.py (VULNERABLE VERSION)
# Python 3.12, Flask-based minimal web app that naïvely evals anything.

from flask import Flask, request, abort

app = Flask(__name__)

@app.route("/eval", methods=["POST"])
def eval_expr():
    """
    Vulnerable endpoint: takes a JSON body {"expr": "..."} and does a raw eval.
    WARNING: This will execute any Python code sent in "expr".
    """
    data = request.get_json(silent=True)
    if not data or "expr" not in data:
        # Bad request if JSON is missing or "expr" key not present
        abort(400, description="Missing 'expr' in JSON body")
    
    expr = data["expr"]
    try:
        # <-- THIS IS UNSAFE: will execute arbitrary code!
        result = eval(expr)
    except Exception as e:
        # If eval itself raises (e.g. syntax error), return 400 with error message
        return str(e), 400

    # Return the raw result as a string (e.g. "4" for expr="2+2")
    return str(result)

if __name__ == "__main__":
    # Run on port 5000 by default
    app.run(host="0.0.0.0", port=5000, debug=True)
