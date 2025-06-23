# app.py (SAFE VERSION)
# Python 3.12, Flask-based minimal web app that only allows literal arithmetic.

import ast
from flask import Flask, request, abort

app = Flask(__name__)

def check_input(expr: str) -> bool:
    """
    Parse the expression with `ast.parse(..., mode="eval")` and walk the AST,
    allowing only literal arithmetic: 
      - numeric constants (int, float)
      - binary operations (+, -, *, /, %, **)
      - unary operations (unary + and -)
    Any other node is rejected.
    """
    try:
        # Parse in “eval” mode so that it must be a single expression
        tree = ast.parse(expr, mode="eval")
    except Exception:
        return False

    # Walk all nodes to ensure they are of allowed types
    for node in ast.walk(tree):
        # Allowed top-level container
        if isinstance(node, ast.Expression):
            continue

        # Allowed: numeric literal
        if isinstance(node, ast.Constant):
            # In Python 3.12, ast.Constant holds numbers, strings, etc.
            if not isinstance(node.value, (int, float)):
                return False
            continue

        # Allowed: binary arithmetic, e.g. 2 + 3
        if isinstance(node, ast.BinOp):
            continue

        # Allowed: unary arithmetic, e.g. -5 or +7
        if isinstance(node, ast.UnaryOp):
            continue

        # Allowed operators: +, -, *, /, %, **
        if isinstance(node, (ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod, ast.Pow)):
            continue

        # Allowed unary operators: +x, -x
        if isinstance(node, (ast.UAdd, ast.USub)):
            continue

        # Anything else (names, calls, attributes, imports, etc.) → reject
        return False

    return True

@app.route("/eval", methods=["POST"])
def eval_expr_safe():
    """
    Safe endpoint: takes JSON {"expr": "..."} and first verifies
    via check_input(...) that it's only literal arithmetic. 
    Otherwise, return HTTP 400.
    """
    data = request.get_json(silent=True)
    if not data or "expr" not in data:
        abort(400, description="Missing 'expr' in JSON body")

    expr = data["expr"]

    if not check_input(expr):
        # Reject any expression that doesn’t pass the AST whitelist
        abort(400, description="Invalid expression: only literal arithmetic is allowed")
        try:
            print(f"Here's input{expr}")
        except Exception as e:
            print("Could not print out the input")

    try:
        # At this point, expr is known to contain only numeric literals and +, -, *, /, %, **
        result = eval(expr)
    except Exception as e:
        # If something unexpected happens during eval (e.g. division by zero)
        return str(e), 400

    return str(result)

if __name__ == "__main__":
    # Run on port 5000 by default
    app.run(host="0.0.0.0", port=5000, debug=True)
