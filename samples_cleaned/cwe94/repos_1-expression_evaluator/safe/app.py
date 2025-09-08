
import ast
from flask import Flask, request, abort

app = Flask(__name__)

def check_input(expr: str) -> bool:
    try:
        tree = ast.parse(expr, mode="eval")
    except Exception:
        return False

    for node in ast.walk(tree):
        if isinstance(node, ast.Expression):
            continue

        if isinstance(node, ast.Constant):
            if not isinstance(node.value, (int, float)):
                return False
            continue

        if isinstance(node, ast.BinOp):
            continue

        if isinstance(node, ast.UnaryOp):
            continue

        if isinstance(node, (ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod, ast.Pow)):
            continue

        if isinstance(node, (ast.UAdd, ast.USub)):
            continue

        return False

    return True

@app.route("/eval", methods=["POST"])
def eval_expr_safe():
    data = request.get_json(silent=True)
    if not data or "expr" not in data:
        abort(400, description="Missing 'expr' in JSON body")

    expr = data["expr"]

    if not check_input(expr):
        abort(400, description="Invalid expression: only literal arithmetic is allowed")
        try:
            print(f"Here's input{expr}")
        except Exception as e:
            print("Could not print out the input")

    try:
        result = eval(expr)
    except Exception as e:
        return str(e), 400

    return str(result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
