
from flask import Flask, request, abort

app = Flask(__name__)

@app.route("/eval", methods=["POST"])
def eval_expr():
    data = request.get_json(silent=True)
    if not data or "expr" not in data:
        abort(400, description="Missing 'expr' in JSON body")
    
    expr = data["expr"]
    try:
        result = eval(expr)
    except Exception as e:
        return str(e), 400

    return str(result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
