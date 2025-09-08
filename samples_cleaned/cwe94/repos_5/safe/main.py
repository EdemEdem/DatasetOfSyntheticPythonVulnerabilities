
import sys
import os
import json
import ast

class SEvaluator(ast.NodeVisitor):
    ALLOWED_NODES = (
        ast.Expression,
        ast.BinOp, ast.UnaryOp, ast.BoolOp, ast.Compare,
        ast.Call,
        ast.Name, ast.Constant, ast.Attribute, ast.Subscript,
        ast.Load,
        ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod, ast.Pow,
        ast.UAdd, ast.USub,
        ast.And, ast.Or, ast.Not,
        ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.Is, ast.IsNot,
        ast.Index, ast.Slice,
    )

    def generic_visit(self, node):
        if not isinstance(node, self.ALLOWED_NODES):
            raise ValueError(f"Disallowed expression: {node.__class__.__name__}")
        super().generic_visit(node)

    def visit_Call(self, node: ast.Call):
        if not isinstance(node.func, ast.Attribute):
            raise ValueError(f"Disallowed call type: {node.func.__class__.__name__}")
        self.generic_visit(node)

def main():
    script_path = os.path.abspath(__file__)
    script_dir = os.path.dirname(script_path)
    data_dir = "json_data_files"
    file_path = os.path.join(script_dir,data_dir, "data.json")
    if not os.path.isfile(file_path):
        print(f"{file_path} dosen't exists")
        sys.exit(1)

    with open(file_path, "r") as f:
        json_data = json.load(f)

    expr = input("Enter expression: ")

    try:
        tree = ast.parse(expr, mode="eval")
        SEvaluator().visit(tree)
    except (SyntaxError, ValueError) as e:
        print(f"Error: {e}")
        return

    code = compile(tree, "<expr>", "eval")

    try:
        result = eval(code, {"__builtins__": None}, json_data)
    except Exception as e:
        print(f"Error during evaluation: {e}")
        return

    print(result)

if __name__ == "__main__":
    main()
