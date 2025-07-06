#!/usr/bin/env python3
"""
Safe Dynamic Function Evaluator
- Reads a Python expression from stdin
- Loads JSON from a file into a dict called json_data
- Parses expression AST and only allows a tight whitelist of nodes
- Compiles and evals with NO builtins and only json_data as locals
- Rejects anything outside simple arithmetic, comparisons, attribute‐calls, etc.
"""

import sys
import os
import json
import ast

class SafeEvaluator(ast.NodeVisitor):
    # only these AST node types are allowed
    ALLOWED_NODES = (
        ast.Expression,
        ast.BinOp, ast.UnaryOp, ast.BoolOp, ast.Compare,
        ast.Call,
        ast.Name, ast.Constant, ast.Attribute, ast.Subscript,
        ast.Load,
        # operators
        ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod, ast.Pow,
        ast.UAdd, ast.USub,
        ast.And, ast.Or, ast.Not,
        # comparison ops
        ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.Is, ast.IsNot,
        # slicing/indexing
        ast.Index, ast.Slice,
    )

    def generic_visit(self, node):
        if not isinstance(node, self.ALLOWED_NODES):
            raise ValueError(f"Disallowed expression: {node.__class__.__name__}")
        super().generic_visit(node)

    def visit_Call(self, node: ast.Call):
        # only allow attribute calls (e.g. data["x"].upper()), not bare functions
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

    # -- load JSON from the given file into our dict --
    with open(file_path, "r") as f:
        json_data = json.load(f)

    # -- prompt for the expression to evaluate --
    expr = input("Enter expression: ")

    # -- parse & sanitize the AST --
    try:
        tree = ast.parse(expr, mode="eval")
        SafeEvaluator().visit(tree)
    except (SyntaxError, ValueError) as e:
        print(f"Error: {e}")
        return

    # -- compile sanitized AST --
    code = compile(tree, "<expr>", "eval")

    # -- eval with NO builtins, only json_data as locals --
    try:
        result = eval(code, {"__builtins__": None}, json_data)
    except Exception as e:
        print(f"Error during evaluation: {e}")
        return

    # -- print the (safe) result --
    print(result)

if __name__ == "__main__":
    main()
