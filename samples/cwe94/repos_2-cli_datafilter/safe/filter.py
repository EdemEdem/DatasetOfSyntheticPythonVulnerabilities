import argparse
import pandas as pd
import ast

class SafeEval(ast.NodeVisitor):
    ALLOWED_NODES = (
        ast.Expression, ast.BoolOp, ast.BinOp, ast.UnaryOp,
        ast.Compare, ast.Name, ast.Load,
        ast.Call, ast.Constant, ast.And, ast.Or, ast.Not,
        ast.Gt, ast.Lt, ast.GtE, ast.LtE, ast.Eq, ast.NotEq
    )

    ALLOWED_FUNCS = {'startswith'}

    def __init__(self, allowed_names):
        self.allowed_names = allowed_names

    def visit(self, node):
        if not isinstance(node, self.ALLOWED_NODES):
            raise ValueError(f"Disallowed expression: {ast.dump(node)}")
        return super().visit(node)

    def visit_Name(self, node):
        if node.id not in self.allowed_names:
            raise ValueError(f"Unknown variable: {node.id}")

    def visit_Call(self, node):
        if not isinstance(node.func, ast.Attribute):
            raise ValueError("Only attribute calls allowed")
        if node.func.attr not in self.ALLOWED_FUNCS:
            raise ValueError(f"Function {node.func.attr} not allowed")
        self.generic_visit(node)

def safe_eval(expr, namespace):
    try:
        tree = ast.parse(expr, mode="eval")
        se = SafeEval(allowed_names=namespace.keys())
        se.visit(tree)
        code = compile(tree, "<string>", "eval")
        return eval(code, {}, namespace)
    except Exception as e:
        raise ValueError(f"Unsafe expression: {e}")

def main():
    parser = argparse.ArgumentParser(description="Safe CLI data filter tool")
    parser.add_argument("--csv", required=True, help="Input CSV file")
    parser.add_argument("--filter", required=True, help="Safe filter expression")
    args = parser.parse_args()

    df = pd.read_csv(args.csv)

    for _, row in df.iterrows():
        namespace = {col: row[col] for col in df.columns}
        try:
            if safe_eval(args.filter, namespace):
                print(','.join(str(namespace[col]) for col in df.columns))
        except Exception as e:
            print(f"Invalid filter: {e}")

if __name__ == "__main__":
    main()
