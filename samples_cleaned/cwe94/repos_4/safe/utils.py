import ast
import math

ALLOWED_NODES = (
    ast.Expression, ast.BinOp, ast.UnaryOp, ast.Constant,
    ast.Name, ast.Load, ast.Add, ast.Sub, ast.Mult,
    ast.Div, ast.Pow, ast.Mod, ast.Call, ast.Attribute,
)

ALLOWED_MATH_FUNCS = set(dir(math))

class FormulaSanitizer(ast.NodeVisitor):
    def visit(self, node):
        if not isinstance(node, ALLOWED_NODES):
            raise ValueError(f"Disallowed expression: {type(node).__name__}")
        return super().visit(node)

    def visit_Call(self, node):
        if isinstance(node.func, ast.Attribute):
            if (isinstance(node.func.value, ast.Name)
               and node.func.value.id == 'math'
               and node.func.attr in ALLOWED_MATH_FUNCS):
                for arg in node.args:
                    self.visit(arg)
                return
        raise ValueError(f"Invalid function call: {ast.dump(node)}")

    def generic_visit(self, node):
        super().generic_visit(node)


def eval_formula(expr, payload):
    tree = ast.parse(expr, mode='eval')
    FormulaSanitizer().visit(tree)
    compiled = compile(tree, '<formula>', 'eval')
    s_globals = {'__builtins__': None, 'math': math}
    return eval(compiled, s_globals, payload)