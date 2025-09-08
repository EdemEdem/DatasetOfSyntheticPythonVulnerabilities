import os
import shutil
import ast

SOURCE_DIR = "./samples"
TARGET_DIR = "./cleaned_samples"


def find_docstring_lines(source_code):
    """Return set of line numbers (0-based) that are real docstrings."""
    docstring_lines = set()
    try:
        tree = ast.parse(source_code)
    except SyntaxError:
        return docstring_lines  # skip files with syntax errors

    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            doc = ast.get_docstring(node, clean=False)
            if doc and hasattr(node, "body") and node.body:
                expr = node.body[0]
                if (
                    isinstance(expr, ast.Expr)
                    and isinstance(expr.value, ast.Constant)
                    and isinstance(expr.value.value, str)
                ):
                    start = expr.lineno - 1  # ast is 1-based
                    end = expr.end_lineno
                    docstring_lines.update(range(start, end))
    return docstring_lines


def clean_file(source_path, target_path):
    with open(source_path, "r", encoding="utf-8") as f:
        source_code = f.read()

    docstring_lines = find_docstring_lines(source_code)
    cleaned_lines = []

    for i, line in enumerate(source_code.splitlines()):
        stripped = line.strip()

        # Skip shebangs
        if i == 0 and stripped.startswith("#!"):
            continue

        # Skip full-line comments
        if stripped.startswith("#"):
            continue

        # Skip docstring lines
        if i in docstring_lines:
            continue

        cleaned_lines.append(line)

    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    with open(target_path, "w", encoding="utf-8") as f:
        f.write("\n".join(cleaned_lines))


def copy_and_clean(source_dir=SOURCE_DIR, target_dir=TARGET_DIR):
    if os.path.exists(target_dir):
        shutil.rmtree(target_dir)
    os.makedirs(target_dir)

    for root, _, files in os.walk(source_dir):
        for filename in files:
            if filename.endswith(".py"):
                source_path = os.path.join(root, filename)
                relative_path = os.path.relpath(source_path, source_dir)
                target_path = os.path.join(target_dir, relative_path)
                clean_file(source_path, target_path)
            else:
                # copy non-Python files unchanged
                source_path = os.path.join(root, filename)
                relative_path = os.path.relpath(source_path, source_dir)
                target_path = os.path.join(target_dir, relative_path)
                os.makedirs(os.path.dirname(target_path), exist_ok=True)
                shutil.copy2(source_path, target_path)


if __name__ == "__main__":
    copy_and_clean()
    print(f"✅ Cleaned samples written to '{TARGET_DIR}'")
