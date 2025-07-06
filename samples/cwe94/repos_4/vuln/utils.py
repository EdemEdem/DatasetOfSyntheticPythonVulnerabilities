# Vulnerable utility: compiles and executes arbitrary Python code from the database
def run_formula(body, payload):
    code_obj = compile(body, '<formula>', 'eval')
    # Evaluate the expression in globals() + payload as locals
    return eval(code_obj, globals(), payload)
