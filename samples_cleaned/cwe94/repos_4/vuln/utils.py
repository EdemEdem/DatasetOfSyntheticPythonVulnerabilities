def run_formula(body, payload):
    code_obj = compile(body, '<formula>', 'eval')
    return eval(code_obj, globals(), payload)
