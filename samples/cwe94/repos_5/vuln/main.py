#!/usr/bin/env python3
"""
Vulnerable Dynamic Function Evaluator
- Reads a Python expression from stdin
- Loads JSON from a file into a dict called json_data
- Compiles and executes the expression with full globals()
- **UNSAFE**: arbitrary code execution is permitted
"""

import sys
import os
import json
from types import FunctionType

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

    # -- compile & build a FunctionType with full globals --
    
    code = compile(expr, "<expr>", "eval")
    result = eval(code, globals(), json_data)
    print(result)
    
if __name__ == "__main__":
    main()
