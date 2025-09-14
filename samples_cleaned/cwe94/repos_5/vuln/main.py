
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


    with open(file_path, "r") as f:
        json_data = json.load(f)

    expr = input("Enter expression: ")

    
    code = compile(expr, "<expr>", "eval")
    result = eval(code, globals(), json_data)
    print(result)
    
if __name__ == "__main__":
    main()
