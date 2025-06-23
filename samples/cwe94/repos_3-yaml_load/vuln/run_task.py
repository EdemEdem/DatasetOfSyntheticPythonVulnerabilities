# Vulnerable configurable task runner (CWE-94)
# Uses yaml.load without Loader + exec to run arbitrary code

import yaml

def main():
    # Read YAML tasks from file
    with open("tasks.yaml") as f:
        # Vulnerable yaml.load without safe loader
        data = yaml.load(f, Loader=yaml.Loader)
    
    tasks = data.get("tasks", [])
    
    for task in tasks:
        print(f"Running task: {task.get('name')}")
        action = task.get("action", "")
        # Directly executes arbitrary Python code
        exec(action)

if __name__ == "__main__":
    main()
