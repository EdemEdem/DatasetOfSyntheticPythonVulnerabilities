# Safe configurable task runner (hardened against CWE-94)
# Uses yaml.safe_load and restricts to allowed actions

import yaml

# Define allowed actions as functions
def cleanup():
    print("Cleaning up...")

def greet():
    print("Hello World!")

def add():
    result = 3 + 4
    print("Sum:", result)

# Map allowed action names to functions
ALLOWED_ACTIONS = {
    "cleanup": cleanup,
    "greet": greet,
    "add": add,
}

def main():
    with open("tasks.yaml") as f:
        try:
            data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            print(f"YAML error: {e}")
            return
    
    tasks = data.get("tasks", [])
    
    for task in tasks:
        print(f"Running task: {task.get('name')}")
        action_name = task.get("name")
        
        # Only allow predefined actions
        func = ALLOWED_ACTIONS.get(action_name)
        if func:
            func()
        else:
            print(f"Rejected action: {action_name}")

if __name__ == "__main__":
    main()
