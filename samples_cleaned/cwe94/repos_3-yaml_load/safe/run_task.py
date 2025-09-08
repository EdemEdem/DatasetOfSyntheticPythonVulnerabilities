import yaml
import sys

def cleanup():
    print("Cleaning up...")

def greet():
    print("Hello World!")

def add():
    result = 3 + 4
    print("Sum:", result)

ALLOWED_ACTIONS = {
    "cleanup": cleanup,
    "greet": greet,
    "add": add,
}

def main():
    if len(sys.argv) != 2:
        print("Usage: python run_task.py <tasks.yaml>")
        return

    yaml_file = sys.argv[1]

    try:
        with open(yaml_file) as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        print(f"YAML error: {e}")
        return

    tasks = data.get("tasks", [])
    for task in tasks:
        print(f"Running task: {task.get('name')}")
        action_name = task.get("name")
        func = ALLOWED_ACTIONS.get(action_name)
        if func:
            func()
        else:
            print(f"Rejected action: {action_name}")

if __name__ == "__main__":
    main()
