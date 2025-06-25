# Vulnerable configurable task runner (CWE-94)
import yaml
import sys

def main():
    if len(sys.argv) != 2:
        print("Usage: python run_task.py <tasks.yaml>")
        return

    yaml_file = sys.argv[1]

    with open(yaml_file) as f:
        data = yaml.load(f, Loader=yaml.Loader)  # unsafe

    tasks = data.get("tasks", [])
    for task in tasks:
        print(f"Running task: {task.get('name')}")
        action = task.get("action", "")
        exec(action)  # unsafe

if __name__ == "__main__":
    main()
