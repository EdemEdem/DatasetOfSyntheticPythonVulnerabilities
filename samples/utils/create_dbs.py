#!/usr/bin/env python3

import os
import subprocess
import sys
import argparse

# ─── CONFIG ────────────────────────────────────────────────────────────────────
script_path = os.path.abspath(__file__)
script_dir = os.path.dirname(script_path)
samples_dir = os.path.dirname(script_dir)
PROJECTS_ROOT = samples_dir
DB_ROOT       = os.path.join(os.path.dirname(PROJECTS_ROOT),"cql_dbs")
LANGUAGE      = "python"
IGNORE_PROJECTS = [""]
# ───────────────────────────────────────────────────────────────────────────────


def run(cmd, cwd=None):
    """Run a shell command and exit on failure."""
    print(f"$ {' '.join(cmd)}")
    subprocess.run(cmd, cwd=cwd, check=True)


def ensure_dir(path):
    os.makedirs(path, exist_ok=True)

def normalize(path):
    return os.path.normpath(path)

#Create the db based on the project directory
def create_db(project_dir, cwe, state):
    """
    Create a CodeQL DB for a given project state ('safe' or 'vuln').
    """
    project_name = project_dir.split("_",1)[-1]
    src_version_dir = f"{state}_{project_name}"
    src = normalize(os.path.join(PROJECTS_ROOT, cwe, project_dir, src_version_dir))
    
    src_version2 = f"{state}"
    src_in_fromat2 = normalize(os.path.join(PROJECTS_ROOT,cwe, project_dir, src_version2))
    if os.path.isdir(src_in_fromat2):
        print(f"Expected to find: {src}")
        print(f"But instead found: {src_in_fromat2}")
        print(f"Createing database on {src_in_fromat2}")
        src = src_in_fromat2
    if not os.path.isdir(src):
        print(f"Warning: source directory not found: neither {src}, nor on{src_in_fromat2} skipping.")
        return
    
    
    db_dir = normalize(os.path.join(DB_ROOT, cwe,f"dbs_{project_name}/{state}-db"))
    if os.path.isdir(db_dir):
        print(f"→ CodeQL DB already exists: {db_dir}, skipping.")
        return
    
    os.makedirs(normalize(os.path.join(DB_ROOT, cwe, f"dbs_{project_name}")), exist_ok=True)

    ensure_dir(DB_ROOT)
    cmd = [
        "codeql", "database", "create",
        f"--language={LANGUAGE}",
        f"--source-root={src}",
        f"{db_dir}"
    ]
    run(cmd)


def create_dbs_for_cwe(cwe):
    projects_dir = normalize(os.path.join(PROJECTS_ROOT, cwe))
    if not os.path.isdir(projects_dir):
        print(f"Error: PROJECTS_ROOT not found: {projects_dir}", file=sys.stderr)
        sys.exit(1)

    # Iterate all repo directories
    for project in os.listdir(projects_dir):
        full_path = normalize(os.path.join(projects_dir, project))
        if not os.path.isdir(full_path):
            print(f"{full_path} is not a directory")
            continue
        
        if project in IGNORE_PROJECTS:
            print(f"{full_path} was found, but I've been told to ignore this project")
            continue

        print(f"\n=== Project: {project} ===")
        # safe and vuln states
        create_db(project, cwe, "safe")
        create_db(project, cwe, "vuln")

    print("\nAll done.")

def create_one():
    if not os.path.isdir(PROJECTS_ROOT):
        print(f"Error: PROJECTS_ROOT not found: {PROJECTS_ROOT}", file=sys.stderr)
        sys.exit(1)
        
    project_dir = "repos_expression_evaluator"
    cwe = "cwe94"

    full_path = normalize(os.path.join(PROJECTS_ROOT, cwe, project_dir))
    if not os.path.isdir(full_path):
        print(f"couldn't find {project_dir}")
        return	

    print(f"\n=== Project: {project_dir} ===")
    # safe and vuln states
    create_db(project_dir, cwe, "safe")
    create_db(project_dir, cwe, "vuln")

    print("\nAll done.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='cql database creator',
        description='This script creates codeQL database for all the projects in the supplied cwe-identifier')
    parser.add_argument('--cwe', type=int)
    args = parser.parse_args()
    cwe_num = args.cwe
    
    if isinstance(cwe_num, int):
        if cwe_num in [78,79,89,94]:
            create_dbs_for_cwe(f"cwe{cwe_num}")
        else:
            print("Cwe is set to a num. But ",cwe_num, " is not in [78,79,89,94]")
    else:
        print(cwe_num, "is not a num")
    #create_one()
