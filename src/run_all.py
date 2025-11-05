import pathlib
import os
import shutil
import sys
import json
import argparse
import subprocess as sp
import re
import src.cwe_context as sani_cont

from src.project_analyzer import ProjectAnalyzer


def iter_projects(samples_dir, cql_dbs_dir, create_missing_dbs=False):

    if not samples_dir.is_dir():
        print(f"[ERROR] samples directory not found at: {samples_dir}")
        return
    if not cql_dbs_dir.is_dir():
        print(f"[ERROR] cql_dbs directory not found at: {cql_dbs_dir}")
        return

    for cwe_dir in sorted(samples_dir.iterdir()):
        if not cwe_dir.is_dir() or not cwe_dir.name.startswith("cwe"):
            continue

        m_cwe = re.fullmatch(r"cwe(\d+)", cwe_dir.name)
        if not m_cwe:
            print(f"[WARN] Skipping non-standard CWE dir name: {cwe_dir.name}")
            continue

        cwe_name = cwe_dir.name  # e.g., "cwe89"

        for repo_dir in sorted(cwe_dir.iterdir()):
            if not repo_dir.is_dir() or not repo_dir.name.startswith("repos_"):
                continue

            identifier = repo_dir.name[len("repos_"):]  # e.g., "3" or "1-expression_evaluator"
            if not identifier:
                print(f"[ERROR] Empty identifier in dir name: {repo_dir}")
                continue

            # First char must be 1..5; suffix allowed.
            m_repo = re.fullmatch(r"([1-5])(.*)", identifier)
            if not m_repo:
                print(f"[ERROR] '{repo_dir.name}' must be 'repos_<id>' where id starts with 1-5. Got: {repo_dir.name}")
                continue

            project_num = m_repo.group(1)            # "1".."5"
            suffix = m_repo.group(2) or ""           # optional suffix (e.g., "-expression_evaluator")

            # Verify 'safe' and 'vuln' subdirs exist
            version_dirs = {"safe": repo_dir / "safe", "vuln": repo_dir / "vuln"}
            missing_versions = [v for v, p in version_dirs.items() if not p.is_dir()]
            if missing_versions:
                print(f"[ERROR] {repo_dir} missing version dirs: {', '.join(missing_versions)}")
                continue

            # Expected DB location: cql_dbs/cweXX/dbs_<identifier>/{safe|vuln}-db
            dbs_base = cql_dbs_dir / cwe_name / f"dbs_{identifier}"
            db_paths = {v: dbs_base / f"{v}-db" for v in ("safe", "vuln")}
            missing_dbs = [v for v, p in db_paths.items() if not p.exists()]
            if missing_dbs:
                print(f"[ERROR] DBs missing for {repo_dir.name} under {cwe_name}: {', '.join(missing_dbs)} "
                      f"(expected under {dbs_base})")
                if create_missing_dbs:
                    if not missing_versions:
                        print(f"  [INFO] Creating missing DBs under {dbs_base}...")
                        dbs_base.mkdir(parents=True, exist_ok=True)
                        for v in missing_dbs:
                            cmd = [
                                "codeql", "database", "create",
                                "--language=python",
                                f"--source-root={version_dirs[v]}",
                                str(db_paths[v])
                            ]
                            print("  Running:", " ".join(cmd))
                            try:
                                sp.run(cmd, check=True)
                            except sp.CalledProcessError as e:
                                print(f"  [ERROR] Failed to create DB: {e}")
                continue

            # All good: yield both versions
            for version in ("vuln", "safe"):
                yield {
                    "project_root": str(version_dirs[version]),
                    "name": repo_dir.name,                      # e.g., "repos_3" or "repos_1-expression_evaluator"
                    "cql_db_path": str(db_paths[version]),      # e.g., ".../cql_dbs/cwe89/dbs_3/vuln-db"
                    "cwe": cwe_name,                            # e.g., "cwe89"
                    "version": version,                         # "safe" or "vuln"
                    "project_id": project_num,                  # numeric part only
                    "identifier": identifier,                   # numeric + optional suffix
                }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the context guardian pipeline, on the synthetic datset.")
    parser.add_argument("--simulate_runs", action="store_true", help="Simulate runs without executing tools.")
    parser.add_argument("--create_missing_dbs", action="store_true", help="Automatically create missing CodeQL databases.")
    args = parser.parse_args()
    simulate_run = False
    create_missing_dbs = False
    if args.simulate_runs:
        simulate_run=True
    if args.create_missing_dbs:
        create_missing_dbs=True
    
    # Assume this script lives somewhere under the dataset root; go up until we find 'samples' sibling 'cql_dbs'.
    # Commonly, repo_root = <.../DatasetOfSyntheticPythonVulnerabilities>
    repo_root = pathlib.Path(__file__).resolve().parent.parent
    
    # Define a subset of projects to run
    project_names_for_subset_run = [ "cwe89_repos_5_safe"]
    # Set flag to indicate subset run
    run_on_subset = True

    found = 0
    samples_dir = repo_root / "samples_cleaned"
    cql_dbs_dir = repo_root / "samples_claned_cql_dbs"
    for cfg in iter_projects(samples_dir, cql_dbs_dir, create_missing_dbs=create_missing_dbs):
        # Example of the variables you wanted to set:
        project_root = cfg["project_root"]
        cql_db_path = cfg["cql_db_path"]
        cwe = cfg["cwe"]
        version = cfg["version"]
        project_id = cfg["project_id"]
        name = f"{cwe}_{cfg["name"]}_{version}"

        found += 1
        model="deepseek-chat"
        sanitizer_context = ""
        rerun_package_extraction=False
        rerun_usage_prompting=True
        rerun_cql_dataflow_discovery=True
        rerun_triage_prompting=True
        stop_after_package_extraction=False
        stop_after_usage_prompting=False
        stop_after_dataflow_caluclation=False
        if cwe == "cwe78":
            sanitizer_context = sani_cont.cwe78

        if cwe == "cwe79":
            sanitizer_context = sani_cont.cwe79

        if cwe == "cwe89":
            sanitizer_context = sani_cont.cwe89

        if cwe == "cwe94":
            sanitizer_context = sani_cont.cwe94

        if run_on_subset and len(project_names_for_subset_run)> 0:
            if name not in project_names_for_subset_run:
                continue        
        print(f"\n[INFO] Analyzing project: {name} (CWE: {cwe}, version: {version})")
        
            
        analyzer = ProjectAnalyzer(
                project_root=project_root,
                project_name=name,
                cql_db_path=cql_db_path,
                cwe=cwe,
                model=model,
                sanitizer_context = sanitizer_context,
                rerun_package_extraction=rerun_package_extraction,
                rerun_usage_prompting=rerun_usage_prompting,
                rerun_cql_dataflow_discovery=rerun_cql_dataflow_discovery,
                rerun_triage_prompting=rerun_triage_prompting,
                stop_after_package_extraction=stop_after_package_extraction,
                stop_after_usage_prompting=stop_after_usage_prompting,
                stop_after_dataflow_caluclation=stop_after_dataflow_caluclation,
                simulate_run=simulate_run)
        analyzer.run_pipeline()

    if found == 0:
        print("[WARN] No projects found.")
    else:
        print(f"[OK] Found {found} project-version configurations.")
