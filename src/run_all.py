import pathlib
import os
import shutil
import sys
import json
import subprocess as sp
import re

from src.project_analyzer import ProjectAnalyzer


def iter_projects(repo_root: pathlib.Path):
    
    samples_dir = repo_root / "samples"
    cql_dbs_dir = repo_root / "cql_dbs"

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
    # Assume this script lives somewhere under the dataset root; go up until we find 'samples' sibling 'cql_dbs'.
    # Commonly, repo_root = <.../DatasetOfSyntheticPythonVulnerabilities>
    repo_root = pathlib.Path(__file__).resolve().parent.parent

    found = 0
    for cfg in iter_projects(repo_root):
        # Example of the variables you wanted to set:
        project_root = cfg["project_root"]
        cql_db_path = cfg["cql_db_path"]
        cwe = cfg["cwe"]
        version = cfg["version"]
        project_id = cfg["project_id"]
        name = f"{cwe}_{cfg["name"]}_{version}"

        found += 1
        model="deepseek"
        sanitizer_context = "parameterized queries"
        rerun_usage_prompting=False
        rerun_triage_prompting=False
        stop_after_usage_prompting=False
        stop_after_dataflow_caluclation=False
        simulate_run=False
    
        if cwe == "cwe89":
            analyzer = ProjectAnalyzer(
                project_root=project_root,
                project_name=name,
                cql_db_path=cql_db_path,
                cwe=cwe,
                model=model,
                sanitizer_context = sanitizer_context,
                rerun_usage_prompting=rerun_usage_prompting,
                rerun_triage_prompting=rerun_triage_prompting,
                stop_after_usage_prompting=stop_after_usage_prompting,
                stop_after_dataflow_caluclation=stop_after_dataflow_caluclation,
                simulate_run=simulate_run)
            analyzer.run_pipeline()
        else:
            print(f"skipping project: {name} ,  because cwe is {cwe}")


    if found == 0:
        print("[WARN] No projects found.")
    else:
        print(f"[OK] Found {found} project-version configurations.")

    
    
    
    
    # loop through the dir called samples
		# loop through all its' subdirs who's name starts with "cwe"
  			#store it's cwe identifier. the number after cwe
			# loop through all it's subdirs
				# this is a subsubdir of samples and a subdir of cweXX
				# this dir's name should start with "repos_" followed by a number between 1 and 5
					# print out an error for me if that's not the case
				#store the name of this dir
				#also store the project_id
							# this is the number that comes after "repos_"
							# for some porjects there are some charachters after the number, also store those in the identifier
				#then verify that this dir has a subdir called "vuln" and a subdir called "safe"
					# print an error if this is not the case
				# The projects are now located. Each project is stored at samples/cweXX/repos_identifier/verison
					#version is always safe/vuln, and each project has two version
				# Then locate the databases
					# they reside in a dir called "cql_dbs", adjecent to the "samples" dir
					# each projects database is at "cql_dbs/cweXX/dbs_identifier/version-db"
						#example 1: cql_dbs/cwe79/dbs_5/vuln-db
						#example 2: cql_dbs/cwe94/dbs_1-expression_evaluator/safe-db
					# verify that each database exist
					# print an error if it could not be found
				# When a project(both versions) has been located, and it's databases located as well set these variables (bellow is an example for project 3 vulnerable version in cwe 89):
					# project_root="C:/Users/Edem Agbo/DatasetOfSyntheticPythonVulnerabilities/samples/cwe89/repos_3/vuln"
     				# name="repos_3"
         			# cql_db_path="C:/Users/Edem Agbo/DatasetOfSyntheticPythonVulnerabilities/cql_dbs/cwe89/dbs_3/vuln-db"
            		# cwe="cwe89"