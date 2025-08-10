import os
import sys
import subprocess as sp
import json
import argparse

CODEQL_QUERY_DIR ="/Users/Edem Agbo/OneDrive/Skrivebord/MscThisis/codeql/qlpacks/codeql/python-queries/1.3.0/myQueriesForResearch"
CODEQL = "C:/Users/Edem Agbo/OneDrive/Skrivebord/MscThisis/codeql/codeql.cmd"
THIS_DIR = "C:/Users/Edem Agbo/DatasetOfSyntheticPythonVulnerabilities"
OUTPUT_CQL_DIR = "C:/Users/Edem Agbo/DatasetOfSyntheticPythonVulnerabilities/samples/query_results"

def normalize(path):
    return os.path.normpath(path)

def run_single_query(project_output_path, project_codeql_db_path, cwe_id, codeql_query_path, query_name):
    print("  ==> Running CodeQL analysis...")
    query_result_bqrs_path = f"{OUTPUT_CQL_DIR}/cwe{cwe_id}/{project_output_path}.bqrs"
    query_result_csv_path = f"{OUTPUT_CQL_DIR}/cwe{cwe_id}/{project_output_path}.csv"
    os.makedirs(normalize(os.path.join(f"{OUTPUT_CQL_DIR}/cwe{cwe_id}/normalQueries")), exist_ok=True)
    #Run the query
    sp.run([CODEQL, "query", "run", f"--database={project_codeql_db_path}", f"--output={query_result_bqrs_path}", "--", codeql_query_path])
    if not os.path.exists(query_result_bqrs_path):
        print(f"  ==> Failed to run query `{query_name}`; aborting")
    #Decode the query
    sp.run([CODEQL, "bqrs", "decode", query_result_bqrs_path, "--format=csv", f"--output={query_result_csv_path}"])
    if not os.path.exists(query_result_csv_path):
        print(f"  ==> Failed to decode result bqrs from `{query_name}`; aborting")

    return

def run_analyze(project_output_path, project_codeql_db_path, cwe_id, to_run_queries_full_path ="C:/Users/Edem Agbo/OneDrive/Skrivebord/MscThisis/codeql/qlpacks/codeql/python-queries/1.3.0/myQueriesContextGuardian"):
    print("  ==> Running CodeQL analysis...")
    query_output_result_sarif_path = f"{OUTPUT_CQL_DIR}/cwe{cwe_id}/normalQueries/{project_output_path}.sarif"
    query_output_result_csv_path = f"{OUTPUT_CQL_DIR}/cwe{cwe_id}/normalQueries/{project_output_path}.csv"
    os.makedirs(normalize(os.path.join(f"{OUTPUT_CQL_DIR}/cwe{cwe_id}/normalQueries")), exist_ok=True)
    sp.run([CODEQL, "database", "analyze", "--rerun", project_codeql_db_path, "--format=sarif-latest", f"--output={query_output_result_sarif_path}", to_run_queries_full_path])
    if not os.path.exists(query_output_result_sarif_path):
        print("  ==> Result SARIF not produced; aborting"); return
    sp.run([CODEQL, "database", "analyze", "--rerun", project_codeql_db_path, "--format=csv", f"--output={query_output_result_csv_path}", to_run_queries_full_path])
    if not os.path.exists(query_output_result_csv_path):
        print("  ==> Result CSV not produced; aborting"); return
    return

def run_analyze_for_pipeline(output_sarif, output_csv, project_codeql_db_path, to_run_queries_full_path ="C:/Users/Edem Agbo/OneDrive/Skrivebord/MscThisis/codeql/qlpacks/codeql/python-queries/1.3.0/myQueriesContextGuardian"):
    print("  ==> Running CodeQL analysis...")
    sp.run([CODEQL, "database", "analyze", "--rerun", project_codeql_db_path, "--format=sarif-latest", f"--output={output_sarif}", to_run_queries_full_path])
    if not os.path.exists(output_sarif):
        print("  ==> Result SARIF not produced; aborting"); return
    sp.run([CODEQL, "database", "analyze", "--rerun", project_codeql_db_path, "--format=csv", f"--output={output_csv}", to_run_queries_full_path])
    if not os.path.exists(output_csv):
        print("  ==> Result CSV not produced; aborting"); return
    return

def locate_dbs_and_run_analyze(cwe_id):
    if not cwe_id.isdigit():
        return
    db_dir = f"{THIS_DIR}/cql_dbs/cwe{cwe_id}"
    with os.scandir(db_dir) as it:
        for entry in it:
            safe_db_dir_path = os.path.join(db_dir, f"{entry.name}", "safe-db")
            vuln_db_dir_path = os.path.join(db_dir, f"{entry.name}", "vuln-db")
            if entry.is_dir():
                run_analyze(f"{entry.name}-safe", safe_db_dir_path, cwe_id)
                run_analyze(f"{entry.name}-vuln", vuln_db_dir_path, cwe_id)
            else:
                print(f"ERROR! No database at{entry.name}")

def analyze_on_one_database(repo, state, cwe_id):
    db_dir = "/Users/Edem Agbo/OneDrive/Skrivebord/MscThisis/secdebt4ai/dataset/codeql_databases"
    db_dir_path = os.path.join(db_dir, f"cwe{cwe_id}", repo, f"{state}-db")
    if os.path.isdir(db_dir_path):
        run_analyze(f"{repo}-{state}", db_dir_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--cwe",
        type=str,
        help="Filter by CWE ID (must be one of 78, 79, 89, 94)"
    )
    args = parser.parse_args()

    valid_cwes = ["78", "79", "89", "94"]
    if args.cwe:
        if args.cwe in valid_cwes:
            cwe_id = args.cwe
            locate_dbs_and_run_analyze(cwe_id)
        else:
            parser.error(f"Invalid --cwe value: {args.cwe}. Must be one of {valid_cwes}")