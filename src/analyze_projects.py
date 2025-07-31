import pathlib
import os
import shutil
import sys
import subprocess as sp
from samples.utils.run_simple_query import run_single_query
from samples.utils.query_dbs_for_vuln import run_analyze

#class project_analyzer:
	#this class holds:
 		#project root dir
		#project name
		#project cwe
		#codeql db path
		#cwe-specific codeql query file(s) path
		#pipline project dir
			# when combined with project's name, cwe, and root dir we'll use this to derrive the following
	  		#project-specific codeql help files (qll files with source and sink specification)
			#sink-source-candidates path
			#sinks path
			#sources path
		#an instance of the package extractor
		#an instance of the LLMClient
		#an insstance of the predicate writer

		#results path
  

# behavior
# # runs a package analysis
# #	# skip if results already exists
# # query-llms for source an sink specificaitons
# #	# skip if results already exists, or if skip-llm is set
# # write_ql_predicates
# #	# skip if results already exists
# # runs the codeql cwe query files
# #	# skip if results already exists
ROOT_DIR = "C:/Users/Edem Agbo/DatasetOfSyntheticPythonVulnerabilities"

def copy_over_sources_and_sinks(cwe, project, state):
    error = False
    query_run_dir = pathlib.Path("/Users/Edem Agbo/OneDrive/Skrivebord/MscThisis/codeql/qlpacks/codeql/python-queries/1.3.0/myQueries")
    #test_query_dir = pathlib.Path("/Users/Edem Agbo/OneDrive/Skrivebord/MscThisis/codeql/qlpacks/codeql/python-queries/1.3.0/myQueriesForResearch")
    node_extraction_dir = pathlib.Path("C:/Users/Edem Agbo/DatasetOfSyntheticPythonVulnerabilities/samples/package_extractor_results")
    path = node_extraction_dir / cwe / project / state
    source_qll_path = path / "TestSources.qll"
    if source_qll_path.is_file():
        try:
            shutil.copy(source_qll_path, query_run_dir)
        except Exception as e:
            print(f"[ERROR] copying TestSources.qll for {cwe}/{project}/{state}: {e}")
            error = True
    else:
        print(f"[ERROR] TestSources.qll not found for {cwe}/{project}/{state}")
        print(f"No file at path: {source_qll_path}")
        error = True

    sink_qll_path = path / "TestSinks.qll"
    if sink_qll_path.is_file():
        try:
            shutil.copy(sink_qll_path, query_run_dir)
        except Exception as e:
            print(f"[ERROR] copying TestSinks.qll for {cwe}/{project}/{state}: {e}")
            error = True
    else:
        print(f"[ERROR] TestSinks.qll not found for {cwe}/{project}/{state}")
        error = True
    if error:
        sys.exit(1)


def clear_sources_and_sinks():
    query_run_dir = pathlib.Path("/Users/Edem Agbo/OneDrive/Skrivebord/MscThisis/codeql/qlpacks/codeql/python-queries/1.3.0/myQueries")
    #test_query_dir = pathlib.Path("/Users/Edem Agbo/OneDrive/Skrivebord/MscThisis/codeql/qlpacks/codeql/python-queries/1.3.0/myQueriesForResearch")
    source_qll_path = query_run_dir / "TestSources.qll"
    if source_qll_path.exists():
        try:
            source_qll_path.unlink()
        except Exception as e:
            print(f"[ERROR] deleting TestSources.qll: {e}")

    sink_qll_path = query_run_dir / "TestSinks.qll"
    if sink_qll_path.exists():
        try:
            sink_qll_path.unlink()
        except Exception as e:
            print(f"[ERROR] deleting TestSinks.qll: {e}")

def find_data_flows_for_cwe(cwe):
    node_extraction_dir="C:/Users/Edem Agbo/DatasetOfSyntheticPythonVulnerabilities/samples/package_extractor_results"
    cwe_dir_path = pathlib.Path(node_extraction_dir) / cwe
    for project_dir in os.listdir(cwe_dir_path):
        project_path = os.path.join(cwe_dir_path, project_dir)
        if os.path.isdir(project_path):
            for state in ["vuln", "safe"]:
                path = os.path.join(project_path, state)
                if os.path.isdir(path):
                    print(f"Now running for project: {path}")
                    project_id = project_dir.split("_")[-1]
                    db = f"{ROOT_DIR}/cql_dbs/{cwe}/dbs_{project_id}/{state}-db"
                    #query= "C:/Users/Edem Agbo/OneDrive/Skrivebord/MscThisis/codeql/qlpacks/codeql/python-queries/1.3.0/myQueriesForResearch/llm_propogations_cwe89.ql"
                    clear_sources_and_sinks()
                    copy_over_sources_and_sinks(cwe,project_dir,state)
                    #run_single_query("testQueries",f"{project_dir}-{state}", db, "89", query, "dataflows")
                    query_dir ="C:/Users/Edem Agbo/OneDrive/Skrivebord/MscThisis/codeql/qlpacks/codeql/python-queries/1.3.0/myQueries"
                    run_analyze(f"{project_dir}-{state}",db,89,to_run_queries_full_path=query_dir)


if __name__ == "__main__":
    find_data_flows_for_cwe("cwe89")
 


