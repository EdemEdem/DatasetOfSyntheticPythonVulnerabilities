import pathlib
import os
import shutil
import sys
import json
import subprocess as sp

from src.package_extractor import analyze_one_project, extract_external_imports_to_file
from src.usage_prompter import UsagePrompter
from src.write_ql_predicates import PredicateWriter
from src.traiage_prompter import TriagePrompter

from samples.utils.query_dbs_for_vuln import run_analyze_for_pipeline

class ProjectAnalyzer:
    def __init__(
        self,
        project_root: str,
        project_name: str,
        cql_db_path: str,
        cwe: str,
        model: str,
        sanitizer_context: str,
        rerun_usage_prompting: bool = False,
        rerun_triage_prompting: bool = False,
        stop_after_usage_prompting: bool = False,
        simulate_run: bool = False
        ):
        self.project_root = project_root
        self.project_name = project_name
        self.cql_db_path = cql_db_path
        self.cwe = cwe
        self.model = model
        self.sanitizer_context = sanitizer_context
        self.rerun_usage_prompting = rerun_usage_prompting
        self.rerun_triage_prompting = rerun_triage_prompting
        self.stop_after_usage_prompting=stop_after_usage_prompting
        self.simulate_run = simulate_run
        
        # Setup paths:
        project_output_dir= pathlib.Path(__file__).resolve().parent.parent / "projects" / project_name
        
        # Paths stage 1 (Package analysis and usage specification)
        # Throw an error if project_output_dir allready exists, and exit the pipeline saying that there's aleady a project named that name
        # If the dir does not exists create it and proceed the execution
        package_analysis_dir = project_output_dir / "package_analysis"
        os.makedirs(package_analysis_dir, exist_ok=True)
        self.package_analysis_raw_jsonl = package_analysis_dir / "usages_raw.jsonl"
        self.package_analysis_result_jsonl = package_analysis_dir / "usages_external.jsonl"
        self.package_origin_analysis_jsonl = package_analysis_dir / "origin.jsonl"
        
        llm_results_dir = project_output_dir / "llm_results" / model
        self.usage_pormpts_dir = llm_results_dir / "usage_prompts"
        self.spesification_result_dir = llm_results_dir / "spesification_results"
        self.package_analysis_sources_jsonl = self.spesification_result_dir / "sources.jsonl"
        self.package_analysis_sinks_jsonl = self.spesification_result_dir / "sinks.jsonl"
        self.package_analysis_sources_qll = self.spesification_result_dir / "TestSources.qll"
        self.package_analysis_sinks_qll = self.spesification_result_dir / "TestSinks.qll"
        os.makedirs(self.usage_pormpts_dir, exist_ok=True)
        os.makedirs(self.spesification_result_dir, exist_ok=True)

        # Paths stage 2
        self.codeQLruns_dir = project_output_dir / "codeQL_runs"
        os.makedirs(self.codeQLruns_dir, exist_ok=True)
        self.cql_output_sarif = self.codeQLruns_dir / f"{self.cwe}-query.sarif"
        self.cql_output_csv = self.codeQLruns_dir / f"{self.cwe}-query.csv"
        self.triage_flows_dir = llm_results_dir / "triaged_flows"
        self.filtred_sarif_path = llm_results_dir / "triaged_flows" / f"filtered-{self.cwe}-query.sarif"
        self.triage_pormpts_dir = llm_results_dir / "triage_prompts"
        self.triage_results_dir = llm_results_dir / "triage_results"
        os.makedirs(self.triage_results_dir, exist_ok=True)
        os.makedirs(self.triage_pormpts_dir, exist_ok=True)
        os.makedirs(self.triage_flows_dir, exist_ok=True)
    
    
    def filter_internal_packages(self):
        # Step 1: Load internal imports from file 1
        internal_imports = set()
        with open(self.package_origin_analysis_jsonl, "r", encoding="utf-8") as f:
            for line in f:
                record = json.loads(line)
                if record.get("type") == "internal":
                    internal_imports.update(record.get("imports", []))
        # Step 2: Read file 2 and filter
        data_file = pathlib.Path(self.package_analysis_raw_jsonl)
        output_path = pathlib.Path(self.package_analysis_result_jsonl)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with data_file.open("r", encoding="utf-8") as infile, \
            output_path.open("w", encoding="utf-8") as outfile:
                for line in infile:
                    record = json.loads(line)
                    if record.get("package") not in internal_imports:
                        outfile.write(json.dumps(record) + "\n")

        
    def copy_over_sources_and_sinks(self):
        error = False
        query_run_dir = pathlib.Path("/Users/Edem Agbo/OneDrive/Skrivebord/MscThisis/codeql/qlpacks/codeql/python-queries/1.3.0/myQueries")
        if self.package_analysis_sources_qll.is_file():
            try:
                shutil.copy(self.package_analysis_sources_qll, query_run_dir)
            except Exception as e:
                print(f"[ERROR] copying TestSources.qll {e}")
                error = True
        else:
            print("[ERROR] TestSources.qll not found")
            print(f"No file at path: {self.package_analysis_sources_qll}")
            error = True
        if self.package_analysis_sinks_qll.is_file():
            try:
                shutil.copy(self.package_analysis_sinks_qll, query_run_dir)
            except Exception as e:
                print(f"[ERROR] TestSinks.qll not found {e}")
                error = True
        else:
            print("[ERROR] TestSinks.qll not found")
            error = True
        if error:
            sys.exit(1)
            
    def clear_sources_and_sinks(self):
        query_run_dir = pathlib.Path("/Users/Edem Agbo/OneDrive/Skrivebord/MscThisis/codeql/qlpacks/codeql/python-queries/1.3.0/myQueries")
        source_qll_path = query_run_dir / "TestSources.qll"
        sink_qll_path = query_run_dir / "TestSinks.qll"
        if source_qll_path.exists():
            try:
                source_qll_path.unlink()
            except Exception as e:
                print(f"[ERROR] deleting TestSources.qll: {e}")
        if sink_qll_path.exists():
            try:
                sink_qll_path.unlink()
            except Exception as e:
                print(f"[ERROR] deleting TestSinks.qll: {e}")
                
    def find_data_flows_for_cwe(self):
        self.clear_sources_and_sinks()
        self.copy_over_sources_and_sinks()
        query_dir ="C:/Users/Edem Agbo/OneDrive/Skrivebord/MscThisis/codeql/qlpacks/codeql/python-queries/1.3.0/myQueries"
        run_analyze_for_pipeline(self.cql_output_sarif, self.cql_output_csv, self.cql_db_path, query_dir)

    def clear_directory(self, dir_path):
        for filename in os.listdir(dir_path):
            file_path = os.path.join(dir_path, filename)
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)  # remove file or symlink
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)  # remove folder and its contents
        print(f"Successfully cleared {dir_path}")
    
    def run_pipeline(self):
        if self.simulate_run:
            print(f"Pretending to run pipeline for project {self.project_name} ... ")
            return
        # Extract packages
        if not os.path.isdir(self.project_root):
            print(f"could not find root at : {self.project_root}")
            return
        if not os.path.isfile(self.package_origin_analysis_jsonl):
            print("Analyzing package origin ...")
            extract_external_imports_to_file(self.project_root, self.package_origin_analysis_jsonl)
        if not os.path.isfile(self.package_analysis_raw_jsonl):
            print("Analyzing packages ...")
            analyze_one_project(self.project_root, self.package_analysis_raw_jsonl)
        if not os.path.isfile(self.package_analysis_result_jsonl):
            self.filter_internal_packages()
        # Query LLM
        usage_analyzer = UsagePrompter(
            specifications_json_path = self.package_analysis_result_jsonl,
            output_dir = self.usage_pormpts_dir,
            spesification_result_dir = self.spesification_result_dir,
            cwe=self.cwe,
            cwe_context= "")
        #checking if this step is already completed
        if self.rerun_usage_prompting:
            self.clear_directory(self.codeQLruns_dir)
            self.clear_directory(self.usage_pormpts_dir)
            self.clear_directory(self.spesification_result_dir)
            
        specification_exists = False
        if os.path.isfile(self.package_analysis_sources_jsonl):
            if os.path.getsize(self.package_analysis_sources_jsonl) > 0:
                print("LLM specified sources already exist")
                specification_exists = True
        if os.path.isfile(self.package_analysis_sinks_jsonl):
            if os.path.getsize(self.package_analysis_sinks_jsonl) > 0:
                print("LLM specified sinks already exist")
                specification_exists = True
        
        if not specification_exists or self.rerun_usage_prompting:
            usage_analyzer.save_prompts()
            print("Finished saving prompts")
            usage_analyzer.run_prompts()
            print("Finished runnig prompts")
            predicate_writer = PredicateWriter(
                input_source_path = self.package_analysis_sources_jsonl,
                input_sink_path = self.package_analysis_sinks_jsonl,
                output_source_qll_file = self.package_analysis_sources_qll,
                output_sink_qll_file = self.package_analysis_sinks_qll,
                llm_specifications_dir_path = self.spesification_result_dir,
                usage_nodes_path = self.package_analysis_result_jsonl
                )
            predicate_writer.process_llm_specifications()
            predicate_writer.write_source_qll_file()
            predicate_writer.write_sink_qll_file()
            print("Finished writing predicates")
        
        if self.stop_after_usage_prompting:
            print("stop_after_usage_prompting is set to true")
            print("Exiting run")
            return
        
        if not os.path.isfile(self.cql_output_sarif):
            print("Starting codeQL run")
            self.find_data_flows_for_cwe()
            print("Finished running codeQL")
        else:
            print("CodeQL-discovered dataflows exist")
        triage_analyzer = TriagePrompter(
            self.project_root,
            self.cql_output_sarif,
            self.filtred_sarif_path,
            self.triage_pormpts_dir,
            self.triage_results_dir,
            self.cwe,
            self.sanitizer_context
		)
        if not os.path.isfile(self.filtred_sarif_path) or self.rerun_triage_prompting:
            self.clear_directory(self.triage_pormpts_dir)
            self.clear_directory(self.triage_flows_dir)
            self.clear_directory(self.triage_results_dir)
            triage_analyzer.build_and_run_triage_prompts()
        else:
            print(f"{self.model}-triaged dataflows already exist")
    
if __name__ == "__main__":
    project_root="C:/Users/Edem Agbo/DatasetOfSyntheticPythonVulnerabilities/samples/cwe89/repos_3/vuln"
    name="SQLi_synth_4"
    cql_db_path="C:/Users/Edem Agbo/DatasetOfSyntheticPythonVulnerabilities/cql_dbs/cwe89/dbs_3/vuln-db"
    cwe="cwe89"
    model="deepseek"
    sanitizer_context = "parameterized queries"
    rerun_usage_prompting=False
    rerun_triage_prompting=True
    stop_after_usage_prompting=False
    simulate_run = True
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
        simulate_run = simulate_run
	)
    analyzer.run_pipeline()
