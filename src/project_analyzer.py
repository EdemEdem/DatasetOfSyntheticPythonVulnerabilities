import pathlib
import os
import shutil
import sys
import json
from typing import Optional, Union
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
        rerun_package_extraction: bool=True,
        rerun_usage_prompting: bool = False,
        rerun_cql_dataflow_discovery: bool = False,
        rerun_triage_prompting: bool = False,
        stop_after_package_extraction: bool = False,
        stop_after_usage_prompting: bool = False,
        stop_after_dataflow_caluclation: bool = False,
        simulate_run: bool = False
        ):
        self.project_root = project_root
        self.project_name = project_name
        self.cql_db_path = cql_db_path
        self.cwe = cwe
        self.model = model
        self.sanitizer_context = sanitizer_context
        self.rerun_package_extraction = rerun_package_extraction
        self.rerun_usage_prompting = rerun_usage_prompting
        self.rerun_cql_dataflow_discovery = rerun_cql_dataflow_discovery
        self.rerun_triage_prompting = rerun_triage_prompting
        self.stop_after_package_extraction = stop_after_package_extraction
        self.stop_after_usage_prompting=stop_after_usage_prompting
        self.stop_after_dataflow_caluclation=stop_after_dataflow_caluclation
        self.simulate_run = simulate_run
        
        # Setup paths:
        project_output_dir= pathlib.Path(__file__).resolve().parent.parent / "projects_cleaned" / project_name
        
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
        self.codeQLruns_dir = llm_results_dir / "codeQL_runs"
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
    
    def prev_run_path_is_valid(self, prev_path: pathlib.Path) -> bool:
        """Check that a previous run folder follows the expected structure."""
        expected_subdirs = [
            "package_analysis",
            "llm_results",
        ]
        if not prev_path.exists() or not prev_path.is_dir():
            print(f"[ERROR] {prev_path} does not exist or is not a directory.")
            return False

        for sub in expected_subdirs:
            subdir = prev_path / sub
            if not subdir.exists() or not subdir.is_dir():
                print(f"[ERROR] Missing subdirectory: {subdir}")
                return False

        print(f"[OK] Valid previous run structure found at {prev_path}")
        return True

    def set_prev_run_path(self, prev_path: pathlib.Path):
        """
        Copy all relevant files and directories from a previous run into the current run structure.
        """

        print(f"[INFO] Copying previous run data from: {prev_path}")

        # ---- File-to-file mapping (individual key outputs) ----
        file_mapping = {
            prev_path / "package_analysis" / "usages_raw.jsonl": self.package_analysis_raw_jsonl,
            prev_path / "package_analysis" / "usages_external.jsonl": self.package_analysis_result_jsonl,
            prev_path / "package_analysis" / "origin.jsonl": self.package_origin_analysis_jsonl,

            prev_path / "llm_results" / self.model / "spesification_results" / "sources.jsonl": self.package_analysis_sources_jsonl,
            prev_path / "llm_results" / self.model / "spesification_results" / "sinks.jsonl": self.package_analysis_sinks_jsonl,
            prev_path / "llm_results" / self.model / "spesification_results" / "TestSources.qll": self.package_analysis_sources_qll,
            prev_path / "llm_results" / self.model / "spesification_results" / "TestSinks.qll": self.package_analysis_sinks_qll,

            prev_path / "llm_results" / self.model / "codeQL_runs" / f"{self.cwe}-query.sarif": self.cql_output_sarif,
            prev_path / "llm_results" / self.model / "codeQL_runs" / f"{self.cwe}-query.csv": self.cql_output_csv,
            prev_path / "llm_results" / self.model / "triaged_flows" / f"filtered-{self.cwe}-query.sarif": self.filtred_sarif_path,
        }

        # ---- Directory mapping (prompt data and results) ----
        dir_mapping = {
            prev_path / "llm_results" / self.model / "usage_prompts": self.usage_pormpts_dir,
            prev_path / "llm_results" / self.model / "spesification_results": self.spesification_result_dir,
        }

        # ---- Copy individual files ----
        copied_files = 0
        for src, dest in file_mapping.items():
            if src.exists():
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dest)
                copied_files += 1
                print(f"  → Copied file: {src} → {dest}")

        # ---- Copy whole directories ----
        copied_dirs = 0
        for src_dir, dest_dir in dir_mapping.items():
            if src_dir.exists():
                if dest_dir.exists():
                    shutil.rmtree(dest_dir)
                shutil.copytree(src_dir, dest_dir)
                copied_dirs += 1
                print(f"  → Copied directory: {src_dir} → {dest_dir}")

        if copied_files == 0 and copied_dirs == 0:
            print("[WARN] No files or directories copied from previous run.")
        else:
            print(f"[OK] Copied {copied_files} files and {copied_dirs} directories from previous run.")

    
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
    
    def check_usage_specifications_present(self):
        """Return True if both sources.jsonl and sinks.jsonl exist and contain at least one JSON entry."""
        def file_has_entries(jsonl_path):
            if not os.path.isfile(jsonl_path) or os.path.getsize(jsonl_path) == 0:
                return False
            with open(jsonl_path, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        json.loads(line)
                        return True  # found at least one valid JSON entry
                    except json.JSONDecodeError:
                        continue
            return False
        sources_ok = file_has_entries(self.package_analysis_sources_jsonl)
        sinks_ok = file_has_entries(self.package_analysis_sinks_jsonl)
        return sources_ok and sinks_ok


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
    
    def run_pipeline(self, prev_run_path: Optional[Union[str, pathlib.Path]] = None):
        if prev_run_path:
            prev_path = pathlib.Path(prev_run_path)

            if not prev_path.exists() or not prev_path.is_dir():
                raise ValueError(f"[ERROR] Provided previous run path does not exist: {prev_run_path}")

            if not self.prev_run_path_is_valid(prev_path):
                raise ValueError(f"[ERROR] Invalid previous run structure at {prev_run_path}")

            self.set_prev_run_path(prev_path)
            print(f"[INFO] Loaded working directories and files from previous run at {prev_run_path}")
        else:
            print("[INFO] No previous run path provided — creating fresh working directories.")

        if self.simulate_run:
            print(f"Pretending to run pipeline for project {self.project_name} ... ")
            return
        # Extract packages
        if not os.path.isdir(self.project_root):
            print(f"could not find root at : {self.project_root}")
            return
        if not os.path.isfile(self.package_origin_analysis_jsonl) or self.rerun_package_extraction:
            print("Analyzing package origin ...")
            extract_external_imports_to_file(self.project_root, self.package_origin_analysis_jsonl)
        if not os.path.isfile(self.package_analysis_raw_jsonl) or self.rerun_package_extraction:
            print("Analyzing packages ...")
            analyze_one_project(self.project_root, self.package_analysis_raw_jsonl)
        if not os.path.isfile(self.package_analysis_result_jsonl) or self.rerun_package_extraction:
            self.filter_internal_packages()
        if self.stop_after_package_extraction:
            print("Stopping after package extraction")
            return
        # Query LLM
        usage_analyzer = UsagePrompter(
            specifications_json_path = self.package_analysis_result_jsonl,
            output_dir = self.usage_pormpts_dir,
            spesification_result_dir = self.spesification_result_dir,
            cwe=self.cwe,
            cwe_context= "")
        
        if self.rerun_usage_prompting:
            print("Rerunning usage prompting, clearing old results ...")
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

        ran_usage_prompting = False
   
        if not specification_exists or self.rerun_usage_prompting:
            usage_analyzer.save_prompts()
            print("Finished saving prompts")
            usage_analyzer.run_prompts_in_parallell()
            print("Finished runnig prompts")
            ran_usage_prompting = True
        
        if ran_usage_prompting or self.rerun_cql_dataflow_discovery:
            print("Writing predicates ...")
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
        
        if not self.check_usage_specifications_present():
            print("Did not find any candidates for both sources and sinks. Exiting run")
            return
        
        if not os.path.isfile(self.cql_output_sarif) or self.rerun_cql_dataflow_discovery:
            print("Starting codeQL run")
            self.find_data_flows_for_cwe()
            print("Finished running codeQL")
        else:
            print("CodeQL-discovered dataflows exist")
        if self.stop_after_dataflow_caluclation:
            print("stop_after_dataflow_caluclation set to true")
            print("Exiting")
            return
        if not os.path.isfile(self.filtred_sarif_path) or self.rerun_triage_prompting:
            triage_analyzer = TriagePrompter(
                self.project_root,
                self.cql_output_sarif,
                self.filtred_sarif_path,
                self.triage_pormpts_dir,
                self.triage_results_dir,
                self.cwe,
                self.sanitizer_context,
                context_lines_top=1,
                context_lines_bottom=1,
                gap_limit_between_steps=1
                )
            self.clear_directory(self.triage_pormpts_dir)
            self.clear_directory(self.triage_flows_dir)
            self.clear_directory(self.triage_results_dir)
            triage_analyzer.build_and_run_triage_prompts()
        else:
            print(f"{self.model}-triaged dataflows already exist at {self.filtred_sarif_path}")
    
if __name__ == "__main__":
     # Example usage
    cwe="cwe94"
    identifier="2-cli_datafilter"
    version="safe"
    
    # Define paths and parameters
    project_root=f"C:/Users/Edem Agbo/DatasetOfSyntheticPythonVulnerabilities/samples_cleaned/{cwe}/repos_{identifier}/{version}"
    name=f"{cwe}_repos_{identifier}_{version}"
    cql_db_path=f"C:/Users/Edem Agbo/DatasetOfSyntheticPythonVulnerabilities/samples_cleaned_cql_dbs/{cwe}/dbs_{identifier}/{version}-db"
    model="deepseek-reasoner"
    sanitizer_context = "parameterized queries"
    rerun_package_extraction=True
    rerun_usage_prompting=False
    rerun_cql_dataflow_discovery=False
    rerun_triage_prompting=False
    stop_after_package_extraction=True
    stop_after_usage_prompting=False
    stop_after_dataflow_caluclation=False
    simulate_run = False
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
        simulate_run = simulate_run
	)
    analyzer.run_pipeline()
