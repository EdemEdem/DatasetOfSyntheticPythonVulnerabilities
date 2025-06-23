import subprocess as sp
#	sp.run([CODEQL, "database", "analyze", "--rerun", self.project_codeql_db_path, "--format=sarif-latest", f"--output={self.query_output_result_sarif_path}", to_run_query_full_path])
 #       if not os.path.exists(self.query_output_result_sarif_path):
  #          self.project_logger.error("  ==> Result SARIF not produced; aborting"); return
   #     sp.run([CODEQL, "database", "analyze", "--rerun", self.project_codeql_db_path, "--format=csv", f"--output={self.query_output_result_csv_path}", to_run_query_full_path])
    #    if not os.path.exists(self.query_output_result_csv_path):
     #       self.project_logger.error("  ==> Result CSV not produced; aborting"); return
      #  return