#!/usr/bin/env python3
"""
flow_triager.py

Reads a SARIF file containing CodeQL dataflows, prompts an LLM to classify each flow as safe or unsafe,
and writes out a new SARIF file with safe flows stripped out.
"""
import argparse
import json
import os
import sys
import re

# matches lines like “1: import os” or “123: import mypkg.submod, otherpkg  # comment”
IMPORT_RE = re.compile(
    r'^\s*'             # optional leading spaces
    r'\d+:'             # line number + colon
    r'\s*import\s+'     # “import ”
    r'[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*'                  # module name (with dots)
    r'(?:\s*,\s*[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)*'      # optional “, other.mod”
    r'\s*(?:#.*)?$'     # optional trailing comment
)

# matches lines like “1: from flask import Flask, request, …”
FROM_IMPORT_RE = re.compile(
    r'^\s*'             # optional leading spaces
    r'\d+:'             # line number + colon
    r'\s*from\s+'       # “from ”
    r'[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*'  # package/module
    r'\s+import\s+'     # “ import ”
    r'[A-Za-z_][A-Za-z0-9_]*(?:\s*,\s*[A-Za-z_][A-Za-z0-9_]*)*'  # one or more names
    r'\s*(?:#.*)?$'     # optional trailing comment
)


#from query_llms import LLMClient

CONTEXT_LINES = 2

class FlowTriager:
    def __init__(self, repo_path: str, sarif_path: str, output_path: str, prompt_dir: str, cwe: str):
        self.repo_path = repo_path
        self.sarif_path = sarif_path
        self.output_path = output_path
        self.prompt_dir = prompt_dir
        self.cwe = cwe
        """self.client = LLMClient(
            base_url   = "http://localhost:11434",
            model      = "llama3.1",
            temperature=0.0,
            top_k      = 0,
            top_p      = 0.0
            )"""

    def extract_code(self, location: dict, context_lines_top=CONTEXT_LINES, context_lines_bottom=CONTEXT_LINES) -> str:
        """
        Given a SARIF location object, read the file from disk and return the code snippet
        including CONTEXT_LINES before and after the region.
        """
        phys = location['location']['physicalLocation']
        uri = phys['artifactLocation']['uri']
        region = phys['region']
        start = max(region['startLine'] - context_lines_top, 1)
        end = region.get('endLine', region['startLine']) + context_lines_bottom
    

        file_path = os.path.join(self.repo_path, uri)
        try:
            with open(file_path, 'r') as f:
                lines = f.readlines()
        except IOError:
            print("Error during file read")
            return f"# Unable to read file: {uri}\n"

        snippet_lines = lines[start - 1:end]
        # Prefix each line with its actual line number
        numbered_lines = []
        for idx, line in enumerate(snippet_lines, start=start):
            # include the line break from the original line
            numbered_lines.append(f"{idx}: {line}")
        return ''.join(numbered_lines)

    
    def extract_block_lines(self, locations , gap_start, gap_end) -> str:
        block_parts = []
        lastline=""
        if len(locations) == 0:
            return""
        for idx, loc in enumerate(locations):
            line = loc['location']['physicalLocation']['region']['startLine']
            if line == lastline:
                continue
            lastline = line
            if idx == 0:
                block_parts.append(self.extract_code(loc, gap_start,0))
            else:
                block_parts.append(self.extract_code(loc, 0,0))
            lastloc = loc
        #add two trailing lines for context
        try:
            block_parts.append(self.extract_code(lastloc,-1,gap_end))
        except Exception:
            # if we couldn't get the two trailing lines it's not an issue
            pass
        return "".join(block_parts)
    
    def extract_block(self, uri: str, start: int, end: int) -> str:
        """
        Read a continuous block from a file and return numbered lines.
        """
        file_path = os.path.join(self.repo_path, uri)
        try:
            with open(file_path, 'r') as f:
                lines = f.readlines()
        except IOError:
            return f"# Unable to read file: {uri}\n"

        snippet = lines[start - 1:end]
        numbered = [f"{i}: {line}" for i, line in enumerate(snippet, start=start)]
        return ''.join(numbered)

    def build_prompt(self, thread_flow: dict) -> str:
        """
        Assemble a prompt listing source, intermediate steps, and sink.
        Then ask the model if the flow is safe (YES or NO).
        """
        locs = thread_flow['locations']
        # 1) Filter out import/from nodes
        filtered = []
        for loc in locs:
            code = self.extract_code(loc, 0, 0)
            # grab the first non-blank line
            first_line = next((l for l in code.splitlines() if l.strip()), "")
            if IMPORT_RE.match(first_line) or FROM_IMPORT_RE.match(first_line):
                continue
            filtered.append((loc, code))
        if not filtered:
            # if everything was an import, maybe fall back to original?
            print("Empty after filtering")
            print(filtered)
            filtered = [(loc, self.extract_code(loc)) for loc in locs]

        
        parts = []
        source_code = filtered[0][1]
        source_phys_loc = filtered[0][0]["location"]['physicalLocation']
        source_uri = source_phys_loc['artifactLocation']['uri']
        source_line = source_phys_loc['region']['startLine']
        source = f"[SOURCE] {source_uri}:{source_line}\n{source_code}"        
        parts.append(source)
        all_locs = [loc for loc,_ in filtered]
        step_nodes = all_locs[1:-1]
        blocks = self.find_blocks(step_nodes, 1)
        for idx, block in enumerate(blocks):
            startloc = block[0]['location']['physicalLocation']['region']['startLine']
            uri = block[0]['location']['physicalLocation']['artifactLocation']['uri']            
            step = f"[STEP {idx+1}] {uri}:{startloc}\n"
            parts.append(step)
            parts.append(self.extract_block_lines(block,1,0))

        sink_code = filtered[-1][1]
        sink_phys_loc = filtered[-1][0]["location"]['physicalLocation']
        sink_uri = sink_phys_loc['artifactLocation']['uri']
        sink_line = sink_phys_loc['region']['startLine']
        sink = f"[SINK] {sink_uri}:{sink_line}\n{sink_code}"
        parts.append(sink)

        body = "\n".join(parts)
        question = f"\nQuestion: Is this dataflow safe with respect to {self.cwe}? Answer YES or NO."
        return body + question
    
    def find_blocks(self, node_locs, gap) -> list:
        if len(node_locs) == 0:
            return []
        first_phys = node_locs[0]['location']['physicalLocation']
        first_uri = first_phys['artifactLocation']['uri']
        first_region = first_phys['region']
        first_start = first_region['startLine']
        
        cur_start = first_start
        cur_uri = first_uri
        buckets = []
        cur_bucket=[]
        for loc in node_locs:
            phys = loc['location']['physicalLocation']
            uri = phys['artifactLocation']['uri']
            region = phys['region']
            start = region['startLine']
            if uri == cur_uri:
                line= cur_start + gap
                if start <= line:
                    cur_bucket.append(loc)
                    cur_start=start
                else:
                    buckets.append(cur_bucket)
                    cur_bucket=[]
                    cur_bucket.append(loc)
                    cur_start = start
            else:
                buckets.append(cur_bucket)
                cur_bucket=[]
                cur_bucket.append(loc)
                cur_uri = uri
                cur_start = start
        buckets.append(cur_bucket)
        return buckets

    def is_flow_safe(self, prompt: str) -> bool:
        """
        Send the prompt to the LLM and interpret YES as safe, NO as unsafe.
        """
        #response = self.client.generate(prompt)
        #first = response.strip().split()[0].upper()
        first = "yes"
        return first == 'YES'
    
    def save_prompt(self, prompt: str, file_path: str) -> None:
        """
        Save the given prompt string to the specified file path.
        """
        try:
            with open(file_path, 'w') as f:
                f.write(prompt)
        except IOError as e:
            print(f"Error saving prompt to {file_path}: {e}", file=sys.stderr)
                 
    def triage(self):
        # Load SARIF
        with open(self.sarif_path, 'r') as f:
            data = json.load(f)

        results = data.get('runs', [])[0].get('results', [])
        flow_counter = 0

        for res in results:
            # Some results may have multiple codeFlows
            for cf in res.get('codeFlows', []):
                new_thread_flows = []
                for tf in cf.get('threadFlows', []):
                    prompt = self.build_prompt(tf)
                    # save prompt if directory configured
                    if self.prompt_dir:
                        flow_id = f"flow_{flow_counter}"
                        prompt_file = os.path.join(self.prompt_dir, f"{flow_id}.txt")
                        self.save_prompt(prompt, prompt_file)
                    safe = self.is_flow_safe(prompt)
                    if not safe:
                        new_thread_flows.append(tf)
                    flow_counter += 1
                cf['threadFlows'] = new_thread_flows

        # Write filtered SARIF
        with open(self.output_path, 'w') as out:
            json.dump(data, out, indent=2)


def main():
    parser = argparse.ArgumentParser(description='Filter safe dataflows from a SARIF file via LLM triage.')
    parser.add_argument('--repo-path', help='Path to the code repository root', default="C:/Users/Edem Agbo/DatasetOfSyntheticPythonVulnerabilities/samples/cwe89/repos_1/vuln")
    parser.add_argument('--sarif-path', help='Input SARIF file path', default="C:/Users/Edem Agbo/DatasetOfSyntheticPythonVulnerabilities/samples/query_results/cwe89/normalQueries/dbs_1-vuln.sarif")
    parser.add_argument('--output-path', help='Output SARIF file path with safe flows removed', default="C:/Users/Edem Agbo/DatasetOfSyntheticPythonVulnerabilities/samples/llm_results/llmTriagedQueries/dbs_1-vuln.sarif")
    args = parser.parse_args()

    triager = FlowTriager(args.repo_path, args.sarif_path, args.output_path, "C:/Users/Edem Agbo/DatasetOfSyntheticPythonVulnerabilities/samples/llm_results/prompts", "cwe89")
    triager.triage()

if __name__ == '__main__':
    main()
