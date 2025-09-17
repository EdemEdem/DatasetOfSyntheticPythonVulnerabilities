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
import pathlib
import re
from urllib.parse import urlsplit, unquote
from openai import OpenAI
from dotenv import load_dotenv
from src.prompt_templates import FLOW_PROMPT_SYSTEM_PROMPT

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

_WIN_ABS_RE = re.compile(r'^(?:[a-zA-Z]:[\\/]|\\\\[^\\\/]+[\\\/][^\\\/]+)')


#from query_llms import LLMClient

#CONTEXT_LINES = 2

class TriagePrompter:
    def __init__(self, repo_path: str, sarif_path: str, filtred_sarif_path: str, prompt_dir: str, result_dir: str, cwe: str, sanitizer_context: str, context_lines_top: int = 1, context_lines_bottom: int = 1, gap_limit_between_steps: int = 1):
        self.repo_path = repo_path
        self.sarif_path = sarif_path
        self.filtred_sarif_path = filtred_sarif_path
        self.prompt_dir = prompt_dir
        self.result_dir = result_dir
        self.cwe = cwe
        self.sanitizer_context = sanitizer_context
        self.context_lines_top = context_lines_top
        self.context_lines_bottom = context_lines_bottom
        self.gap_limit_between_steps = gap_limit_between_steps
    
    @staticmethod
    def _from_file_uri(uri: str) -> str:
        """Convert file: URI to a local path (handles Windows + POSIX)."""
        s = urlsplit(uri)
        if s.scheme != 'file':
            return uri

        # UNC: file://server/share/path
        if s.netloc and s.netloc.lower() not in ('', 'localhost'):
            path = f"\\\\{s.netloc}{s.path}"
            return unquote(path.replace('/', '\\'))

        # Local path (percent-decoded)
        path = unquote(s.path)

        # Windows drive path like /C:/dir/file  -> C:\dir\file
        if re.match(r'^/[a-zA-Z]:', path):
            return path[1:].replace('/', '\\')

        # POSIX absolute path like /usr/bin/ls
        return path

    def format_path(self, uri: str) -> str:
        """
        If `uri` is absolute (POSIX, Windows drive, or UNC), return it as-is (normalized).
        Otherwise, join it with `self.repo_path`.
        """
        if not uri:
            return self.repo_path

        # Normalize file: URIs to local paths first
        if uri.lower().startswith('file:'):
            uri = self._from_file_uri(uri)

        if os.path.isabs(uri) or _WIN_ABS_RE.match(uri):
            return os.path.normpath(uri)

        return os.path.normpath(os.path.join(self.repo_path, uri))

    def extract_code(self, location: dict, context_lines_top, context_lines_bottom) -> str:
        """
        Given a SARIF location object, read the file from disk and return the code snippet
        including CONTEXT_LINES before and after the region.
        """
        phys = location['location']['physicalLocation']
        uri = phys['artifactLocation']['uri']
        region = phys['region']
        start = max(region['startLine'] - context_lines_top, 1)
        end = region.get('endLine', region['startLine']) + context_lines_bottom
    

#        file_path = os.path.join(self.repo_path, uri)
        file_path = self.format_path(uri)
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except IOError as e:
            print("Error during file read")
            print(f"file_path was {file_path}")
            print(e)
            
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
        #add trailing lines for context
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

    def build_one_triage_prompt(self, thread_flow: dict) -> str:
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
            filtered = [(loc, self.extract_code(loc, self.context_lines_top, self.context_lines_bottom)) for loc in locs]

        
        parts = []
        source_code = filtered[0][1]
        source_phys_loc = filtered[0][0]["location"]['physicalLocation']
        source_uri = source_phys_loc['artifactLocation']['uri']
        source_line = source_phys_loc['region']['startLine']
        source = f"[SOURCE] {source_uri}:{source_line}\n{source_code}"        
        parts.append(source)
        all_locs = [loc for loc,_ in filtered]
        step_nodes = all_locs[1:-1]
        # group step nodes into blocks with no more than {gap_limit_between_steps} line gaps
        blocks = self.find_blocks(step_nodes, self.gap_limit_between_steps)
        for idx, block in enumerate(blocks):
            startloc = block[0]['location']['physicalLocation']['region']['startLine']
            uri = block[0]['location']['physicalLocation']['artifactLocation']['uri']            
            step = f"[STEP {idx+1}] {uri}:{startloc}\n"
            parts.append(step)
            parts.append(self.extract_block_lines(block,self.context_lines_top,self.context_lines_bottom))

        sink_code = filtered[-1][1]
        sink_phys_loc = filtered[-1][0]["location"]['physicalLocation']
        sink_uri = sink_phys_loc['artifactLocation']['uri']
        sink_line = sink_phys_loc['region']['startLine']
        sink = f"[SINK] {sink_uri}:{sink_line}\n{sink_code}"
        parts.append(sink)

        body = "\n".join(parts)
        question = f"\nQuestion: Is this dataflow vulnerable to {self.cwe}? Answer YES or NO."
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

    def ask_llm_if_flow_is_safe(self, prompt: str, filename) -> bool:
        raw = self.generate_response(prompt)
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
                print(f"Failed to parse JSON for {filename}: {e}")
        output_path = pathlib.Path(self.result_dir) / filename
        with open(output_path, "a", encoding="utf-8") as f:
            for key, value in data.items():
                line = json.dumps({ key: value })
                f.write(line + "\n")
            print(f"Appended result for {filename} to {output_path}")
        return data["judgement"]
    
    def generate_response(self,prompt):
        load_dotenv()
        api_key = os.getenv("DEEPSEEK_API_KEY")
        client = OpenAI(api_key=api_key, base_url="https://api.deepseek.com")
        response = client.chat.completions.create(
            model="deepseek-chat",
            messages=[
                {"role": "system", "content": FLOW_PROMPT_SYSTEM_PROMPT.format(cwe=self.cwe, sanitizer_context=self.sanitizer_context)},
                {"role": "user", "content": prompt},
                ],
            response_format={
                'type': 'json_object'
                },
            stream=False
            )
        if response.choices[0].message.content is None:
            print("Error. No model reponse. Mdel response was: None")
            return {"judgement":"none"}
        return response.choices[0].message.content
    
    def save_prompt(self, prompt: str, file_path: str) -> None:
        """
        Save the given prompt string to the specified file path.
        """
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(prompt)
        except IOError as e:
            print(f"Error saving prompt to {file_path}: {e}", file=sys.stderr)
                 
	#builds prompts, prompts llm, returns the flows the llm deems vulnerable
    def build_and_run_triage_prompts(self):
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
                    prompt = self.build_one_triage_prompt(tf)
                    # save prompt if directory configured
                    if self.prompt_dir:
                        flow_id = f"flow_{flow_counter}"
                        prompt_file = os.path.join(self.prompt_dir, f"{flow_id}.txt")
                        self.save_prompt(prompt, prompt_file)
                    safe = self.ask_llm_if_flow_is_safe(prompt, f"{flow_id}.txt")
                    if not safe:
                        new_thread_flows.append(tf)
                    flow_counter += 1
                cf['threadFlows'] = new_thread_flows

        # Write filtered SARIF
        with open(self.filtred_sarif_path, 'w') as out:
            json.dump(data, out, indent=2)

def main():
    parser = argparse.ArgumentParser(description='Filter safe dataflows from a SARIF file via LLM triage.')
    parser.add_argument('--repo-path', help='Path to the code repository root', default="C:/Users/Edem Agbo/DatasetOfSyntheticPythonVulnerabilities/samples/cwe89/repos_1/vuln")
    parser.add_argument('--sarif-path', help='Input SARIF file path', default="C:/Users/Edem Agbo/DatasetOfSyntheticPythonVulnerabilities/samples/query_results/cwe89/normalQueries/dbs_1-vuln.sarif")
    parser.add_argument('--output-path', help='Output SARIF file path with safe flows removed', default="C:/Users/Edem Agbo/DatasetOfSyntheticPythonVulnerabilities/samples/llm_results/llmTriagedQueries/dbs_1-vuln.sarif")
    args = parser.parse_args()

    triager = TriagePrompter(args.repo_path, args.sarif_path, args.output_path, "C:/Users/Edem Agbo/DatasetOfSyntheticPythonVulnerabilities/samples/llm_results/prompts", "cwe89")
    triager.build_and_run_triage_prompts()

if __name__ == '__main__':
    main()
