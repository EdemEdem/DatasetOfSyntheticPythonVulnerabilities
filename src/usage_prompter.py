import json
import os
import sys
import pathlib
from collections import defaultdict
from openai import OpenAI
from dotenv import load_dotenv
from typing import List, Dict, Iterator, Any, Union
import src.prompt_templates

class UsagePrompter:
    def __init__(
        self,
        specifications_json_path: str,
        output_dir: str,
        spesification_result_dir: str,
        cwe: str,
        cwe_context: str,
        batch_size: Union[int, str] = 20
    ):
        # Path to JSONL file; CWE identifier and context for prompts
        self.specifications_json_path = specifications_json_path
        self.spesification_result_dir = spesification_result_dir
        self.cwe = cwe
        self.cwe_context = cwe_context
        self.output_dir = output_dir
        # Ensure batch_size is integer
        try:
            self.batch_size = int(batch_size)
            if self.batch_size < 1:
                raise ValueError
        except (TypeError, ValueError):
            raise ValueError(f"Invalid batch_size: {batch_size}. Must be a positive integer.")
        # Ensure output directory exists
        os.makedirs(self.output_dir, exist_ok=True)
        # Load all nodes at initialization
        self.nodes: List[Dict[str, Any]] = self._load_nodes()

    def _load_nodes(self) -> List[Dict[str, Any]]:
        """
        Load nodes from a JSONL file, one JSON object per line.
        """
        nodes: List[Dict[str, Any]] = []
        try:
            with open(self.specifications_json_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        nodes.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            print(f"Error reading JSONL file: {e}")
        return nodes

    def _chunked(self, seq: List[Any], size: int) -> Iterator[List[Any]]:
        """
        Split a list into chunks of at most `size` elements.
        """
        # Simple, clear slicing-based chunking avoids islice errors
        for i in range(0, len(seq), size):
            yield seq[i:i + size]
    
    def build_chain_prompts(self, package_context):
        pkgs = {}
        pkgs: dict[str, list]
        for node in self.nodes:
            pkg_name = node.get('package', '<unknown>')
            raw_chain = node.get('chain', [])
            try:
                # if package isn't registred
                if pkg_name not in pkgs:
                    pkgs[pkg_name] = []
                if raw_chain and raw_chain in pkgs[pkg_name]:
                    continue    
                pkgs[pkg_name].append(raw_chain)
            except Exception as e:
                print(f"Error during parsing:{e}")
                print("exiting")
                sys.exit(1)
                
        prompts = []
        for pkg in pkgs:
            chains = []
            for chain in pkgs[pkg]:
                chain_str = " ".join(chain)
                chains.append(chain_str)
            if pkg == "built_in":
                prompt = src.prompt_templates.PACKAGE_PROMPT_BUILTIN.format( cwe=self.cwe, body="\n".join(chains))
                prompts.append(prompt)
                continue
            prompt =src.prompt_templates.PACKAGE_PROMPT_SINK_AND_SOURCE.format(package=pkg, cwe=self.cwe, body="\n".join(chains))
            prompts.append(prompt)
        return prompts

    def save_prompts(self):
        """
        Generate and save all prompt types to files in output_dir.
        """
        methods = [           
            ('pre_chain', self.build_chain_prompts({}))
        ]
        total = 0
        for kind, prompts in methods:
            for i, prompt in enumerate(prompts, start=1):
                filename = os.path.join(self.output_dir, f"{kind}_prompt_{i}.txt")
                with open(filename, 'w') as f:
                    f.write(prompt)
                total += 1
        print(f"Saved {total} prompts to {self.output_dir}")        
    
    def run_prompts(self):
        prompts = self.load_prompts(self.output_dir)
        if not prompts:
            print("No prompts loaded. Exiting.")
            sys.exit(0)
        
        for filename, prompt in prompts.items():
            print(f"Running prompt: {filename}")
            raw = self.run_prompt(prompt)
            try:
                data = json.loads(raw)
            except json.JSONDecodeError as e:
                print(f"Failed to parse JSON for {filename}: {e}")
                continue
            # Include the source prompt filename for reference
            # # Append to JSONL
            output_filename = os.path.splitext(filename)[0] + "_result.jsonl"
            output_path = pathlib.Path(self.spesification_result_dir) / output_filename
            with open(output_path, "a", encoding="utf-8") as f:
                for key, value in data.items():
                    line = json.dumps({ key: value })
                    f.write(line + "\n")
        return
        
    def run_prompt(self, prompt):
        load_dotenv()
        api_key = os.getenv("DEEPSEEK_API_KEY")
        client = OpenAI(api_key=api_key, base_url="https://api.deepseek.com")
        response = client.chat.completions.create(
            model="deepseek-reasoner",
            messages=[
                {"role": "system", "content": src.prompt_templates.PACKAGE_PROMPT_SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
                ],
            response_format={
                'type': 'json_object'
                },
            stream=False
            )
        try:
            reasoning_content = response.choices[0].message.reasoning_content
            reaonsing_content_file = pathlib.Path(self.output_dir) / "reasoning.txt"
            with open(reaonsing_content_file,"a", encoding="utf-8", newline="\n") as f:
                if reasoning_content and not reasoning_content.endswith("\n"):
                    reasoning_content += "\n"
                    f.write(reasoning_content)
        except Exception:
            pass
        return response.choices[0].message.content
    
    def load_prompts(self, dir_path):
        prompt_prefix = "pre_chain"
        # Directory containing prompt files (each file should contain one prompt)
        prompts = {}
        if not os.path.isdir(dir_path):
            print(f"Prompt directory '{dir_path}' does not exist.")
            return prompts
        for filename in os.listdir(dir_path):
            file_path = os.path.join(dir_path, filename)
            if os.path.isfile(file_path):
                if prompt_prefix and prompt_prefix not in filename:
                    continue
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        prompts[filename] = f.read()
                except Exception as e:
                    print(f"Failed to read {file_path}: {e}")
        return prompts
    
def main():
    jsonl_path = "C:/Users/Edem Agbo/DatasetOfSyntheticPythonVulnerabilities/samples/package_extractor_results/cwe89/repos_3/vuln/usages_sorted.jsonl"
    cwe = "CWE 89"
    cwe_context = "Sql injection. "
    output_dir = "C:/Users/Edem Agbo/DatasetOfSyntheticPythonVulnerabilities/samples/llm_results/prompts"
    batch_size = "30"
    prompter = UsagePrompter(
        jsonl_path,
        cwe,
        cwe_context,
        output_dir,
        batch_size=batch_size
    )
    prompter.save_prompts()


if __name__ == '__main__':
    main()
