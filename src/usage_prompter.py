import json
import os
import sys
from collections import defaultdict
from typing import List, Dict, Iterator, Any, Union
import prompt_templates

class UsagePrompter:
    def __init__(
        self,
        specifications_json_path: str,
        cwe: str,
        cwe_context: str,
        output_dir: str,
        batch_size: Union[int, str] = 20
    ):
        # Path to JSONL file; CWE identifier and context for prompts
        self.specifications_json_path = specifications_json_path
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
            prompt =prompt_templates.PACKAGE_PROMPT_SINK_AND_SOURCE.format(package=pkg, cwe=self.cwe, body="\n".join(chains))
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
        
def main():
    '''
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate usage prompts from a JSONL specifications file."
    )
    parser.add_argument('jsonl_path', help='Path to specifications JSONL file', required=False)
    parser.add_argument('cwe', help='CWE identifier, e.g. CWE-89', required=False)
    parser.add_argument('cwe_context', help='Description or context of the CWE', required=False)
    parser.add_argument('output_dir', help='Directory to save generated prompts', required=False)
    parser.add_argument('--batch-size', type=int, default=20,
                        help='Number of nodes per batch', required=False)

    args = parser.parse_args()
    
    jsonl_path = args.jsonl_path or "C:/Users/Edem Agbo/DatasetOfSyntheticPythonVulnerabilities/samples/package_extractor_results/cwe89/repos_3/vuln/usages_sorted.jsonl"
    cwe = args.cwe or "CWE 89"
    cwe_context = args.cwe_context or "Sql injection. "
    output_dir = args.output_dir or "C:/Users/Edem Agbo/DatasetOfSyntheticPythonVulnerabilities/samples/llm_results/prompts"
    batch_size = args.batch_size or "30"
    '''
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
