#!/usr/bin/env python3
import json
import time
import argparse
import requests
import random
import sys
import os
from pathlib import Path
from itertools import islice
from dotenv import load_dotenv


# ------------------------------------------------------------------------------
# Configuration / Constants
# ------------------------------------------------------------------------------
load_dotenv()
api_key = os.getenv("DEEPSEEK_API_KEY")

DEFAULT_CHUNK_SIZE = 50
DEFAULT_RETRIES    = 3
DEFAULT_TIMEOUT    = 600  # seconds
RETRY_DELAY        = 1   # seconds between retries

# ------------------------------------------------------------------------------
# LLM CLIENT
# ------------------------------------------------------------------------------
class LLMClient:
    """
    Simple client to call a local Ollama v1/completions endpoint
    and ensure we get back JSON.
    """
    def __init__(self,
                 base_url: str,
                 model: str,
                 temperature: float = 0.0,
                 top_k: int = 0,
                 top_p: float = 0.0,
                 timeout: int = DEFAULT_TIMEOUT):
        self.base_url = base_url.rstrip('/')
        self.params = {
            "model": model,
            "temperature": temperature,
            "top_k": top_k,
            "top_p": top_p,
        }
        self.timeout = timeout

    def generate(self, prompt: str) -> dict:
        """Send prompt, return raw JSON."""
        url = f"{self.base_url}/v1/completions"
        payload = {"prompt": prompt, **self.params}
        resp = requests.post(url, json=payload, timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()
    
    def dummy_generate(self, prompt: str) -> dict:
        """
        Dummy LLM response: parses the JSON array in `prompt`, then
        assigns each item a random classification of "source", "sink", or "sanitizer".
        Returns a dict shaped like a real Ollama response.
        """
        # 1) Extract the JSON array from the prompt
        start = prompt.find('[')
        end   = prompt.rfind(']') + 1
        try:
            usages = json.loads(prompt[start:end])
        except Exception as e:
            raise ValueError(f"Could not parse usages from prompt: {e}")

        # 2) Randomly label each usage
        labels = ["source", "sink", "sanitizer"]
        results = [
            #change from chain to id
            {"id": u["chain"], "classification": random.choice(labels)}
            for u in usages
        ]

        # 3) Wrap in the same structure your code expects
        return {
            "choices": [
                {
                    "text": json.dumps(results)
                }
            ]
        }

    @staticmethod
    def extract_json_array(text: str):
        """
        Pull out the first JSON array [...] from the model’s text.
        Raises ValueError if no well-formed JSON array is found.
        """
        start = text.find('[')
        end   = text.rfind(']')
        if start < 0 or end < 0:
            raise ValueError("No JSON array found in model output.")
        return json.loads(text[start:end+1])

# ------------------------------------------------------------------------------
# USAGE CLASSIFIER
# ------------------------------------------------------------------------------
class UsageClassifier:
    """
    Reads a JSONL of usages, chunks them, prompts the LLM to classify each as
    source/sink/neither for a given CWE, and writes out a JSONL of {id,classification}.
    """
    def __init__(self,
                 client: LLMClient,
                 cwe_id: str,
                 chunk_size: int = DEFAULT_CHUNK_SIZE,
                 retries: int = DEFAULT_RETRIES,
                 retry_delay: int = RETRY_DELAY):
        self.client = client
        self.cwe_id = cwe_id
        self.chunk_size = chunk_size
        self.retries = retries
        self.retry_delay = retry_delay

    def classify_file(self, input_path: Path, output_path: Path):
        usages = list(self._load_usages(input_path))
        with output_path.open('w', encoding='utf-8') as out_f:
            for batch in self._batches(usages):
                results = self._classify_batch(batch)
                for r in results:
                    out_f.write(json.dumps(r) + "\n")

    def _load_usages(self, path: Path):
        #Yield each line of the input JSONL file as a dict
        with path.open('r', encoding='utf-8') as f:
            for line in f:
                yield json.loads(line)

    def _batches(self, iterable):
        #Yield successive chunks of size self.chunk_size
        it = iter(iterable)
        while True:
            chunk = list(islice(it, self.chunk_size))
            if not chunk:
                break
            yield chunk

    def _build_prompt(self, usages_chunk):
        """
        Build a single prompt asking to classify each item in usages_chunk.
        We include only the fields the model needs.
        """
        header = (
            f"You are a security analyst.  "
            f"For each usage below, classify it as \"source\", \"sink\", or \"neither\" "
            f"for {self.cwe_id}.\n"
            "Reply ONLY with a JSON array of objects with keys: id, classification.\n\n"
        )
        # reduce each usage to the essentials
        minimal = [
            {
                #"id":   u["identifier"],
                "chain": u.get("chain"),
                "code":  u.get("code")
            }
            for u in usages_chunk
        ]
        body = json.dumps(minimal, indent=2)
        return header + body

    def _classify_batch(self, batch):
        """Send one batch, retrying on JSON errors."""
        prompt = self._build_prompt(batch)
        for attempt in range(1, self.retries + 1):
            try:
                raw = self.client.dummy_generate(prompt)
                text = raw.get("choices", [{}])[0].get("text", "")
                return self.client.extract_json_array(text)
            except Exception as e:
                #change form chain to identifier
                print(f"[Batch {batch[0]['chain']}] Attempt {attempt} failed: {e}", file=sys.stderr)
                if attempt < self.retries:
                    time.sleep(self.retry_delay)
                else:
                    raise

# ------------------------------------------------------------------------------
# ENTRY POINT
# ------------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Classify AST usage records as source/sink/neither for a given CWE"
    )
    parser.add_argument("--input",  "-i", type=Path, required=True, help="Path to usages.jsonl")
    parser.add_argument("--output", "-o", type=Path, required=True, help="Where to write classifications.jsonl")
    parser.add_argument("--url",    "-u", type=str,  default="http://localhost:11434",
                        help="Base URL for Ollama API")
    parser.add_argument("--model",  "-m", type=str,  required=True, help="Ollama model name")
    parser.add_argument("--cwe",    "-c", type=str,  required=True, help="CWE identifier (e.g. CWE-79)")
    parser.add_argument("--chunk",  type=int, default=DEFAULT_CHUNK_SIZE, help="Usages per batch")
    parser.add_argument("--retries",type=int, default=DEFAULT_RETRIES,    help="JSON parse retries")
    args = parser.parse_args()

    client = LLMClient(
        base_url   = args.url,
        model      = args.model,
        temperature=0.0,
        top_k      = 0,
        top_p      = 0.0
    )
    classifier = UsageClassifier(
        client     = client,
        cwe_id     = args.cwe,
        chunk_size = args.chunk,
        retries    = args.retries
    )

    classifier.classify_file(args.input, args.output)
    print(f"Done — classifications written to {args.output}")

if __name__ == "__main__":
    main()
