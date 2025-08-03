from openai import OpenAI
from dotenv import load_dotenv
import os
import sys
import json
import pathlib
from prompt_templates import PACKAGE_PROMPT_SYSTEM_PROMPT
load_dotenv()
api_key = os.getenv("DEEPSEEK_API_KEY")

client = OpenAI(api_key=api_key, base_url="https://api.deepseek.com")

def run_prompt(prompt, do_dummy: bool):
    if do_dummy:
        return '''{
            "node node node":"sink",
            "node node":"sink",
            "node":"sink",
            "node-node-node":"sink"
            }'''
    response = client.chat.completions.create(
        model="deepseek-chat",
        messages=[
            {"role": "system", "content": PACKAGE_PROMPT_SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
            ],
        response_format={
            'type': 'json_object'
            },
        stream=False
        )
    print(response.choices[0].message.content)
    return response.choices[0].message.content

# Optional filter: only load prompts whose filename contains this substring
prompt_name = "pre_chain"
# Directory containing prompt files (each file should contain one prompt)
dir_path = "samples/llm_results/prompts"
# Where to write model outputs
output_dir = "samples/llm_results/results"

# Loads all prompt files in dir_path (filtered by prompt_name if set)
def load_prompts(dir_path):
    prompts = {}
    if not os.path.isdir(dir_path):
        print(f"Prompt directory '{dir_path}' does not exist.")
        return prompts
    for filename in os.listdir(dir_path):
        file_path = os.path.join(dir_path, filename)
        if os.path.isfile(file_path):
            if prompt_name and prompt_name not in filename:
                continue
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    prompts[filename] = f.read()
            except Exception as e:
                print(f"Failed to read {file_path}: {e}")
    return prompts

# Writes a single result string to the specified output file path
def write_model_results(output_file_path, result):
    os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
    try:
        with open(output_file_path, "w", encoding="utf-8") as f:
            f.write(result)
    except Exception as e:
        print(f"Failed to write results to {output_file_path}: {e}")

# Main execution: load prompts, run each, and save outputs
if __name__ == "__main__":
    prompts = load_prompts(dir_path)
    if not prompts:
        print("No prompts loaded. Exiting.")
        sys.exit(0)

    os.makedirs(output_dir, exist_ok=True)

    for filename, prompt in prompts.items():
        print(f"Running prompt: {filename}")
        raw = run_prompt(prompt, True)
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            print(f"Failed to parse JSON for {filename}: {e}")
            continue
        # Include the source prompt filename for reference
        # Append to JSONL
        output_filename = os.path.splitext(filename)[0] + "_result.jsonl"
        print(output_filename)
        output_path = pathlib.Path(output_dir) / output_filename
        with open(output_path, "a", encoding="utf-8") as f:
            for key, value in data.items():
                line = json.dumps({ key: value })
                f.write(line + "\n")
        print(f"Appended result for {filename} to {output_path}")

