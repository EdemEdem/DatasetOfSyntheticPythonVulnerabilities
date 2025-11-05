# src/models/deepseek_reasoner.py
import os
from openai import OpenAI
from dotenv import load_dotenv
from src.models.llm_interface import LLMInterface

class DeepseekReasoner(LLMInterface):
    def generate_response(self, prompt):
        load_dotenv()
        api_key = os.getenv("DEEPSEEK_API_KEY")
        client = OpenAI(api_key=api_key, base_url="https://api.deepseek.com")

        response = client.chat.completions.create(
            model="deepseek-reasoner",
            messages=[
                {"role": "system", "content": "You are a reasoning assistant."},
                {"role": "user", "content": prompt},
            ],
            response_format={'type': 'json_object'},
            stream=False
        )

        content = response.choices[0].message.content
        if content is None:
            print("Error: Model returned no response.")
            return {"judgement": "none"}
        return content

