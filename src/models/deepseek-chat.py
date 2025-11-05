# src/models/deepseek_model.py

import os
from openai import OpenAI
from dotenv import load_dotenv
from src.models.llm_interface import LLMInterface

class DeepseekModel(LLMInterface):
    def __init__(self, model_name: str = "deepseek-chat", temperature: float = 1.0, max_tokens: int = None):
        """
        model_name: one of “deepseek-chat” or “deepseek-reasoner”
        temperature: randomness of generation
        max_tokens: optional cap on generated tokens
        """
        self.model_name = model_name
        self.temperature = temperature
        self.max_tokens = max_tokens

    def generate_response(self, prompt: str):
        load_dotenv()
        api_key = os.getenv("DEEPSEEK_API_KEY")
        if not api_key:
            raise RuntimeError("DEEPSEEK_API_KEY not set in environment")

        client = OpenAI(api_key=api_key, base_url="https://api.deepseek.com")

        messages = [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": prompt}
        ]

        # Build parameters for request
        request_kwargs = {
            "model": self.model_name,
            "messages": messages,
            "temperature": self.temperature,
            "stream": False
        }
        if self.max_tokens is not None:
            request_kwargs["max_tokens"] = self.max_tokens

        response = client.chat.completions.create(**request_kwargs)

        # The API returns the content in response.choices[0].message.content
        # For “reasoner” model, there may be a reasoning_content field too
        choice = response.choices[0]
        message = choice.message
        content = message.content

        if content is None:
            print("Error: Model returned no content.")
            return {"judgement": "none"}

        # If using reasoner model, we might capture reasoning_content too
        if hasattr(message, "reasoning_content") and message.reasoning_content is not None:
            return {
                "reasoning": message.reasoning_content,
                "content": content
            }

        return content
