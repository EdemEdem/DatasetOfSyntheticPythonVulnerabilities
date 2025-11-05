from abc import ABC, abstractmethod

class LLMInterface(ABC):
    """Abstract base class for all LLM backends."""

    @abstractmethod
    def generate_response(self, prompt: str) -> dict:
        """Generate a response given a prompt. Must return a JSON-serializable dict."""
        pass
