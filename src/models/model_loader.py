import importlib
from src.models.llm_interface import LLMInterface

def load_model(model_name):
    """Dynamically load an LLM backend by name (e.g. 'deepseek_reasoner')."""
    try:
        module_path = f"src.models.{model_name.lower()}"
        model_module = importlib.import_module(module_path)
    except ModuleNotFoundError:
        raise ValueError(f"Model '{model_name}' not found in src/models/")

    for attr in dir(model_module):
        obj = getattr(model_module, attr)
        if isinstance(obj, type) and issubclass(obj, LLMInterface) and obj is not LLMInterface:
            return obj()  # instantiate and return

    raise ValueError(f"No valid LLM class found in {module_path}")
