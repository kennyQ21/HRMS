"""Detection engines package."""
from .base_engine import BaseEngine, EngineResult
from .regex_engine import RegexEngine
from .gliner_engine import GLiNEREngine
from .llm_engine import LLMEngine
from .otter_engine import OtterEngine

__all__ = [
    "BaseEngine",
    "EngineResult",
    "RegexEngine",
    "GLiNEREngine",
    "LLMEngine",
    "OtterEngine",
]
