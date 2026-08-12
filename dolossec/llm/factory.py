from __future__ import annotations

from ..config import settings
from .base import Planner
from .deterministic import DeterministicPlanner


def create_planner(provider: str | None = None, model: str | None = None) -> Planner:
    selected = (provider or settings.llm_provider or "none").strip().lower()
    selected_model = (model if model is not None else settings.model).strip()

    if selected in {"none", "deterministic", "offline"}:
        return DeterministicPlanner()
    if selected == "ollama":
        from .ollama_provider import OllamaPlanner

        return OllamaPlanner(selected_model)
    if selected == "openai":
        from .openai_provider import OpenAIPlanner

        return OpenAIPlanner(selected_model)
    raise ValueError(f"unsupported LLM provider: {selected}")
